import os
import json
from fpdf import FPDF
from datetime import datetime, timezone
import email
from email import policy
import hashlib
import re
import dns.resolver
import dns.reversename
import checkdmarc
import geoip2.database
import boto3
from botocore.exceptions import ClientError

GEOIP_PATH = os.path.join("data", "GeoLite2-City.mmdb")
geo_reader = geoip2.database.Reader(GEOIP_PATH)

# AWS Configuration matching the SIH architecture
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
S3_BUCKET_NAME = os.environ.get("S3_BUCKET_NAME", "phantomtrace-evidence-vault-samee")
DYNAMODB_TABLE_NAME = os.environ.get("DYNAMODB_TABLE_NAME", "phantomtrace_audits")
BEDROCK_MODEL_ID = "amazon.nova-micro-v1:0"

bedrock_client = boto3.client("bedrock-runtime", region_name=AWS_REGION)
s3_client = boto3.client("s3", region_name=AWS_REGION)
dynamodb_resource = boto3.resource("dynamodb", region_name=AWS_REGION)

# Configure dedicated public resolvers to bypass local gateway (192.168.1.1) timeouts
custom_resolver = dns.resolver.Resolver()
custom_resolver.nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]


def sanitize_text(text: str) -> str:
    """Replaces Unicode characters with safe ASCII/Latin-1 equivalents for standard FPDF fonts."""
    if not text:
        return ""
    replacements = {
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u2014": "--",
        "\u2013": "-",
        "\u2026": "...",
    }
    for orig, rep in replacements.items():
        text = text.replace(orig, rep)
    return text.encode("latin-1", errors="replace").decode("latin-1")


def is_public_ip(ip: str) -> bool:
    """Validates that an IP is not loopback, link-local, or RFC-1918 private."""
    if not ip:
        return False
    return not ip.startswith((
        "10.", "192.168.", "127.", "172.16.", "172.17.", 
        "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", 
        "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", 
        "172.28.", "172.29.", "172.30.", "172.31.", "0.", "169.254."
    ))


def extract_ip(header_val: str):
    """Finds the first valid public IPv4 in a header string."""
    ip_regex = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
    ips = re.findall(ip_regex, header_val)
    valid_ips = [ip for ip in ips if is_public_ip(ip)]
    return valid_ips[0] if valid_ips else None


def get_reverse_dns(ip: str):
    """Performs PTR record lookups via configured public DNS resolvers."""
    try:
        addr = dns.reversename.from_address(ip)
        answers = custom_resolver.resolve(addr, "PTR")
        return str(answers[0]).rstrip(".")
    except Exception:
        return "No PTR Record"


def extract_true_originating_client(msg, hops: list) -> dict:
    """
    Extracts the sender's originating client IP.
    Prioritizes client headers (X-Originating-IP, X-Sender-IP) and authentication
    telemetry over intermediate cloud provider datacenter relays.
    """
    candidate_ip = None
    source_header = "Received Chain"

    # 1. Check explicit client-IP headers injected by MUAs and enterprise webmail
    for hdr in ["X-Originating-IP", "X-Sender-IP", "X-Client-IP", "X-Apparently-From"]:
        raw_val = msg.get(hdr)
        if raw_val:
            found_ip = extract_ip(raw_val)
            if found_ip:
                candidate_ip = found_ip
                source_header = hdr
                break

    # 2. Check Authentication-Results / Received-SPF client IP logging
    if not candidate_ip:
        auth_header = (msg.get("Authentication-Results", "") or "") + " " + (msg.get("Received-SPF", "") or "")
        spf_ip_match = re.search(r"sender IP is ((?:[0-9]{1,3}\.){3}[0-9]{1,3})", auth_header)
        if spf_ip_match and is_public_ip(spf_ip_match.group(1)):
            candidate_ip = spf_ip_match.group(1)
            source_header = "Authentication Telemetry (Client Socket)"

    # 3. Fallback: First chronological public relay hop in traversal chain
    if not candidate_ip and hops:
        candidate_ip = hops[0]["ip"]
        source_header = "Earliest Public MTA Relay"

    # Geolocation resolution for the candidate IP
    location_desc = "Unknown Location"
    lat, lon = None, None
    if candidate_ip:
        try:
            geo = geo_reader.city(candidate_ip)
            city = geo.city.name or "Unknown City"
            country = geo.country.name or "Unknown Country"
            location_desc = f"{city}, {country}"
            lat = geo.location.latitude
            lon = geo.location.longitude
        except Exception:
            pass

    # Verify if the resolved host is an intermediary cloud datacenter
    ptr_val = get_reverse_dns(candidate_ip) if candidate_ip else "N/A"
    is_obscured = any(
        service in ptr_val.lower() 
        for service in ["google.com", "outlook.com", "yahoodns.net", "navercorp.com", "protection.outlook.com"]
    )

    return {
        "ip": candidate_ip or "Not Available in Headers",
        "header_source": source_header,
        "ptr": ptr_val,
        "location": location_desc,
        "latitude": lat,
        "longitude": lon,
        "client_obscured_by_cloud": is_obscured
    }


def get_bedrock_reasoning(data: dict) -> str:
    """Invokes Amazon Nova Micro on Amazon Bedrock for SIH Threat Reasoning."""
    origin_info = data.get("origin_client", {})
    prompt = (
        f"You are a Level 3 Digital Forensics SOC Analyst inspecting an email artifact.\n"
        f"Forensic Evidence Summary:\n"
        f"- Sender: {data['metadata']['from']}\n"
        f"- Return-Path Domain: {data['metadata']['domain']}\n"
        f"- Subject: {data['metadata']['subject']}\n"
        f"- SPF Verification: {data['auth']['spf_status']} (Record: {data['auth']['spf_record']})\n"
        f"- DKIM Status: {data['auth']['dkim_status']}\n"
        f"- DMARC Policy: {data['auth']['dmarc_status']} (p={data['auth']['dmarc_policy']})\n"
        f"- Relay Hop Count: {len(data['hops'])}\n"
        f"- Inferred Origin Client IP: {origin_info.get('ip')} ({origin_info.get('location')})\n"
        f"- Cloud Obfuscated: {origin_info.get('client_obscured_by_cloud')}\n\n"
        f"Provide a concise, 3-sentence technical verdict on domain authenticity, "
        f"spoofing vectors, and whether origin IP indicates an end-user client or cloud relay boundary."
    )

    try:
        response = bedrock_client.converse(
            modelId=BEDROCK_MODEL_ID,
            messages=[
                {
                    "role": "user",
                    "content": [{"text": prompt}]
                }
            ],
            inferenceConfig={
                "maxTokens": 256,
                "temperature": 0.2,
                "topP": 0.9
            }
        )
        return response["output"]["message"]["content"][0]["text"].strip()
    except Exception as e:
        return f"Bedrock Analysis Exception: {str(e)}"


def persist_to_aws(data: dict, pdf_filepath: str) -> str:
    """Stores Section 65B PDF to S3 and registers the audit record in DynamoDB."""
    signed_url = ""
    filename = os.path.basename(pdf_filepath)
    s3_key = f"reports/{filename}"

    # 1. Upload to Amazon S3
    try:
        s3_client.upload_file(
            pdf_filepath,
            S3_BUCKET_NAME,
            s3_key,
            ExtraArgs={"ContentType": "application/pdf"}
        )
        signed_url = s3_client.generate_presigned_url(
            "get_object",
            Params={"Bucket": S3_BUCKET_NAME, "Key": s3_key},
            ExpiresIn=3600
        )
    except ClientError as e:
        if e.response["Error"]["Code"] in ("NoSuchBucket", "404"):
            try:
                s3_client.create_bucket(Bucket=S3_BUCKET_NAME)
                s3_client.upload_file(
                    pdf_filepath,
                    S3_BUCKET_NAME,
                    s3_key,
                    ExtraArgs={"ContentType": "application/pdf"}
                )
                signed_url = s3_client.generate_presigned_url(
                    "get_object",
                    Params={"Bucket": S3_BUCKET_NAME, "Key": s3_key},
                    ExpiresIn=3600
                )
            except Exception:
                pass
    except Exception:
        pass

    # 2. Persist to Amazon DynamoDB
    try:
        table = dynamodb_resource.Table(DYNAMODB_TABLE_NAME)
        table.put_item(
            Item={
                "sha256": data["sha256"],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "sender": data["metadata"]["from"],
                "domain": data["metadata"]["domain"],
                "subject": data["metadata"]["subject"],
                "spf_status": data["auth"]["spf_status"],
                "dkim_status": data["auth"]["dkim_status"],
                "dmarc_status": data["auth"]["dmarc_status"],
                "threat_assessment": data.get("threat_assessment", "N/A"),
                "origin_ip": data.get("origin_client", {}).get("ip", "N/A"),
                "s3_report_url": signed_url or f"local://{pdf_filepath}"
            }
        )
    except Exception:
        pass

    return signed_url


def analyze_email(raw_eml_bytes: bytes):
    """Executes the core forensic pipeline on raw RFC-5322 byte payload."""
    sha256_hash = hashlib.sha256(raw_eml_bytes).hexdigest()
    msg = email.message_from_bytes(raw_eml_bytes, policy=policy.default)

    sender = msg.get("From", "Unknown")
    reply_to = msg.get("Reply-To", "None")
    subject = msg.get("Subject", "No Subject")
    date_sent = msg.get("Date", "Unknown")
    message_id = msg.get("Message-ID", "Unknown")

    sender_domain = ""
    if "@" in sender:
        match = re.search(r"@([a-zA-Z0-9.-]+)", sender)
        if match:
            sender_domain = match.group(1).rstrip(">")

    # 1. Received MTA Relay Traversal
    received_headers = msg.get_all("Received", [])
    hops = []

    for idx, header in enumerate(reversed(received_headers)):
        ip = extract_ip(header)
        if ip:
            city, country, lat, lon = "Unknown", "Unknown", None, None
            try:
                geo = geo_reader.city(ip)
                city = geo.city.name or "Unknown"
                country = geo.country.name or "Unknown"
                lat = geo.location.latitude
                lon = geo.location.longitude
            except Exception:
                pass

            ptr = get_reverse_dns(ip)
            hops.append({
                "hop": len(hops) + 1,
                "ip": ip,
                "ptr": ptr,
                "location": f"{city}, {country}",
                "latitude": lat,
                "longitude": lon
            })

    # 2. Extract Originating Machine (Client IP Extraction)
    origin_client = extract_true_originating_client(msg, hops)

    # 3. Authentication Verification via Public Resolvers
    auth = {
        "spf_status": "NONE",
        "spf_record": "None",
        "dkim_status": "NONE",
        "dmarc_status": "NONE",
        "dmarc_policy": "None"
    }

    auth_results = msg.get("Authentication-Results", "")
    if auth_results:
        if "dkim=pass" in auth_results.lower():
            auth["dkim_status"] = "PASS"
        elif "dkim=fail" in auth_results.lower():
            auth["dkim_status"] = "FAIL"

    if sender_domain:
        try:
            dns_report = checkdmarc.check_domains(
                [sender_domain],
                nameservers=["8.8.8.8", "1.1.1.1", "9.9.9.9"],
                timeout=3.0
            )
            spf_info = dns_report.get("spf", {})
            dmarc_info = dns_report.get("dmarc", {})

            auth["spf_status"] = "PASS" if spf_info.get("valid") else "FAIL"
            auth["spf_record"] = spf_info.get("record", "Not found")
            auth["dmarc_status"] = "PASS" if dmarc_info.get("valid") else "FAIL"
            auth["dmarc_policy"] = dmarc_info.get("tags", {}).get("p", {}).get("value", "None")
        except Exception:
            auth["spf_status"] = "LOOKUP_ERR"
            auth["dmarc_status"] = "LOOKUP_ERR"

    parsed_data = {
        "sha256": sha256_hash,
        "metadata": {
            "from": sender,
            "reply_to": reply_to,
            "subject": subject,
            "domain": sender_domain,
            "date": date_sent,
            "message_id": message_id
        },
        "auth": auth,
        "hops": hops,
        "origin_client": origin_client
    }

    # 4. Invoke Bedrock Threat Reasoning
    threat_verdict = get_bedrock_reasoning(parsed_data)
    parsed_data["threat_assessment"] = threat_verdict

    # 5. Generate Section 65B PDF and Persist to AWS S3 / DynamoDB
    pdf_path = generate_pdf_report(parsed_data)
    signed_url = persist_to_aws(parsed_data, pdf_path)
    parsed_data["pdf_url"] = signed_url if signed_url else f"/reports/{os.path.basename(pdf_path)}"

    return parsed_data


def generate_pdf_report(data: dict, output_path: str = None) -> str:
    """Generates Section 65B Compliance Certificate PDF with origin attribution details."""
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(2, 132, 199)
    pdf.cell(0, 10, "PHANTOMTRACE FORENSIC CERTIFICATE", ln=True, align="C")

    pdf.set_font("Helvetica", "I", 9)
    pdf.set_text_color(100, 116, 139)
    pdf.cell(0, 6, "INDIAN EVIDENCE ACT - SECTION 65B COMPLIANCE RECORD", ln=True, align="C")
    pdf.ln(5)

    pdf.set_draw_color(203, 213, 225)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(6)

    # 1. SHA-256 Ledger
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 8, "1. IMMUTABLE CRYPTOGRAPHIC LEDGER", ln=True)
    pdf.set_font("Courier", "", 9)
    pdf.set_text_color(51, 65, 85)
    pdf.cell(0, 6, f"SHA-256 Digest : {data['sha256']}", ln=True)
    pdf.cell(0, 6, f"Timestamp      : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}", ln=True)
    pdf.ln(4)

    # 2. Originating Machine / Client Telemetry
    client = data.get("origin_client", {})
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 8, "2. SENDER CLIENT IDENTIFICATION (ORIGIN TRACE)", ln=True)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, sanitize_text(f"Inferred Client IP : {client.get('ip')} ({client.get('header_source')})"), ln=True)
    pdf.cell(0, 6, sanitize_text(f"Physical Location  : {client.get('location')}"), ln=True)
    pdf.cell(0, 6, sanitize_text(f"Reverse DNS (PTR)  : {client.get('ptr')}"), ln=True)
    pdf.cell(0, 6, sanitize_text(f"Cloud Obfuscated   : {'YES (Consumer Webmail Relay)' if client.get('client_obscured_by_cloud') else 'NO (Direct Client Origin)'}"), ln=True)
    pdf.ln(4)

    # 3. Root DNS Telemetry
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 8, "3. AUTHENTICATION TELEMETRY (ROOT DNS)", ln=True)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, sanitize_text(f"SPF Validation : {data['auth']['spf_status']} (Record: {data['auth']['spf_record']})"), ln=True)
    pdf.cell(0, 6, sanitize_text(f"DKIM Status    : {data['auth']['dkim_status']}"), ln=True)
    pdf.cell(0, 6, sanitize_text(f"DMARC Policy   : {data['auth']['dmarc_status']} (Policy: {data['auth']['dmarc_policy']})"), ln=True)
    pdf.ln(4)

    # 4. Traversal Hops
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "4. MTA RELAY TRAVERSAL (REVERSE HOPS)", ln=True)
    pdf.set_font("Helvetica", "", 9)
    for hop in data.get("hops", []):
        pdf.cell(0, 6, sanitize_text(f"Hop #{hop['hop']}: IP {hop['ip']} | PTR: {hop['ptr']} | Geo: {hop['location']}"), ln=True)
    pdf.ln(4)

    # 5. Bedrock Assessment
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "5. AMAZON BEDROCK THREAT REASONING", ln=True)
    pdf.set_font("Helvetica", "", 9)
    threat_text = sanitize_text(data.get("threat_assessment", "N/A"))
    pdf.multi_cell(0, 5, threat_text)

    # Vercel / Local filesystem check
    if output_path is None:
        target_dir = "/tmp/reports" if os.environ.get("VERCEL") else "reports"
        os.makedirs(target_dir, exist_ok=True)
        output_path = os.path.join(target_dir, f"forensic_report_{data['sha256'][:10]}.pdf")

    pdf.output(output_path)
    return output_path