let map = L.map('map', {
  center: [20, 0],
  zoom: 1,
  zoomControl: false,
  attributionControl: false
});

// Using Esri Dark Gray Canvas - Free, reliable, NO API Key needed
L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}', {
  maxZoom: 16,
  attribution: 'Tiles &copy; Esri &mdash; Esri, DeLorme, NAVTEQ'
}).addTo(map);

let flightPathLayer = L.layerGroup().addTo(map);
let selectedFile = null;
let currentReportUrl = null;
let lastAutopsyData = null;

// Fixed Tab Switching Logic
function switchTab(viewId, clickedLink) {
  // Hide all tab views
  document.querySelectorAll('.tab-view').forEach(view => {
    view.classList.add('hidden');
  });

  // Remove active styling from all links
  document.querySelectorAll('.nav-tab').forEach(link => {
    link.classList.remove('active');
  });

  // Show selected view and activate link
  document.getElementById(viewId).classList.remove('hidden');
  clickedLink.classList.add('active');

  // Fix map tile rendering bug when returning to a hidden map container
  if (viewId === 'view-analysis' && lastAutopsyData) {
    setTimeout(() => {
      map.invalidateSize();
      if (flightPathLayer.getLayers().length > 0) {
        const layers = flightPathLayer.getLayers();
        const route = layers.find(l => l instanceof L.Polyline);
        if (route) map.fitBounds(route.getBounds(), { padding: [30, 30] });
      }
    }, 100);
  }
}

function fileSelected() {
  const input = document.getElementById('emlUpload');
  if (input && input.files && input.files.length > 0) {
    selectedFile = input.files[0];
    runForensicAutopsy();
  }
}

async function runForensicAutopsy() {
  if (!selectedFile) return;

  const btnText = document.querySelector('.btn-primary');
  if (btnText) btnText.textContent = 'Processing...';

  const formData = new FormData();
  formData.append('file', selectedFile);

  try {
    const res = await fetch('/analyze', {
      method: 'POST',
      body: formData
    });

    if (!res.ok) throw new Error(await res.text());

    lastAutopsyData = await res.json();
    
    // Switch States
    document.getElementById('stateEmpty').classList.add('hidden');
    document.getElementById('stateAnalyzed').classList.remove('hidden');
    
    renderDashboard(lastAutopsyData);

    // Ensure map tiles calculate correctly since the container just became visible
    setTimeout(() => {
      map.invalidateSize();
      if (flightPathLayer.getLayers().length > 0) {
        const layers = flightPathLayer.getLayers();
        const route = layers.find(l => l instanceof L.Polyline);
        if (route) map.fitBounds(route.getBounds(), { padding: [30, 30] });
      }
    }, 100);

  } catch (err) {
    console.error(err);
    alert('Forensic Autopsy Exception: ' + err.message);
  } finally {
    if (btnText) btnText.textContent = 'New Analysis';
  }
}

function renderDashboard(data) {
  let riskScore = 0;
  const factors = [];
  const obs = [];

  // 1. Evaluate Auth
  const spf = data.auth ? data.auth.spf_status : 'FAIL';
  const dkim = data.auth ? data.auth.dkim_status : 'FAIL';
  const dmarc = data.auth ? data.auth.dmarc_status : 'FAIL';

  if (spf !== 'PASS') {
    riskScore += 25;
    factors.push({ score: '+25', class: 'high', msg: 'SPF authentication failed' });
    obs.push('SPF authentication failed or is missing.');
  }
  if (dkim !== 'PASS') {
    riskScore += 25;
    factors.push({ score: '+25', class: 'high', msg: 'DKIM signature unverifiable' });
    obs.push('DKIM cryptographic signature could not be verified.');
  }
  if (dmarc !== 'PASS') {
    riskScore += 20;
    factors.push({ score: '+20', class: 'high', msg: 'DMARC policy enforcement failed' });
    obs.push('DMARC alignment failure detected.');
  }

  // 2. Evaluate Hops
  const hopCount = data.hops ? data.hops.length : 0;
  if (hopCount > 4) {
    riskScore += 15;
    factors.push({ score: '+15', class: 'warn', msg: 'Elevated routing complexity' });
    obs.push(`Unusual routing complexity (${hopCount} transitions detected).`);
  }

  // Alignment Check
  const fromDomain = data.metadata.from.split('@')[1] || '';
  const returnPathDomain = data.metadata.domain || '';
  let alignment = 'ALIGNED';
  if (fromDomain && returnPathDomain && fromDomain.toLowerCase() !== returnPathDomain.toLowerCase()) {
    riskScore += 25;
    factors.push({ score: '+25', class: 'high', msg: 'Sender identity mismatch' });
    obs.push('Return-Path domain differs from visible From address.');
    alignment = 'MISMATCH';
  }

  if (riskScore === 0) {
    factors.push({ score: '0', class: 'info', msg: 'No critical anomalies detected' });
    obs.push('Standard authentication protocols aligned successfully.');
  }

  riskScore = Math.min(riskScore, 100);

  // Update Top Banner
  document.getElementById('threatScoreVal').textContent = riskScore;
  document.getElementById('threatScoreVal').style.color = riskScore >= 60 ? 'var(--status-fail)' : (riskScore > 0 ? 'var(--status-warn)' : 'var(--status-pass)');
  
  let tLevel = 'LOW';
  if (riskScore >= 75) tLevel = 'CRITICAL';
  else if (riskScore >= 50) tLevel = 'HIGH';
  else if (riskScore >= 25) tLevel = 'MEDIUM';
  document.getElementById('threatLevelLbl').textContent = `THREAT LEVEL: ${tLevel}`;

  document.getElementById('metaFilename').textContent = selectedFile ? selectedFile.name : 'artifact.eml';
  document.getElementById('metaTimestamp').textContent = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
  document.getElementById('metaSha').textContent = data.sha256.substring(0, 16) + '...';

  const factorsList = document.getElementById('factorsList');
  factorsList.innerHTML = '';
  factors.forEach(f => {
    factorsList.innerHTML += `<div class="factor-item"><span class="factor-score ${f.class}">${f.score}</span> <span>${f.msg}</span></div>`;
  });

  // Update Identity & Auth
  document.getElementById('valFrom').textContent = data.metadata.from || 'N/A';
  document.getElementById('valReturnPath').textContent = returnPathDomain || 'N/A';
  const alignEl = document.getElementById('valAlignment');
  alignEl.textContent = alignment;
  alignEl.style.color = alignment === 'ALIGNED' ? 'var(--status-pass)' : 'var(--status-fail)';

  const setAuth = (id, resId, status) => {
    const el = document.getElementById(resId);
    el.textContent = status;
    el.className = 'auth-result ' + (status === 'PASS' ? 'res-pass' : 'res-fail');
  };
  setAuth('authSpf', 'resSpf', spf);
  setAuth('authDkim', 'resDkim', dkim);
  setAuth('authDmarc', 'resDmarc', dmarc);

  // Network Origin Update
  if (data.hops && data.hops.length > 0) {
    const originHop = data.hops[0];
    document.getElementById('netOriginIp').textContent = originHop.ip;
    document.getElementById('netLocation').textContent = originHop.location;
    document.getElementById('netPtr').textContent = originHop.ptr;
  }

  // Threat Indicators (Cards)
  document.getElementById('threatIndicatorsEmpty').classList.add('hidden');
  document.getElementById('threatIndicatorsContent').classList.remove('hidden');

  const domainRepSev = riskScore >= 50 ? 'HIGH' : 'LOW';
  document.getElementById('indDomainSeverity').textContent = domainRepSev;
  document.getElementById('indDomainSeverity').className = 'ind-severity ' + (domainRepSev === 'HIGH' ? 'sev-high' : 'sev-low');
  document.getElementById('indDomainName').textContent = returnPathDomain || 'Unknown';
  document.getElementById('indDomainDesc').textContent = domainRepSev === 'HIGH' ? 'Authentication protocols failing.' : 'Authentication verified.';

  const relaySev = hopCount > 4 ? 'WARN' : 'LOW';
  document.getElementById('indRelaySeverity').textContent = relaySev;
  document.getElementById('indRelaySeverity').className = 'ind-severity ' + (relaySev === 'WARN' ? 'sev-warn' : 'sev-low');
  document.getElementById('indRelayCount').textContent = `${hopCount} hops`;
  document.getElementById('indRelayDesc').textContent = 'Extracted from Received headers.';

  // AI Analysis (Displaying Bedrock Output)
  document.getElementById('aiAnalysisEmpty').classList.add('hidden');
  document.getElementById('aiAnalysisContent').classList.remove('hidden');
  document.getElementById('threatText').textContent = data.threat_assessment || 'No assessment returned.';
  
  const obsList = document.getElementById('aiObservationsList');
  obsList.innerHTML = '';
  obs.forEach(o => {
    obsList.innerHTML += `<li>${o}</li>`;
  });

  // MTA Traversal Table & Map
  const tbody = document.getElementById('hopTableBody');
  document.getElementById('mtaEmpty').classList.add('hidden');
  document.getElementById('mtaTableContainer').classList.remove('hidden');
  document.getElementById('mtaSubtitle').textContent = `${hopCount} HOPS PARSED`;
  
  tbody.innerHTML = '';
  flightPathLayer.clearLayers();
  const coords = [];

  if (data.hops) {
    data.hops.forEach((h, idx) => {
      // Determine pseudo-status based on ptr resolution and position
      let hStatus = 'PASS';
      let statusClass = 'sev-low';
      if (h.ptr === 'Unknown PTR' || h.ip.startsWith('unknown')) {
        hStatus = 'WARNING';
        statusClass = 'sev-warn';
      }
      if (idx === 0 && riskScore >= 50) {
        hStatus = 'SUSPICIOUS';
        statusClass = 'sev-high';
      }

      const timeStr = "N/A (TODO: parse timestamp)";
      const asnStr = "N/A (TODO: fetch ASN)";

      const row = document.createElement('tr');
      row.innerHTML = `
        <td class="mono">0${h.hop}</td>
        <td class="mono" style="color: var(--text-secondary);">${timeStr}</td>
        <td class="mono">${h.ip}</td>
        <td>${h.ptr}</td>
        <td class="mono" style="color: var(--text-secondary);">${asnStr}</td>
        <td>${h.location}</td>
        <td><span class="status-badge ${statusClass}">${hStatus}</span></td>
      `;
      tbody.appendChild(row);

      // Map plotting
      if (h.latitude && h.longitude) {
        const pt = [h.latitude, h.longitude];
        coords.push(pt);

        let pinClass = 'simple-pin';
        if (idx === 0) pinClass += ' origin';
        if (idx === data.hops.length - 1) pinClass += ' dest';

        const customPin = L.divIcon({
          className: '',
          html: `<div class="${pinClass}"></div>`,
          iconSize: [12, 12],
          iconAnchor: [6, 6]
        });

        const marker = L.marker(pt, { icon: customPin })
          .bindPopup(`<b>Hop #${h.hop}</b><br><code style="color:#000;">${h.ip}</code><br><span style="color:#000;">${h.location}</span>`);
        flightPathLayer.addLayer(marker);
      }
    });
  }

  // Draw subdued map route
  if (coords.length > 1) {
    const route = L.polyline(coords, {
      color: 'var(--border-focus)',
      weight: 2,
      opacity: 0.6,
      dashArray: '4, 6'
    });
    flightPathLayer.addLayer(route);
  } else if (coords.length === 1) {
    map.setView(coords[0], 4);
  }

  // Evidence Integrity
  document.getElementById('evSha').textContent = data.sha256;
  document.getElementById('evFilename').textContent = selectedFile ? selectedFile.name : 'artifact.eml';
  document.getElementById('evTimestamp').textContent = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';

  if (data.pdf_url) {
    currentReportUrl = data.pdf_url;
  }
}

function downloadCertificate() {
  if (currentReportUrl) window.open(currentReportUrl, '_blank');
}

function exportJson() {
  if (!lastAutopsyData) return;
  const blob = new Blob([JSON.stringify(lastAutopsyData, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `forensic_report_${lastAutopsyData.sha256.slice(0, 8)}.json`;
  a.click();
}