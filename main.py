from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os
from forensic_engine import analyze_email

app = FastAPI(title="PhantomTrace Forensic Engine", version="1.0.0")

# Compute base project root directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Configure directories for local vs Vercel serverless environments
STATIC_DIR = os.path.join(BASE_DIR, "static")
REPORTS_DIR = "/tmp/reports" if os.environ.get("VERCEL") else os.path.join(BASE_DIR, "reports")

os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

# Mount static and dynamic report assets
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
app.mount("/reports", StaticFiles(directory=REPORTS_DIR), name="reports")


@app.get("/")
async def serve_index():
    index_file = os.path.join(STATIC_DIR, "index.html")
    if not os.path.exists(index_file):
        raise HTTPException(status_code=404, detail="Frontend interface not found.")
    return FileResponse(index_file)


@app.post("/analyze")
async def process_email(file: UploadFile = File(...)):
    if not file.filename.lower().endswith((".eml", ".txt", ".msg")):
        raise HTTPException(status_code=400, detail="Invalid artifact type. Provide a .eml file.")

    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    try:
        results = analyze_email(raw_bytes)
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))