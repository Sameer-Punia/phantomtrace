from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os
from forensic_engine import analyze_email

app = FastAPI(title="PhantomTrace Forensic Engine", version="1.0.0")

# Serve UI and generated local report files
os.makedirs("static", exist_ok=True)
os.makedirs("reports", exist_ok=True)

app.mount("/static", StaticFiles(directory="static"), name="static")
app.mount("/reports", StaticFiles(directory="reports"), name="reports")


@app.get("/")
async def serve_index():
    return FileResponse("static/index.html")


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