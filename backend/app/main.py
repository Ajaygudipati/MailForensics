from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from .models import AnalysisResponse
from .security import validate_eml_upload
from .services.analysis_service import analyze_email

load_dotenv()

app = FastAPI(title="MailForensics API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

@app.get("/api/health")
def health():
    return {"status": "healthy", "service": "mailforensics", "storage": "ephemeral"}

@app.post("/api/analyze", response_model=AnalysisResponse)
async def analyze(file: UploadFile = File(...)):
    return analyze_email(await validate_eml_upload(file), file.filename or "sample.eml")
