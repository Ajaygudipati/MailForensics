# MailForensics

Privacy-first `.eml` forensic analysis platform. Run the FastAPI API in `backend/` and the React application in `frontend/`.

## Quick start

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

```powershell
cd frontend
npm install
npm run dev
```

The UI runs at `http://localhost:5173` and proxies `/api` to FastAPI.

Uploaded samples are processed in memory only. Optional intelligence integrations are deliberately disabled unless their API keys are configured.
