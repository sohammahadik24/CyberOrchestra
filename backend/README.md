# CyberOrchestra Backend

FastAPI service for incident submission, analysis orchestration, threat intelligence, policy review, reporting, and evaluation endpoints.

## Local setup

From this directory in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Configure optional model and intelligence providers in the private `.env` file. Never commit credentials. The API documentation is available at http://127.0.0.1:8000/docs.

For full-stack startup and test instructions, see the repository [README](../README.md).
