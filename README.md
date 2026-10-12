# CyberOrchestra

CyberOrchestra is a college research and demonstration project for cybersecurity incident analysis. A React dashboard connects to a FastAPI backend that coordinates six specialized analysis and response-planning agents, enriches indicators with threat intelligence where configured, and applies a deterministic policy review. Recovery actions are presented for review; the application does not execute them.

The repository includes controlled synthetic incident scenarios for demonstration and testing. They are simulations, not real incidents.

## Features

- Submit and inspect security incidents through the web dashboard.
- Coordinate threat detection, malware analysis, log analysis, vulnerability assessment, recovery planning, and report generation.
- Use supported threat intelligence integrations when credentials and services are configured.
- Review evidence, recommendations, policy decisions, and benchmark results.

## Requirements

Install a current Python 3 release and Node.js with npm. The backend dependencies are listed in `backend/requirements.txt`; frontend dependencies are locked in `frontend/package-lock.json`.

## Run locally (Windows PowerShell)

1. Configure the backend:

   ```powershell
   cd backend
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install -r requirements.txt
   Copy-Item .env.example .env
   ```

2. Edit `backend/.env` and add only the provider credentials or settings you have. Keep this file private; it is excluded from Git. Threat intelligence and model integrations that lack configuration will be unavailable.

3. Start the API from the `backend` directory:

   ```powershell
   python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
   ```

4. In a second terminal, install and start the frontend:

   ```powershell
   cd frontend
   npm ci
   npm run dev -- --host 127.0.0.1
   ```

5. Open the Vite URL shown in the terminal (normally http://127.0.0.1:5173). The API is at http://127.0.0.1:8000 and interactive API documentation is at http://127.0.0.1:8000/docs.

Stop either development server with Ctrl+C. Do not put backend API keys in frontend environment variables or browser code.

## Checks

From `frontend/`, run the production build:

```powershell
npm run build
```

From the repository root, install pytest if needed and run the backend suite:

```powershell
python -m pip install pytest
python -m pytest backend/tests
```

Some integration tests may depend on external model/provider configuration; consult their output and the backend configuration before interpreting provider-related failures.

## Repository notes

- Synthetic scenarios live in `backend/data/raw/` and are intentionally tracked because the backend uses them for demos and tests.
- Generated evaluation output, normalized data, local databases, secrets, virtual environments, and build artifacts are ignored.
- Use `backend/README.md` and `frontend/README.md` for service-specific notes.
