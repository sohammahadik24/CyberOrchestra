from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1 import api_v1_router

app = FastAPI(
    title="CyberOrchestra API",
    description="Backend API for CyberOrchestra Multi-Agent Incident Response Framework",
    version="0.1.0",
)

# Enable CORS for frontend applications (Vite dev server, localhost, and production origins)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_v1_router)


@app.get("/")
def read_root():
    """Health / root endpoint indicating system operational status."""
    return {
        "status": "ok",
        "message": "CyberOrchestra is running",
        "version": "0.1.0",
    }
