from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.routers import snmpv3, ntp, golden_config, aaa, cve
from models.meta import MetaInfo
import datetime

# to run backend cd /Users/uwillc/SaaS/cisco-microtool-generator
# python3 -m uvicorn api.main:app --reload --port 8000

app = FastAPI(
    title="Cisco Micro-Tool Generator API",
    description="Micro-SaaS backend for generating secure Cisco configurations.",
    version="0.2.0",
)

# CORS for local frontend (dev)
origins = [
    "http://127.0.0.1:5500",  # VS Code Live Server (częsty port)
    "http://localhost:5500",
    "http://127.0.0.1:8000",
    "http://localhost:8000",
    "*",  # for now: allow all in dev; you can tighten later
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(snmpv3.router, prefix="/generate", tags=["SNMPv3"])
app.include_router(ntp.router, prefix="/generate", tags=["NTP"])
app.include_router(golden_config.router, prefix="/generate", tags=["Golden Config"])
app.include_router(aaa.router, prefix="/generate", tags=["AAA / TACACS+"])
app.include_router(cve.router, prefix="/analyze", tags=["CVE Analyzer"])

@app.get("/")
def root():
    return {
        "status": "ok",
        "message": "Cisco Micro-Tool Generator API is running.",
    }

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/meta/version", response_model=MetaInfo)
def meta_version():
    return MetaInfo(
        version="0.2.0",
        build_time=datetime.datetime.utcnow().isoformat() + "Z",
        feature_flags=["cve_engine_v2", "web_ui_v2"]
    )
