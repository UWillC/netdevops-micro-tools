from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from api.routers import snmpv3, ntp, golden_config, aaa, cve, profiles, iperf, subnet, mtu, config_parser, export, mitigation, timezone
from models.meta import MetaInfo
import datetime
import os

# to run backend cd /Users/uwillc/SaaS/netdevops-micro-tools
# python3 -m uvicorn api.main:app --reload --port 8000

app = FastAPI(
    title="NetDevOps Micro-Tools API",
    description="Small tools. Real automation. AI-assisted. Backend for generating secure Cisco configurations.",
    version="0.4.0",
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
app.include_router(profiles.router, tags=["Profiles"])
app.include_router(iperf.router, prefix="/generate", tags=["iPerf3"])
app.include_router(subnet.router, prefix="/tools", tags=["IP Subnet Calculator"])
app.include_router(mtu.router, prefix="/tools", tags=["MTU Calculator"])
app.include_router(config_parser.router, prefix="/tools", tags=["Config Parser"])
app.include_router(export.router, tags=["Export"])
app.include_router(mitigation.router, tags=["CVE Mitigation Advisor"])
app.include_router(timezone.router, tags=["Timezone Converter"])


# Determine base path for static files
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB_DIR = os.path.join(BASE_DIR, "web")

@app.get("/")
def root():
    """Serve the frontend index.html"""
    return FileResponse(os.path.join(WEB_DIR, "index.html"))

@app.get("/style.css")
def serve_css():
    """Serve CSS file"""
    return FileResponse(os.path.join(WEB_DIR, "style.css"), media_type="text/css")

@app.get("/app.js")
def serve_js():
    """Serve JS file"""
    return FileResponse(os.path.join(WEB_DIR, "app.js"), media_type="application/javascript")

@app.get("/api")
def api_root():
    """API status endpoint"""
    return {
        "status": "ok",
        "message": "NetDevOps Micro-Tools API is running.",
    }

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/meta/version", response_model=MetaInfo)
def meta_version():
    return MetaInfo(
        version="0.5.1",
        build_time=datetime.datetime.utcnow().isoformat() + "Z",
        feature_flags=["cve_engine_v3", "nvd_enrichment", "nvd_cache", "web_ui_v2", "profiles_v2", "profiles_cve", "security_score", "subnet_calc", "mtu_calc", "config_parser", "cloud_deploy", "export_pdf", "cve_mitigation_advisor", "timezone_converter"]
    )

# Mount static files (CSS, JS) - must be after all API routes
app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")
