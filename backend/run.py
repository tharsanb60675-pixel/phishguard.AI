import os
import sys
from pathlib import Path

# Ensure backend directory and virtualenv packages are on sys.path
backend_dir = Path(__file__).resolve().parent
venv_site_packages = backend_dir / ".venv" / "Lib" / "site-packages"
if venv_site_packages.exists() and str(venv_site_packages) not in sys.path:
    sys.path.insert(0, str(venv_site_packages))
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

import uvicorn

if __name__ == "__main__":
    print("[PHISHGUARD] Starting FastAPI Backend on http://0.0.0.0:8000 ...", flush=True)
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=False
    )

