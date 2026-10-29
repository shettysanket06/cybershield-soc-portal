$ErrorActionPreference = 'Stop'

if (-not (Test-Path '.\venv')) {
    python -m venv venv
}

& '.\venv\Scripts\Activate.ps1'
pip install -r requirements.txt

if (-not $env:CYBERSHIELD_SECRET_KEY) {
    $env:CYBERSHIELD_SECRET_KEY = (python -c "import secrets; print(secrets.token_hex(32))")
}

python app.py
