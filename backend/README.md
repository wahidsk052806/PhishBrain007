# PhishBrain Backend

FastAPI backend that performs multi-layer phishing analysis of URLs, emails and
web pages, combining deterministic heuristics, a CatBoost prefilter and a
local Ollama LLM for final assessment.

## Quick start

```bash
cp .env.example .env
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

## Environment variables

See `app/core/config.py` for the full list: `APP_ENV`, `BACKEND_HOST`,
`BACKEND_PORT`, `DATABASE_URL`, `CACHE_URL`, `LLM_PROVIDER`,
`OLLAMA_BASE_URL`, `OLLAMA_MODEL`, `ANALYSIS_TIMEOUT_SECONDS`,
`CACHE_TTL_SECONDS`, `EMAIL_WEIGHT`, `URL_WEIGHT`, `DOMAIN_WEIGHT`,
`WEBPAGE_WEIGHT`, `SAFE_THRESHOLD`, `SUSPICIOUS_THRESHOLD`,
`STORE_RAW_EMAIL`, `RETENTION_DAYS`, `BRAND_LIST`, `ALLOWED_SCHEMES`.

## Testing

```bash
pytest
```

No outbound network calls happen at import time; all external I/O (RDAP,
DNS, Ollama, screenshots, DB, cache) fails gracefully into a "degraded"
mode so the API keeps working offline.
