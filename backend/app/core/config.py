"""Application configuration loaded from environment variables / .env file."""
from __future__ import annotations

from functools import lru_cache
from typing import List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_BRANDS = [
    "paypal", "microsoft", "apple", "google", "amazon", "facebook",
    "netflix", "bankofamerica", "chase", "wellsfargo", "dropbox",
    "linkedin", "instagram", "docusign", "adobe", "outlook", "office365",
]

DEFAULT_SCHEMES = ["http", "https"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    APP_ENV: str = Field(default="development")
    BACKEND_HOST: str = Field(default="0.0.0.0")
    BACKEND_PORT: int = Field(default=8000)

    DATABASE_URL: str = Field(default="sqlite:///./phishbrain.db")
    CACHE_URL: str = Field(default="redis://localhost:6379/0")

    LLM_PROVIDER: str = Field(default="ollama")
    OLLAMA_BASE_URL: str = Field(default="http://localhost:11434")
    OLLAMA_MODEL: str = Field(default="llama3.1")

    ANALYSIS_TIMEOUT_SECONDS: float = Field(default=20.0)
    CACHE_TTL_SECONDS: int = Field(default=3600)

    # How much of the fetched page is handed to the LLM. The page text is
    # untrusted and prompt size dominates CPU inference time, so this is a
    # deliberate cap rather than "as much as we downloaded".
    LLM_WEBPAGE_SUMMARY_CHARS: int = Field(default=1200, ge=0)
    # Cap the generated response. The schema needs ~120 tokens; letting a small
    # CPU model ramble to 2000 tokens was most of a scan's wall-clock time.
    LLM_NUM_PREDICT: int = Field(default=320, ge=16)
    # Keep the model resident between scans. Without this, Ollama unloads it
    # after its default idle window and the next scan pays a cold start that is
    # many times the inference cost itself.
    LLM_KEEP_ALIVE: str = Field(default="30m")
    # Load the model into memory at startup instead of during the first scan.
    # Loading costs ~30 s of CPU on a 4-core box, which the first request would
    # otherwise pay for; set to false on a memory-constrained deployment where
    # holding the model resident is not acceptable.
    LLM_WARMUP_ON_STARTUP: bool = Field(default=True)
    # Ollama defaults to a large context; on CPU a 4k window is markedly faster
    # and is ample for a URL plus a capped page summary.
    LLM_NUM_CTX: int = Field(default=4096, ge=512)

    EMAIL_WEIGHT: float = Field(default=0.30)
    URL_WEIGHT: float = Field(default=0.30)
    DOMAIN_WEIGHT: float = Field(default=0.20)
    WEBPAGE_WEIGHT: float = Field(default=0.20)

    # Share of the composite score contributed by a *trained* CatBoost
    # prefilter. Deliberately modest: the prefilter only sees lexical URL
    # features while the layers corroborate each other with page, domain and
    # email evidence, so it should nudge the verdict rather than set it. Kept
    # well under 0.5 so a lone maximal prefilter score cannot drag a clean
    # multi-layer analysis above the SAFE ceiling on its own.
    PREFILTER_WEIGHT: float = Field(default=0.15, ge=0.0, le=0.5)

    SAFE_THRESHOLD: int = Field(default=30)
    SUSPICIOUS_THRESHOLD: int = Field(default=65)

    STORE_RAW_EMAIL: bool = Field(default=False)
    RETENTION_DAYS: int = Field(default=30)

    # Screenshot evidence is the most sensitive thing this backend stores — a
    # picture of the page a user visited — so it is purged on its own, much
    # shorter clock than the analysis record itself. The analysis (score,
    # indicators, evidence) survives under RETENTION_DAYS; only the image is
    # dropped. A value of 0 means "store none at all": every sweep strips the
    # screenshots immediately, which is the right setting for a shared box.
    VISUAL_RETENTION_DAYS: int = Field(default=7, ge=0)
    # How often the background sweep runs. The sweep is cheap (it only looks at
    # records older than the cutoff) and idempotent, so a coarse interval is
    # fine; it also runs once at startup so a restart enforces the policy.
    VISUAL_PURGE_INTERVAL_MINUTES: int = Field(default=360, ge=1)

    BRAND_LIST: str = Field(default=",".join(DEFAULT_BRANDS))
    ALLOWED_SCHEMES: str = Field(default=",".join(DEFAULT_SCHEMES))

    MAX_REQUEST_BYTES: int = Field(default=2_000_000)
    MAX_FETCH_BYTES: int = Field(default=3_000_000)

    # Sent when fetching a target page or taking its screenshot. The library
    # default ("python-httpx/x.y") is refused outright by a lot of the web —
    # Wikipedia answers 403 with a 126-byte notice, for example — and because
    # the fetch did not check the status code, that notice was parsed as the
    # page: the webpage layer reported "no forms, no credential fields, no
    # external resources" for a page it had never actually read. Keep this in
    # sync with scripts/data/generate_reference_hashes.py so reference captures
    # and probe captures render the same way.
    FETCH_USER_AGENT: str = Field(
        default=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        )
    )
    FETCH_ACCEPT_LANGUAGE: str = Field(default="en-US,en;q=0.9")

    # Whether the visual layer hands the captured screenshot back for display,
    # and in what form. "off" keeps the pixels on the server; "pixels" returns a
    # downscaled JPEG evidence image; "wireframe" returns an edge-only rendering
    # that preserves the layout while dropping colour and legible text, so the
    # dashboard can SHOW what it compared without storing the page itself.
    VISUAL_SCREENSHOT_MODE: str = Field(default="pixels")
    VISUAL_SCREENSHOT_MAX_WIDTH: int = Field(default=480)
    # Set to false to disable the automatic screenshot-evidence sweep entirely
    # (the retention policy then only runs when an operator calls it).
    VISUAL_AUTO_PURGE_ENABLED: bool = Field(default=True)

    @field_validator("APP_ENV")
    @classmethod
    def _lower_env(cls, v: str) -> str:
        return v.lower()

    @field_validator("VISUAL_SCREENSHOT_MODE")
    @classmethod
    def _valid_screenshot_mode(cls, v: str) -> str:
        mode = (v or "off").lower()
        # An unrecognised value is a misconfiguration, and the safe reading is
        # "off" — never silently ship page pixels when the intent was wireframe.
        return mode if mode in {"off", "pixels", "wireframe"} else "off"

    @property
    def brands(self) -> List[str]:
        return [b.strip().lower() for b in self.BRAND_LIST.split(",") if b.strip()]

    @property
    def allowed_schemes(self) -> List[str]:
        return [s.strip().lower() for s in self.ALLOWED_SCHEMES.split(",") if s.strip()]

    @property
    def is_production(self) -> bool:
        return self.APP_ENV == "production"

    @property
    def layer_weights(self) -> dict:
        # The prefilter's share is carved out of the layer weights, so the
        # blend always sums to 1.0: (1 - PREFILTER_WEIGHT) * layers + W * ml.
        layer_total = self.EMAIL_WEIGHT + self.URL_WEIGHT + self.DOMAIN_WEIGHT + self.WEBPAGE_WEIGHT
        layer_total = layer_total or 1.0
        return {
            "email": self.EMAIL_WEIGHT / layer_total,
            "url": self.URL_WEIGHT / layer_total,
            "domain": self.DOMAIN_WEIGHT / layer_total,
            "webpage": self.WEBPAGE_WEIGHT / layer_total,
        }


@lru_cache
def get_settings() -> Settings:
    return Settings()
