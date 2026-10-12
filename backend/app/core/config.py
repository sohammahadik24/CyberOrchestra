"""Application configuration and environment settings for CyberOrchestra."""

import os
from typing import Optional
from dotenv import load_dotenv

# Load local environment configuration from .env if available
load_dotenv()


class Settings:
    """Core settings and threat intelligence API configuration.

    Optional API keys are not required at application startup. Individual clients
    will raise explicit configuration errors only when invoked without their required keys.
    """

    PROJECT_NAME: str = "CyberOrchestra API"
    VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"

    # AbuseIPDB Configuration
    ABUSEIPDB_API_KEY: Optional[str] = os.getenv("ABUSEIPDB_API_KEY")
    ABUSEIPDB_API_URL: str = os.getenv("ABUSEIPDB_API_URL", "https://api.abuseipdb.com/api/v2/check")
    ABUSEIPDB_TIMEOUT_SECONDS: float = float(os.getenv("ABUSEIPDB_TIMEOUT_SECONDS", "10.0"))

    # URLhaus Configuration
    URLHAUS_AUTH_KEY: Optional[str] = os.getenv("URLHAUS_AUTH_KEY")
    URLHAUS_API_URL: str = os.getenv("URLHAUS_API_URL", "https://urlhaus-api.abuse.ch/v1/url/")
    URLHAUS_TIMEOUT_SECONDS: float = float(os.getenv("URLHAUS_TIMEOUT_SECONDS", "10.0"))

    # NVD CVE API 2.0 Configuration
    # NVD_API_KEY is OPTIONAL. The NVD API works without a key but with lower rate limits.
    # Register for a free key at: https://nvd.nist.gov/developers/request-an-api-key
    NVD_API_KEY: Optional[str] = os.getenv("NVD_API_KEY")
    NVD_API_URL: str = os.getenv("NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
    NVD_TIMEOUT_SECONDS: float = float(os.getenv("NVD_TIMEOUT_SECONDS", "15.0"))

    # Generic LLM settings remain available for other agents.
    LLM_PROVIDER: Optional[str] = os.getenv("LLM_PROVIDER")
    LLM_MODEL: Optional[str] = os.getenv("LLM_MODEL")
    LLM_API_KEY: Optional[str] = os.getenv("LLM_API_KEY")
    LLM_BASE_URL: Optional[str] = os.getenv("LLM_BASE_URL")
    LLM_TIMEOUT_SECONDS: float = float(os.getenv("LLM_TIMEOUT_SECONDS", "60.0"))

    # Threat Detection Agent Groq profile; uses the shared LLMService adapter.
    THREAT_LLM_PROVIDER: str = os.getenv("THREAT_LLM_PROVIDER", "groq")
    THREAT_LLM_MODEL: str = os.getenv("THREAT_LLM_MODEL", "openai/gpt-oss-120b")
    THREAT_LLM_API_KEY: Optional[str] = os.getenv("GROQ_API_KEY")
    THREAT_LLM_BASE_URL: str = os.getenv(
        "GROQ_BASE_URL", "https://api.groq.com/openai/v1"
    )

    # Malware Analysis Agent Groq profile; uses the shared LLMService adapter.
    MALWARE_LLM_PROVIDER: str = os.getenv("MALWARE_LLM_PROVIDER", "groq")
    MALWARE_LLM_MODEL: str = os.getenv(
        "MALWARE_LLM_MODEL", os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
    )
    MALWARE_LLM_API_KEY: Optional[str] = os.getenv("GROQ_API_KEY")
    MALWARE_LLM_BASE_URL: str = os.getenv(
        "GROQ_BASE_URL", "https://api.groq.com/openai/v1"
    )

    # Log Analysis Agent Groq profile; independent from other agent profiles.
    LOG_LLM_PROVIDER: str = os.getenv("LOG_LLM_PROVIDER", "groq")
    LOG_LLM_MODEL: str = os.getenv(
        "LOG_LLM_MODEL", os.getenv("GROQ_LOG_MODEL", "qwen/qwen3-32b")
    )
    LOG_LLM_API_KEY: Optional[str] = os.getenv("GROQ_API_KEY")
    LOG_LLM_BASE_URL: str = os.getenv(
        "GROQ_BASE_URL", "https://api.groq.com/openai/v1"
    )

    # Vulnerability Assessment Agent Groq profile; uses the shared LLMService adapter.
    VULNERABILITY_LLM_PROVIDER: str = os.getenv("VULNERABILITY_LLM_PROVIDER", "groq")
    VULNERABILITY_LLM_MODEL: str = os.getenv(
        "VULNERABILITY_LLM_MODEL", "qwen/qwen3-32b"
    )
    VULNERABILITY_LLM_API_KEY: Optional[str] = os.getenv("GROQ_API_KEY")
    VULNERABILITY_LLM_BASE_URL: str = os.getenv(
        "GROQ_BASE_URL", "https://api.groq.com/openai/v1"
    )

    # Recovery Planning Agent Groq profile; uses the shared LLMService adapter.
    RECOVERY_LLM_PROVIDER: str = os.getenv("RECOVERY_LLM_PROVIDER", "groq")
    RECOVERY_LLM_MODEL: str = os.getenv("RECOVERY_LLM_MODEL", "qwen/qwen3-32b")
    RECOVERY_LLM_API_KEY: Optional[str] = os.getenv("GROQ_API_KEY")
    RECOVERY_LLM_BASE_URL: str = os.getenv(
        "GROQ_BASE_URL", "https://api.groq.com/openai/v1"
    )

    # Report Generation Agent Groq profile; uses the shared LLMService adapter.
    REPORT_LLM_PROVIDER: str = os.getenv("REPORT_LLM_PROVIDER", "groq")
    REPORT_LLM_MODEL: str = os.getenv("REPORT_LLM_MODEL", "qwen/qwen3-32b")
    REPORT_LLM_API_KEY: Optional[str] = os.getenv("GROQ_API_KEY")
    REPORT_LLM_BASE_URL: str = os.getenv(
        "GROQ_BASE_URL", "https://api.groq.com/openai/v1"
    )

    # Single-LLM baseline profile, isolated from the multi-agent pipeline.
    BASELINE_LLM_PROVIDER: str = os.getenv("BASELINE_LLM_PROVIDER", "groq")
    BASELINE_LLM_MODEL: str = os.getenv(
        "BASELINE_LLM_MODEL", "openai/gpt-oss-120b"
    )
    BASELINE_LLM_API_KEY: Optional[str] = os.getenv("GROQ_API_KEY")
    BASELINE_LLM_BASE_URL: str = os.getenv(
        "GROQ_BASE_URL", "https://api.groq.com/openai/v1"
    )


settings = Settings()
