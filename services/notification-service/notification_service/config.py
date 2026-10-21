from email.utils import parseaddr
from urllib.parse import urlparse

from pydantic import AliasChoices, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    host: str = "0.0.0.0"
    port: int = 8086
    database_url: str = Field(
        default="sqlite+pysqlite:///:memory:",
        validation_alias=AliasChoices("NOTIFICATION_DATABASE_URL", "DATABASE_URL"),
    )
    notification_webhook_url: str = ""
    notification_webhook_secret: str = ""
    notification_api_key: str = ""
    webhook_max_retries: int = 3
    webhook_retry_backoff_seconds: float = 0.05
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_starttls: bool = True
    default_email_to: str = ""
    outbox_poll_seconds: float = 10.0
    outbox_retry_seconds: int = 60
    outbox_max_attempts: int = 5

    @model_validator(mode="after")
    def validate_delivery_configuration(self) -> "Settings":
        if self.notification_webhook_url:
            parsed = urlparse(self.notification_webhook_url)
            if parsed.scheme != "https" or not parsed.netloc:
                raise ValueError("NOTIFICATION_WEBHOOK_URL must be an absolute HTTPS URL")
        if self.smtp_host:
            if not self.smtp_starttls:
                raise ValueError("SMTP_STARTTLS must be enabled when SMTP_HOST is set")
            _, sender = parseaddr(self.smtp_from)
            if not sender or sender != self.smtp_from or "." not in sender.rpartition("@")[2]:
                raise ValueError("SMTP_FROM must be a valid email address when SMTP_HOST is set")
            if self.smtp_username and not self.smtp_password:
                raise ValueError("SMTP_PASSWORD is required when SMTP_USERNAME is set")
        if self.default_email_to:
            _, recipient = parseaddr(self.default_email_to)
            if recipient != self.default_email_to or "." not in recipient.rpartition("@")[2]:
                raise ValueError("NOTIFICATION_DEFAULT_EMAIL_TO must be a valid email address")
        return self


settings = Settings()
