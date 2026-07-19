"""F9: notification interface — Slack webhook and/or SMTP (§7B.5)."""

from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage

import httpx

from litellm_ext.settings import get_settings

logger = logging.getLogger("litellm_ext.costgov")


async def send_slack(text: str) -> bool:
    settings = get_settings()
    if not settings.slack_webhook_url:
        return False
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(settings.slack_webhook_url, json={"text": text})
            resp.raise_for_status()
        return True
    except httpx.HTTPError:
        logger.exception("slack notification failed")
        return False


def send_email(subject: str, body: str) -> bool:
    settings = get_settings()
    if not (settings.smtp_host and settings.smtp_from and settings.smtp_to):
        return False
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings.smtp_from
    message["To"] = ", ".join(settings.smtp_to)
    message.set_content(body)
    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as smtp:
            smtp.starttls()
            smtp.send_message(message)
        return True
    except (smtplib.SMTPException, OSError):
        logger.exception("email notification failed")
        return False


async def notify(subject: str, body: str) -> None:
    """Best-effort fan-out to every configured channel."""
    sent_slack = await send_slack(f"*{subject}*\n{body}")
    sent_email = send_email(subject, body)
    if not (sent_slack or sent_email):
        logger.warning("no notification channel configured; message: %s", subject)
