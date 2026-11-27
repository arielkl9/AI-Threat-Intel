"""Gmail API sender (OAuth2 desktop flow)."""

from __future__ import annotations

import base64
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

log = logging.getLogger(__name__)

SCOPES = ["https://www.googleapis.com/auth/gmail.send"]


class EmailSender:
    def __init__(self, credentials_file: str, token_file: str, recipient_email: str | None):
        self.credentials_file = credentials_file
        self.token_file = Path(token_file)
        self.recipient_email = recipient_email
        self.service = None

    def _get_creds(self) -> Credentials:
        creds: Credentials | None = None
        if self.token_file.exists():
            creds = Credentials.from_authorized_user_file(str(self.token_file), SCOPES)
        if creds and creds.valid:
            return creds
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(self.credentials_file, SCOPES)
            creds = flow.run_local_server(port=0)
        self.token_file.write_text(creds.to_json(), encoding="utf-8")
        return creds

    def _build_service(self):
        if not self.service:
            self.service = build("gmail", "v1", credentials=self._get_creds())
        return self.service

    def send_email(self, subject: str, html_content: str) -> bool:
        if not self.recipient_email:
            log.error("No recipient email configured; cannot send.")
            return False
        try:
            service = self._build_service()
            msg = MIMEMultipart()
            msg["From"] = "me"
            msg["To"] = self.recipient_email
            msg["Subject"] = subject
            msg.attach(MIMEText(html_content, "html"))
            raw = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8")
            response = service.users().messages().send(userId="me", body={"raw": raw}).execute()
            log.info("Email sent: %s", response.get("id"))
            return True
        except Exception as exc:  # the Google client raises a wide range of errors
            log.error("Failed to send email: %s", exc)
            return False
