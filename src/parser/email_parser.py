# src/parser/email_parser.py

import email
import hashlib
from dataclasses import dataclass, field
from email import policy
from typing import Optional


@dataclass
class ParsedEmail:
    """Structured representation of an email extracted from an .eml file."""

    headers: dict[str, list[str]]
    plain_body: str
    html_body: str
    attachments: list[dict]
    is_forwarded: bool
    original_message: Optional["ParsedEmail"]
    raw_source: bytes

    @property
    def subject(self) -> str:
        return self.headers.get("Subject", [""])[0]

    @property
    def sender(self) -> str:
        return self.headers.get("From", [""])[0]

    @property
    def reply_to(self) -> str:
        return self.headers.get("Reply-To", [""])[0]

    @property
    def message_id(self) -> str:
        return self.headers.get("Message-ID", [""])[0]


def _extract_headers(msg) -> dict[str, list[str]]:
    headers = {}

    for key in msg.keys():
        headers[key] = msg.get_all(key, failobj=[])

    return headers


def _extract_attachments(msg) -> list[dict]:
    attachments = []

    for part in msg.iter_attachments():

        try:
            payload = part.get_payload(decode=True)
        except Exception:
            payload = None

        if payload is None:
            payload = b""

        content_type = part.get_content_type()

        attachments.append({
            "filename": part.get_filename() or "unknown",
            "content_type": content_type,
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "is_message": content_type == "message/rfc822",
        })

    return attachments


def _extract_forwarded_message(msg) -> Optional["ParsedEmail"]:
    for part in msg.iter_attachments():

        if part.get_content_type() != "message/rfc822":
            continue

        try:
            inner_msg = part.get_payload(0)

            if inner_msg is None:
                continue

            return parse_email(
                raw_bytes=inner_msg.as_bytes()
            )

        except Exception:
            continue

    return None


def parse_email(
    file_path: str = None,
    raw_bytes: bytes = None
) -> ParsedEmail:
    """
    Parse an .eml file and return its contents in a structured form.

    Either file_path or raw_bytes can be supplied.
    """

    if raw_bytes is None:

        if file_path is None:
            raise ValueError(
                "Either file_path or raw_bytes must be provided"
            )

        with open(file_path, "rb") as f:
            raw_bytes = f.read()

    msg = email.message_from_bytes(
        raw_bytes,
        policy=policy.default
    )

    headers = _extract_headers(msg)

    plain_part = msg.get_body(
        preferencelist=("plain",)
    )

    html_part = msg.get_body(
        preferencelist=("html",)
    )

    plain_body = (
        plain_part.get_content()
        if plain_part
        else ""
    )

    html_body = (
        html_part.get_content()
        if html_part
        else ""
    )

    attachments = _extract_attachments(msg)

    original_message = _extract_forwarded_message(msg)

    return ParsedEmail(
        headers=headers,
        plain_body=plain_body,
        html_body=html_body,
        attachments=attachments,
        is_forwarded=original_message is not None,
        original_message=original_message,
        raw_source=raw_bytes,
    )

