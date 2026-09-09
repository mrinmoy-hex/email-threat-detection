# src/parser/email_parser.py

import email
import hashlib
import logging
import os
from dataclasses import dataclass
from email import policy
from email.errors import MessageError
from typing import Optional

logger = logging.getLogger(__name__)

MAX_FILE_SIZE = 25 * 1024 * 1024  # 10 MB
ALLOWED_DIRS = [os.path.abspath("data/samples")]


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


def _validate_path(file_path: str) -> str:
    resolved = os.path.abspath(file_path)
    if not any(resolved.startswith(d) for d in ALLOWED_DIRS):
        logger.warning(f"Path traversal attempt blocked: {file_path}")
        raise ValueError("Access denied: path outside allowed directories")
    return resolved


def _extract_headers(msg) -> dict[str, list[str]]:
    headers = {}

    for key in set(msg.keys()):
        headers[key] = msg.get_all(key, failobj=[])

    return headers


def _extract_attachments(msg) -> list[dict]:
    attachments = []

    for part in msg.iter_attachments():

        try:
            payload = part.get_payload(decode=True)
        except (MessageError, ValueError, TypeError) as e:
            logger.warning(f"Failed to decode attachment payload: {e}")
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


def _extract_forwarded_message(msg, depth: int = 0) -> Optional["ParsedEmail"]:
    if depth >= 5:
        logger.warning("Max recursion depth reached for forwarded messages")
        return None

    for part in msg.iter_attachments():

        if part.get_content_type() != "message/rfc822":
            continue

        try:
            inner_msg = next(part.iter_parts(), part) if part.is_multipart() else part

            if inner_msg is None:
                continue

            return parse_email(
                raw_bytes=inner_msg.as_bytes(),
                _depth=depth + 1
            )

        except (MessageError, ValueError, AttributeError) as e:
            logger.warning(f"Failed to parse inner message: {e}")
            continue

    return None


def parse_email(
    file_path: str = None,
    raw_bytes: bytes = None,
    _depth: int = 0
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

        file_path = _validate_path(file_path)

        if os.path.getsize(file_path) > MAX_FILE_SIZE:
            logger.warning(f"File exceeds maximum allowed size: {file_path}")
            raise ValueError("File too large")

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

    original_message = _extract_forwarded_message(msg, depth=_depth)

    return ParsedEmail(
        headers=headers,
        plain_body=plain_body,
        html_body=html_body,
        attachments=attachments,
        is_forwarded=original_message is not None,
        original_message=original_message,
        raw_source=raw_bytes,
    )
