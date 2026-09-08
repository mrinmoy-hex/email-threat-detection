import email
import hashlib
from email import policy
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ParsedEmail:
    headers: dict
    plain_body: str
    html_body: str
    attachments: list
    is_forwarded: bool
    original_message: Optional["ParsedEmail"]
    raw_source: bytes


def _extract_headers(msg) -> dict:
    headers = {}
    for key in msg.keys():
        headers[key] = msg.get_all(key)
    return headers


def _extract_attachments(msg) -> list:
    attachments = []
    for part in msg.iter_attachments():
        try:
            payload = part.get_payload(decode=True)
        except Exception:
            payload = None

        content_type = part.get_content_type()
        size = len(payload) if payload else 0
        sha256 = hashlib.sha256(payload).hexdigest() if payload else None

        attachments.append({
            "filename": part.get_filename(),
            "content_type": content_type,
            "size": size,
            "sha256": sha256,
            "is_message": content_type == "message/rfc822",
            "part": part,  # keep reference for forwarding unwrap
        })
    return attachments


def parse_email(file_path: str = None, raw_bytes: bytes = None) -> ParsedEmail:
    if raw_bytes is None:
        with open(file_path, "rb") as f:
            raw_bytes = f.read()

    msg = email.message_from_bytes(raw_bytes, policy=policy.default)

    headers = _extract_headers(msg)

    plain_part = msg.get_body(preferencelist=("plain",))
    plain_body = plain_part.get_content() if plain_part else ""

    html_part = msg.get_body(preferencelist=("html",))
    html_body = html_part.get_content() if html_part else ""

    attachments = _extract_attachments(msg)

    is_forwarded = False
    original_message = None
    for att in attachments:
        if att["is_message"]:
            is_forwarded = True
            inner_msg = att["part"].get_payload()[0]  # the embedded Message object
            inner_bytes = inner_msg.as_bytes()
            original_message = parse_email(raw_bytes=inner_bytes)
            break

    return ParsedEmail(
        headers=headers,
        plain_body=plain_body,
        html_body=html_body,
        attachments=attachments,
        is_forwarded=is_forwarded,
        original_message=original_message,
        raw_source=raw_bytes,
    )


if __name__ == "__main__":
    result = parse_email("data/samples/test1.eml")
    print(result.headers.get("Subject"))
    print(result.plain_body)