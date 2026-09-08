from pathlib import Path

import pytest

from src.parser.email_parser import parse_email


SAMPLE_EMAIL = Path("data/samples/test1.eml")


def test_parse_email():
    result = parse_email(file_path=str(SAMPLE_EMAIL))

    assert result is not None
    assert result.raw_source


def test_extract_headers():
    result = parse_email(file_path=str(SAMPLE_EMAIL))

    assert result.subject
    assert result.sender


def test_body_extraction():
    result = parse_email(file_path=str(SAMPLE_EMAIL))

    assert isinstance(result.plain_body, str)
    assert isinstance(result.html_body, str)


def test_attachments():
    result = parse_email(file_path=str(SAMPLE_EMAIL))

    assert isinstance(result.attachments, list)

    for attachment in result.attachments:
        assert "filename" in attachment
        assert "content_type" in attachment
        assert "size" in attachment
        assert "sha256" in attachment


def test_sha256():
    result = parse_email(file_path=str(SAMPLE_EMAIL))

    for attachment in result.attachments:
        assert len(attachment["sha256"]) == 64


def test_missing_input():
    with pytest.raises(ValueError):
        parse_email()