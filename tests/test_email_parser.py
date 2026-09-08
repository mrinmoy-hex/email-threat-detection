import os
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


def test_path_traversal_blocked():
    """Verify that attempting to parse a file outside the allowed directory raises ValueError."""
    with pytest.raises(ValueError, match="Access denied"):
        # Use an absolute path pointing to something outside the workspace/allowed dir
        parse_email(file_path="../../etc/passwd")


def test_max_file_size_enforced(tmp_path):
    """Verify that a file exceeding the maximum size raises ValueError."""
    import unittest.mock as mock
    
    # We create a dummy file in the allowed dir to pass the path validation
    allowed_dir = Path("data/samples")
    allowed_dir.mkdir(parents=True, exist_ok=True)
    dummy_file = allowed_dir / "huge_test.eml"
    dummy_file.write_text("dummy")

    with mock.patch('os.path.getsize', return_value=11 * 1024 * 1024):
        with pytest.raises(ValueError, match="File too large"):
            parse_email(file_path=str(dummy_file))

    dummy_file.unlink()


def test_recursion_depth_limit():
    """Verify that deeply nested forwarded emails do not cause a stack overflow."""
    from email.message import EmailMessage
    
    msg = EmailMessage()
    msg['Subject'] = 'Level 0'
    
    # Create nested message manually
    inner1 = EmailMessage()
    inner1['Subject'] = 'Level 1'
    inner2 = EmailMessage()
    inner2['Subject'] = 'Level 2'
    inner3 = EmailMessage()
    inner3['Subject'] = 'Level 3'
    inner4 = EmailMessage()
    inner4['Subject'] = 'Level 4'
    inner5 = EmailMessage()
    inner5['Subject'] = 'Level 5'
    inner6 = EmailMessage()
    inner6['Subject'] = 'Level 6'

    inner5.add_attachment(inner6.as_bytes(), maintype='message', subtype='rfc822')
    inner4.add_attachment(inner5.as_bytes(), maintype='message', subtype='rfc822')
    inner3.add_attachment(inner4.as_bytes(), maintype='message', subtype='rfc822')
    inner2.add_attachment(inner3.as_bytes(), maintype='message', subtype='rfc822')
    inner1.add_attachment(inner2.as_bytes(), maintype='message', subtype='rfc822')
    msg.add_attachment(inner1.as_bytes(), maintype='message', subtype='rfc822')

    result = parse_email(raw_bytes=msg.as_bytes())
    
    # The depth limit is 5. We nested 6 levels deep.
    # Level 5's original_message should be None, preventing a recursion error.
    assert result.is_forwarded is True
    
    curr = result
    depth = 0
    while curr.original_message is not None:
        curr = curr.original_message
        depth += 1
    
    assert depth <= 5