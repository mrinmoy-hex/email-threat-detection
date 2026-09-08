from pathlib import Path

from src.parser.email_parser import parse_email
from src.headers.header_analyzer import analyze_headers, _parse_auth_results


SAMPLE_EMAIL = Path("data/samples/test1.eml")


def test_header_analysis():
    email = parse_email(file_path=str(SAMPLE_EMAIL))
    result = analyze_headers(email.headers)
    assert result is not None
    assert hasattr(result, "spf_result")
    assert hasattr(result, "dkim_result")
    assert hasattr(result, "dmarc_result")
    assert hasattr(result, "from_domain")
    assert hasattr(result, "received_chain")


def test_sender_domain():
    email = parse_email(file_path=str(SAMPLE_EMAIL))
    result = analyze_headers(email.headers)
    assert isinstance(result.from_domain, (str, type(None)))


def test_authentication_results():
    email = parse_email(file_path=str(SAMPLE_EMAIL))
    result = analyze_headers(email.headers)
    assert result.spf_result in {
        None, "pass", "fail", "softfail", "neutral", "none", "temperror", "permerror",
    }
    assert result.dkim_result in {
        None, "pass", "fail", "softfail", "neutral", "none", "temperror", "permerror",
    }
    assert result.dmarc_result in {
        None, "pass", "fail", "softfail", "neutral", "none", "temperror", "permerror",
    }


def test_received_chain():
    email = parse_email(file_path=str(SAMPLE_EMAIL))
    result = analyze_headers(email.headers)
    assert isinstance(result.received_chain, list)


def test_hop_count():
    email = parse_email(file_path=str(SAMPLE_EMAIL))
    result = analyze_headers(email.headers)
    assert isinstance(result.hop_count, int)
    assert result.hop_count >= 0


def test_suspicious_hops():
    email = parse_email(file_path=str(SAMPLE_EMAIL))
    result = analyze_headers(email.headers)
    assert isinstance(result.suspicious_hops, list)


def test_extract_headers():
    result = parse_email(file_path=str(SAMPLE_EMAIL))
    assert result.subject
    assert result.sender


def test_ipv6_received_chain():
    """Verify that IPv6 addresses are properly extracted from the Received chain."""
    headers = {
        "Received": [
            "from mail.example.com (mail.example.com [2001:db8::1]) by mx.dest.com"
        ]
    }
    result = analyze_headers(headers)
    assert result.received_chain[0]["ip"] == "2001:db8::1"
    assert result.received_chain[0]["from_host"] == "mail.example.com"


def test_reply_to_mismatch():
    """Verify that domain mismatch catches Reply-To vs From differences."""
    headers = {
        "From": ["user@example.com"],
        "Reply-To": ["user@evil.com"],
    }
    result = analyze_headers(headers)
    assert result.domain_mismatch is True


def test_auth_results_spoof_bypass_prevented():
    """Verify that the stricter auth results regex prevents naive substring spoofing."""
    headers = {
        # Naive regex would match the first instance "spf=pass" inside the injected comment.
        "Authentication-Results": [
            "mx.google.com; x-fake-comment=\"spf=pass\"; spf=fail"
        ]
    }
    result = _parse_auth_results(headers)
    # The strict regex should skip the x-fake-comment and find the real spf=fail at the end
    # or at least not match the space-separated injected comment easily.
    # Our new regex looks for (?:^|;)\s*mechanism\s*=\s*val
    # "x-fake-comment="spf=pass"" does not start with ; spf=...
    assert result["spf"] == "fail"