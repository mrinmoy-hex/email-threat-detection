from pathlib import Path

from src.parser.email_parser import parse_email
from src.headers.header_analyzer import analyze_headers


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
        None,
        "pass",
        "fail",
        "softfail",
        "neutral",
        "none",
        "temperror",
        "permerror",
    }

    assert result.dkim_result in {
        None,
        "pass",
        "fail",
        "softfail",
        "neutral",
        "none",
        "temperror",
        "permerror",
    }

    assert result.dmarc_result in {
        None,
        "pass",
        "fail",
        "softfail",
        "neutral",
        "none",
        "temperror",
        "permerror",
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

    print("Subject:", result.subject)
    print("From:", result.sender)
    print("Reply-To:", result.reply_to)

    assert result.subject
    assert result.sender