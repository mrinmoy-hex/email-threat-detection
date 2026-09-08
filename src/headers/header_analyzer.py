import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class HeaderAnalysis:
    spf_result: Optional[str]
    dkim_result: Optional[str]
    dmarc_result: Optional[str]
    from_domain: Optional[str]
    return_path_domain: Optional[str]
    reply_to_domain: Optional[str]
    domain_mismatch: bool
    received_chain: list
    hop_count: int
    suspicious_hops: list


def _extract_domain(header_value: Optional[str]) -> Optional[str]:
    if not header_value:
        return None
    match = re.search(r"@([\w.-]+)", header_value)
    return match.group(1).lower() if match else None


def _parse_auth_results(headers: dict) -> dict:
    auth_header = headers.get("Authentication-Results")
    result = {"spf": None, "dkim": None, "dmarc": None}
    if not auth_header:
        return result

    combined = " ".join(str(h) for h in auth_header)
    for mechanism in ("spf", "dkim", "dmarc"):
        match = re.search(rf"(?:^|;)\s*{mechanism}\s*=\s*([a-zA-Z0-9]+)", combined, re.IGNORECASE)
        if match:
            result[mechanism] = match.group(1).lower()
    return result


def _parse_received_chain(headers: dict) -> list:
    received_list = headers.get("Received", [])
    chain = []
    for hop in received_list:
        hop_str = str(hop)
        from_match = re.search(r"from\s+([\w.-]+)", hop_str, re.IGNORECASE)
        by_match = re.search(r"by\s+([\w.-]+)", hop_str, re.IGNORECASE)
        ip_match = re.search(r"\[([a-fA-F0-9.:]+)\]", hop_str)
        chain.append({
            "raw": hop_str,
            "from_host": from_match.group(1) if from_match else None,
            "by_host": by_match.group(1) if by_match else None,
            "ip": ip_match.group(1) if ip_match else None,
        })
    return chain


def _find_suspicious_hops(chain: list) -> list:
    suspicious = []
    for hop in chain:
        # flag hops with no resolvable from_host but an IP present (common spoofing pattern)
        if hop["ip"] and not hop["from_host"]:
            suspicious.append(hop)
    return suspicious


def analyze_headers(headers: dict) -> HeaderAnalysis:
    from_header = headers.get("From", [None])[0]
    return_path_header = headers.get("Return-Path", [None])[0]
    reply_to_header = headers.get("Reply-To", [None])[0]

    from_domain = _extract_domain(str(from_header)) if from_header else None
    return_path_domain = _extract_domain(str(return_path_header)) if return_path_header else None
    reply_to_domain = _extract_domain(str(reply_to_header)) if reply_to_header else None

    domain_mismatch = False
    if from_domain:
        if return_path_domain and from_domain != return_path_domain:
            domain_mismatch = True
        elif reply_to_domain and from_domain != reply_to_domain:
            domain_mismatch = True

    auth_results = _parse_auth_results(headers)
    received_chain = _parse_received_chain(headers)
    suspicious_hops = _find_suspicious_hops(received_chain)

    return HeaderAnalysis(
        spf_result=auth_results["spf"],
        dkim_result=auth_results["dkim"],
        dmarc_result=auth_results["dmarc"],
        from_domain=from_domain,
        return_path_domain=return_path_domain,
        reply_to_domain=reply_to_domain,
        domain_mismatch=domain_mismatch,
        received_chain=received_chain,
        hop_count=len(received_chain),
        suspicious_hops=suspicious_hops,
    )
