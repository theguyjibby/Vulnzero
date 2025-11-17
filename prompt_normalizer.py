import os
import json
from typing import Any, Dict, List, Optional




# -------------------------
# JSON Normalization (Scanner + Recon)
# -------------------------

def normalize_zap_and_recon_to_json(
    scanner_alerts: Optional[List[Dict[str, Any]]],
    recon: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Build a unified JSON structure that includes scanner findings (Nikto/ZAP/etc) and reconnaissance data from DB.
    recon should contain keys: open_ports, services, service_versions, subdomains, subdirectories,
    ip_addresses, hostnames, ssl_certs (optional list of cert info)
    """
    result: Dict[str, Any] = {
        "source": "scanner+recon",
        "scanner_findings": [],
        "reconnaissance": {
            "open_ports": recon.get("open_ports", []),
            "services": recon.get("services", []),
            "service_versions": recon.get("service_versions", []),
            "subdomains": recon.get("subdomains", []),
            "subdirectories": recon.get("subdirectories", []),
            "ip_addresses": recon.get("ip_addresses", []),
            "hostnames": recon.get("hostnames", []),
            "ssl_certs": recon.get("ssl_certs", []),
        },
    }

    for a in scanner_alerts or []:
        result["scanner_findings"].append({
            "name": a.get("alert") or a.get("title"),
            "severity": (a.get("risk") or a.get("severity") or "").lower(),
            "url": a.get("url"),
            "description": a.get("description"),
            "param": a.get("param"),
            "evidence": a.get("evidence"),
            "remediation": a.get("remediation") or a.get("solution"),
        })

    return result


def write_json(data: Dict[str, Any], out_path: str) -> None:
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def build_recon_from_models(
    open_ports_rows: List[Any],
    subdomain_rows: List[Any],
    subdirectory_rows: List[Any],
    ssl_cert_rows: List[Any],
    hostname: str,
    ipaddress: str,
) -> Dict[str, Any]:
    """
    Convert ORM rows (from the app's DB models) into a normalized reconnaissance dict
    suitable for normalize_zap_and_recon_to_json (works with any scanner).
    """
    open_ports = [
        {
            "port": getattr(p, "port_number", None),
            "service": getattr(p, "port_service", None),
            "version": getattr(p, "port_service_version", None),
        }
        for p in (open_ports_rows or [])
    ]

    services = [
        {
            "service": getattr(p, "port_service", None),
            "port": getattr(p, "port_number", None),
        }
        for p in (open_ports_rows or [])
        if getattr(p, "port_service", None)
    ]

    service_versions = [
        {
            "service": getattr(p, "port_service", None),
            "version": getattr(p, "port_service_version", None),
            "port": getattr(p, "port_number", None),
        }
        for p in (open_ports_rows or [])
        if getattr(p, "port_service_version", None)
    ]

    subdomains = [getattr(s, "subdomain", None) for s in (subdomain_rows or [])]
    subdirectories = [getattr(s, "subdirectory", None) for s in (subdirectory_rows or [])]

    ssl_certs = [
        {
            "subject": getattr(c, "subject", None),
            "issuer": getattr(c, "issuer", None),
            "not_before": getattr(c, "not_before", None),
            "not_after": getattr(c, "not_after", None),
            "status": getattr(c, "status", None),
            "error": getattr(c, "error", None),
        }
        for c in (ssl_cert_rows or [])
    ]

    return {
        "open_ports": open_ports,
        "services": services,
        "service_versions": service_versions,
        "subdomains": subdomains,
        "subdirectories": subdirectories,
        "ip_addresses": [ipaddress],
        "hostnames": [hostname],
        "ssl_certs": ssl_certs,
    }