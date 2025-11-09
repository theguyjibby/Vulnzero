

import os
import json
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, Optional
from openai import OpenAI  # adjust import if your environment uses a different client


def analyze_xml_ai_only(
    
    scan_xml: str,
    mode: str,
    api_key: str = "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",
    model: str = "gpt-5",
    temperature: float = 0.15,
    max_tokens: int = 2000
) -> Dict[str, Any]:
    # Validate arguments
    
    if not isinstance(scan_xml, str) or not scan_xml.strip():
        return {"status": "error", "error": "scan_xml must be a non-empty XML string."}

    # Quick well-formed XML check (fail early if malformed)
    try:
        ET.fromstring(scan_xml)
    except Exception as e:
        return {"status": "error", "error": f"Invalid XML: {e}"}

    # Build the instruction/prompt for the model
    # Strict JSON schema requested. Safety note included.
    instruction = (
        "You are an expert web/security analyst. Analyze the provided XML vulnerability scan report and "
        "return STRICT valid JSON (no extra commentary) matching the schema described below.\n\n"
        "TOP-LEVEL OBJECT SCHEMA:\n"
        "{\n"
        "  \"top_level_summary\": \"<2-3 sentence overview>\",\n"
        "  \"overall_risk_score\": <integer 1-10>,\n"
        "  \"risk_table\": {\"Critical\": int, \"High\": int, \"Medium\": int, \"Low\": int},\n"
        "  \"top_findings_table\": [ { index, name, severity, risk_score, url (opt), description, rationale, remediation OR exploitation_concept & detection_indicators } ... up to 5 ],\n"
        "  \"ranked_findings\": [ same structure as top_findings_table for full list sorted by risk_score desc ],\n"
        "  \"reconnaissance\": {\n"
        "      \"open_ports\": [ {\"port\": int, \"protocol\": \"tcp|udp\", \"service\": \"\", \"version\": \"\"}, ... ],\n"
        "      \"services\": [ {\"service\": \"\", \"port\": int}, ... ],\n"
        "      \"service_versions\": [ {\"service\":\"\", \"version\":\"\", \"port\": int}, ... ],\n"
        "      \"subdomains\": [\"a.example.com\", ...],\n"
        "      \"subdirectories\": [\"/admin\", \"/uploads\", ...],\n"
        "      \"ip_addresses\": [\"1.2.3.4\", ...],\n"
        "      \"hostnames\": [\"host.example.com\", ...]\n"
        "  },\n"
        "  \"truncated\": <boolean>\n"
        "}\n\n"
        f"MODE: {mode.upper()}\n"
        + (
            "If MODE=BLUE: include 'remediation' for each finding (concrete fixes, config, mitigations).\n"
            if mode == "blue"
            else
            "If MODE=RED: include 'exploitation_concept' (high-level conceptual attack path) and 'detection_indicators' (log/monitoring cues). DO NOT provide exploit payloads, step-by-step commands, or scripts.\n"
        )
        + "\nSAFETY RULE: Under no circumstances return exploit payloads, working exploit code, step-by-step commands, or automation scripts that enable unauthorized access. For RED mode, only conceptual attack vectors and detection cues are allowed.\n"
        "Return ONLY the JSON object and no other text."
    )

    prompt = f"{instruction}\n\nSCAN_XML:\n{scan_xml}"

    # Prepare client
    key = api_key or os.getenv("OPENAI_API_KEY")
    if not key:
        return {"status": "error", "error": "No API key provided (api_key param or OPENAI_API_KEY env var required)."}

    client = OpenAI(api_key=key)

    # Call the model
    try:
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a concise security analyst that outputs strictly valid JSON."},
                {"role": "user", "content": prompt}
            ],
            temperature=temperature,
            max_tokens=max_tokens
        )
    except Exception as e:
        return {"status": "error", "error": f"API request failed: {e}"}

    # Extract assistant text
    try:
        assistant_text = resp.choices[0].message.content
    except Exception:
        assistant_text = str(resp)

    # Try to parse assistant output as JSON
    parsed = None
    try:
        parsed = json.loads(assistant_text)
    except Exception:
        # extract first JSON object substring (best-effort)
        m = re.search(r"(\{[\s\S]*\})", assistant_text)
        if m:
            try:
                parsed = json.loads(m.group(1))
            except Exception:
                parsed = None

    # Return structured result
    if parsed is not None:
        # minimal sanitation / defaults
        parsed.setdefault("risk_table", {"Critical": 0, "High": 0, "Medium": 0, "Low": 0})
        parsed.setdefault("reconnaissance", {
            "open_ports": [], "services": [], "service_versions": [],
            "subdomains": [], "subdirectories": [], "ip_addresses": [], "hostnames": []
        })
        parsed.setdefault("ranked_findings", [])
        parsed.setdefault("top_findings_table", parsed["ranked_findings"][:5])
        parsed.setdefault("truncated", False)
        # normalize overall_risk_score
        try:
            ors = int(parsed.get("overall_risk_score") or 1)
            parsed["overall_risk_score"] = max(1, min(10, ors))
        except Exception:
            parsed["overall_risk_score"] = 1

        return {"status": "ok", "parsed": parsed, "raw": assistant_text}
    else:
        return {"status": "warning", "parsed": None, "raw": assistant_text,
                "error": "Assistant output not parseable as JSON. Inspect 'raw' for debugging."}


# -------------------------
# JSON Analyzer interface (no XML)
# -------------------------
def analyze_json_ai_only(
    scan_json: Dict[str, Any],
    mode: str,
    api_key: str = "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",
    model: str = "gpt-5",
    temperature: float = 0.15,
    max_tokens: int = 2000
) -> Dict[str, Any]:
    if not isinstance(scan_json, dict) or not scan_json:
        return {"status": "error", "error": "scan_json must be a non-empty object."}

    try:
        scan_json_str = json.dumps(scan_json)
    except Exception as e:
        return {"status": "error", "error": f"Failed to serialize JSON: {e}"}

    instruction =  (
        "You are an expert web/security analyst. Analyze the provided XML vulnerability scan report and "
        "return STRICT valid JSON (no extra commentary) matching the schema described below.\n\n"
        "TOP-LEVEL OBJECT SCHEMA:\n"
        "{\n"
        "  \"top_level_summary\": \"<2-3 sentence overview>\",\n"
        "  \"overall_risk_score\": <integer 1-10>,\n"
        "  \"risk_table\": {\"Critical\": int, \"High\": int, \"Medium\": int, \"Low\": int},\n"
        "  \"top_findings_table\": [ { index, name, severity, risk_score, url (opt), description, rationale, remediation OR exploitation_concept & detection_indicators } ... up to 5 ],\n"
        "  \"ranked_findings\": [ same structure as top_findings_table for full list sorted by risk_score desc ],\n"
        "  \"reconnaissance\": {\n"
        "      \"open_ports\": [ {\"port\": int, \"protocol\": \"tcp|udp\", \"service\": \"\", \"version\": \"\"}, ... ],\n"
        "      \"services\": [ {\"service\": \"\", \"port\": int}, ... ],\n"
        "      \"service_versions\": [ {\"service\":\"\", \"version\":\"\", \"port\": int}, ... ],\n"
        "      \"subdomains\": [\"a.example.com\", ...],\n"
        "      \"subdirectories\": [\"/admin\", \"/uploads\", ...],\n"
        "      \"ip_addresses\": [\"1.2.3.4\", ...],\n"
        "      \"hostnames\": [\"host.example.com\", ...]\n"
        "  },\n"
        "  \"truncated\": <boolean>\n"
        "}\n\n"
        f"MODE: {mode.upper()}\n"
        + (
            "If MODE=BLUE: include 'remediation' for each finding (concrete fixes, config, mitigations).\n"
            if mode == "blue"
            else
            "If MODE=RED: include 'exploitation_concept' (high-level conceptual attack path) and 'detection_indicators' (log/monitoring cues). DO NOT provide exploit payloads, step-by-step commands, or scripts.\n"
        )
        + "\nSAFETY RULE: Under no circumstances return exploit payloads, working exploit code, step-by-step commands, or automation scripts that enable unauthorized access. For RED mode, only conceptual attack vectors and detection cues are allowed.\n"
        "Return ONLY the JSON object and no other text."
    )
    prompt = f"{instruction}\n\nSCAN_JSON:\n{scan_json_str}"

    key = api_key or os.getenv("OPENAI_API_KEY")
    if not key:
        return {"status": "error", "error": "No API key provided (api_key param or OPENAI_API_KEY env var required)."}

    client = OpenAI(api_key=key)
    try:
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a concise security analyst that outputs strictly valid JSON."},
                {"role": "user", "content": prompt}
            ],
            temperature=temperature,
            max_tokens=max_tokens
        )
    except Exception as e:
        return {"status": "error", "error": f"API request failed: {e}"}

    try:
        assistant_text = resp.choices[0].message.content
    except Exception:
        assistant_text = str(resp)

    try:
        parsed = json.loads(assistant_text)
    except Exception:
        m = re.search(r"(\{[\s\S]*\})", assistant_text)
        parsed = json.loads(m.group(1)) if m else None

    if parsed is not None:
        parsed.setdefault("risk_table", {"Critical": 0, "High": 0, "Medium": 0, "Low": 0})
        parsed.setdefault("reconnaissance", {
            "open_ports": [], "services": [], "service_versions": [],
            "subdomains": [], "subdirectories": [], "ip_addresses": [], "hostnames": []
        })
        parsed.setdefault("ranked_findings", [])
        parsed.setdefault("top_findings_table", parsed["ranked_findings"][:5])
        parsed.setdefault("truncated", False)
        try:
            ors = int(parsed.get("overall_risk_score") or 1)
            parsed["overall_risk_score"] = max(1, min(10, ors))
        except Exception:
            parsed["overall_risk_score"] = 1
        return {"status": "ok", "parsed": parsed, "raw": assistant_text}
    else:
        return {"status": "warning", "parsed": None, "raw": assistant_text,
                "error": "Assistant output not parseable as JSON. Inspect 'raw' for debugging."}
    
