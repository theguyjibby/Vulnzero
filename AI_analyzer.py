import os
import json
from typing import Any, Dict
from dotenv import load_dotenv

import google.genai as genai
from google.genai import types 
# The type import is still useful, but we won't use the JSON-specific config options

load_dotenv()

# IMPORTANT: Ensure GEMINI_API_KEY is correctly set in your environment or .env file.
def analyze_json_ai_only(
    scan_json: Dict[str, Any],
    mode: str,
    # Use the specific Gemini environment variable for clarity
    api_key=os.getenv("GEMINI_API_KEY"), 
    model: str = "gemini-2.5-flash",
    temperature: float = 0.15,
    max_tokens: int = 2000
) -> Dict[str, Any]:
    if not isinstance(scan_json, dict) or not scan_json:
        return {"status": "error", "error": "scan_json must be a non-empty object."}

    try:
        scan_json_str = json.dumps(scan_json)
    except Exception as e:
        return {"status": "error", "error": f"Failed to serialize JSON: {e}"}

    # --- INSTRUCTION PROMPT (MODIFIED to request structured text) ---
    instruction = (
    "You are an expert web/security analyst. Analyze the provided json vulnerability scan report and "
    "return a single **structured text report** using **STRICT MARKDOWN** formatting. "
    "DO NOT return raw JSON or any commentary outside the report structure. "
    "Follow the EXACT STRUCTURE, HEADINGS (use # and ##), and FIELD NAMES below.\n\n"
    
    "## 📄 Top-Level Summary\n"
    "* **Top-Level Summary:** <2-3 sentence overview>\n"
    "* **Overall Risk Score:** <integer 1-10>\n"
    
    "## 📈 Risk Table\n"
    "**REQUIRED ACTION: Generate a MARKDOWN TABLE.** Columns MUST be **Severity** and **Count** (Critical, High, Medium, Low).\n"
    
    "## 🛑 Top Findings Table\n"
    "**REQUIRED ACTION: Generate a MARKDOWN TABLE.** List the top 5 findings. Columns MUST include: **Index**, **Name**, **Severity**, **Risk Score**, **Description**, and the required **MODE-specific column(s)** below.\n"
    
    "## 🔍 Reconnaissance\n"
    "**REQUIRED ACTION: Generate MARKDOWN LISTS.** Provide a separate list for each category, listing all available data:\n"
    "* **Open Ports**\n"
    "* **Services**\n"
    "* **Service Versions**\n"
    "* **Subdomains**\n"
    "* **Subdirectories**\n"
    "* **IP Addresses**\n"
    "* **Hostnames**\n"
    
    "## 📏 Truncated\n"
    "* **Truncated:** <boolean>\n\n"
    
    f"MODE: {mode.upper()}\n"
    + (
        "If MODE=BLUE: **CRITICALLY IMPORTANT**: Top Findings Table MUST include a **Remediation** column.\n"
        if mode == "blue"
        else
        "If MODE=RED: **CRITICALLY IMPORTANT**: Top Findings Table MUST include **Exploitation Concept** and **Detection Indicators** columns. DO NOT provide exploit payloads, step-by-step commands, or scripts.\n"
    )
    + "\nSAFETY RULE: Under no circumstances return exploit payloads, working exploit code, step-by-step commands, or automation scripts that enable unauthorized access.\n"
    "Return ONLY the structured text report and no other text."

)
    prompt = f"{instruction}\n\nSCAN_JSON:\n{scan_json_str}"

    key = api_key
    if not key:
        return {"status": "error", "error": "No API key provided. Please set the 'GEMINI_API_KEY' environment variable."}

    # Define the system instruction text (Still good for setting the model's persona)
    system_instruction_text = "You are a concise security analyst that outputs a structured text report."

    try:
        client = genai.Client(api_key=key) 
    except Exception as e:
        return {"status": "error", "error": f"Failed to initialize Gemini client: {e}"}
    
    try:
        # 1. Define the generation config:
        # We REMOVE response_mime_type="application/json" to get standard text output
        generation_config = types.GenerateContentConfig( 
            temperature=temperature,
            max_output_tokens=max_tokens,
            # response_mime_type="application/json", # <-- REMOVED
            system_instruction=system_instruction_text 
        )

        # 2. Make the call
        resp = client.models.generate_content(
            model=model,
            contents=prompt,
            config=generation_config
        )
        
        # Check for a blocked or empty response
        if not resp.text:
             return {"status": "error", "error": f"API returned an empty response. Check if content was blocked or if the prompt is too complex for the model. Raw response object: {str(resp)}"}


    except Exception as e:
        return {"status": "error", "error": f"API request failed: {e}"}

    # --- Output handling is now simple text access ---
    assistant_text = resp.text

    # Since you want raw text, we return it directly, skipping the complex JSON parsing/cleaning
    return {"status": "ok", "raw_report": assistant_text}

if __name__ == "__main__":
    # Example minimal input data
    yay = analyze_json_ai_only(
        {
            "target": "example.com", 
            "vulnerabilities": [
                {"name": "XSS", "severity": "High", "url": "/search"},
                {"name": "Outdated SSH", "severity": "Medium", "port": 22}
            ]
        },
        "red"
    )
    print(json.dumps(yay, indent=2))