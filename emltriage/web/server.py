import os
import shutil
import tempfile
import json
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from emltriage.core.parser import parse_eml_file, create_iocs_json
from emltriage.core.models import AnalysisMode
from emltriage.cti import CTIEngine, CTIProviderType


app = FastAPI(title="emltriage Backend")

# Define base path relative to this file
BASE_DIR = Path(__file__).parent.absolute()

@app.post("/api/analyze")
async def analyze_eml(file: UploadFile = File(...), vt_api_key: str = Form(None)):
    if not file.filename.endswith('.eml'):
        raise HTTPException(status_code=400, detail="Only .eml files are supported")

    # Create a temporary directory for analysis
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        eml_path = tmp_path / file.filename
        output_path = tmp_path / "output"
        output_path.mkdir()

        # Save uploaded file
        with open(eml_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        try:
            # Run analysis
            artifacts = parse_eml_file(
                file_path=eml_path,
                output_dir=output_path,
                mode=AnalysisMode.TRIAGE,
                offline=True,
                redact=False,
                perform_dns_lookup=False
            )

            # Generate IOCs
            iocs = create_iocs_json(artifacts, filter_infrastructure=True)

            # Build response
            response_data = {
                "artifacts": artifacts.model_dump(mode='json'),
                "iocs": iocs.model_dump(mode='json'),
                "auth_results": artifacts.authentication.model_dump(mode='json')
            }

            return JSONResponse(content=response_data)

        except Exception as e:
            import traceback
            traceback.print_exc()
            raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/api/analyze/cti")
async def analyze_eml_cti(file: UploadFile = File(...), vt_api_key: str = Form(None)):
    if not file.filename.endswith('.eml'):
        raise HTTPException(status_code=400, detail="Only .eml files are supported")

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        eml_path = tmp_path / file.filename
        output_path = tmp_path / "output"
        output_path.mkdir()

        with open(eml_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        try:
            artifacts = parse_eml_file(
                file_path=eml_path,
                output_dir=output_path,
                mode=AnalysisMode.TRIAGE,
                offline=True,
                redact=False,
                perform_dns_lookup=False
            )
            iocs = create_iocs_json(artifacts, filter_infrastructure=True)

            response_data = {}
            if vt_api_key:
                os.environ["VIRUSTOTAL_API_KEY"] = vt_api_key
                engine = CTIEngine(offline=False, providers=[CTIProviderType.VIRUSTOTAL])
                
                # Cap VT lookups
                import copy
                vt_iocs = copy.deepcopy(iocs)
                
                # Prioritize IOCs from the body/attachments over routing headers
                def sort_iocs(ioc_list):
                    score_map = {'body_html': 0, 'body_plain': 0, 'attachments': 1, 'headers': 2}
                    return sorted(ioc_list, key=lambda ioc: score_map.get(getattr(ioc, 'source', ''), 3))

                # Filter out obvious safe/routing infrastructure domains to save VT quota
                safe_infra = ['namprd', 'outlook.com', 'schemas.microsoft.com', 'w3.org', 'protection.outlook.com']
                
                vt_iocs.domains = [d for d in vt_iocs.domains if not d.value.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg')) and not any(safe in d.value.lower() for safe in safe_infra)]
                vt_iocs.urls = [u for u in vt_iocs.urls if not u.value.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg')) and not any(safe in u.value.lower() for safe in safe_infra)]
                
                vt_iocs.domains = sort_iocs(vt_iocs.domains)[:3]
                vt_iocs.ips = sort_iocs(vt_iocs.ips)[:2]
                vt_iocs.urls = sort_iocs(vt_iocs.urls)[:2]
                vt_iocs.hashes = vt_iocs.hashes[:0]

                try:
                    enrichments = engine.enrich_iocs(vt_iocs)
                    cti_data = enrichments.model_dump(mode='json')
                except Exception as cti_err:
                    print(f"WARN: CTI Enrichment failed: {cti_err}")
                    cti_data = {"summary": {}, "enrichments": []}

                import socket
                import subprocess

                dns_records = {}
                whois_data = {}
                
                for d in vt_iocs.domains:
                    domain = d.value.strip()
                    try:
                        dns_records[domain] = socket.gethostbyname(domain)
                    except Exception as e:
                        dns_records[domain] = f"Error: {e}"
                    
                    try:
                        proc = subprocess.run(['whois', domain], capture_output=True, text=True, timeout=5)
                        whois_out = proc.stdout
                        creation = "Unknown"
                        registrar = "Unknown"
                        for line in whois_out.split('\\n'):
                            line_l = line.lower()
                            # Use regex for creation date to avoid grabbing full Verisign server string blobs
                            if ('creation date:' in line_l or 'created:' in line_l) and creation == "Unknown":
                                import re
                                date_match = re.search(r'\d{4}-\d{2}-\d{2}', line_l)
                                if date_match:
                                    creation = date_match.group(0)
                                else:
                                    # Fallback if no strict YYYY-MM-DD
                                    parts = line.split(':', 1)
                                    if len(parts) > 1 and len(parts[1].strip()) < 30:
                                        creation = parts[1].strip()
                            elif 'registrar:' in line_l and registrar == "Unknown":
                                parts = line.split(':', 1)
                                if len(parts) > 1 and len(parts[1].strip()) < 100:
                                    registrar = parts[1].strip()
                        
                        # Deterministic WHOIS Assessment Heuristic
                        assessment = "Neutral"
                        brand_keywords = ['microsoft', 'office', 'google', 'apple', 'login', 'secure', 'verify', 'update', 'account', 'admin']
                        enterprise_registrars = ['markmonitor', 'csc corporate domains', 'amazon', 'google']
                        
                        reg_lower = registrar.lower()
                        dom_lower = domain.lower()
                        
                        has_brand = any(kw in dom_lower for kw in brand_keywords)
                        is_enterprise = any(ent in reg_lower for ent in enterprise_registrars)
                        
                        if has_brand and not is_enterprise and registrar != "Unknown":
                            assessment = "Suspicious (Brand Impersonation)"
                        elif is_enterprise:
                            assessment = "Legitimate (Enterprise Registrar)"
                        elif '2024' in creation or '2025' in creation or '2026' in creation:
                            assessment = "Suspicious (Newly Registered)"
                            
                        whois_data[domain] = {
                            "creation": creation, 
                            "registrar": registrar, 
                            "assessment": assessment,
                            "raw": whois_out
                        }
                    except Exception as e:
                        whois_data[domain] = {"error": str(e)}

                cti_data["dns_records"] = dns_records
                cti_data["whois"] = whois_data
                response_data["cti"] = cti_data

            return JSONResponse(content=response_data)
        except Exception as e:
            import traceback
            traceback.print_exc()
            raise HTTPException(status_code=500, detail=f"CTI Analysis failed: {str(e)}")


from pydantic import BaseModel

class AISummaryRequest(BaseModel):
    endpointUrl: str
    apiKey: str
    model: str
    prompt: str
    length: str = 'medium'

@app.post("/api/ai/summarize")
async def summarize_eml(req: AISummaryRequest):
    import urllib.request
    import urllib.error
    import re
    
    url = req.endpointUrl.rstrip('/')
    
    # Smarter Universal Routing
    is_ollama = "11434" in url
    
    if is_ollama:
        # Resolve Ollama native vs compat paths
        if url.endswith(":11434") or url.endswith("/v1"):
            url = url.replace("/v1", "") + "/api/chat"
    else:
        # Default Cloud Provider Handling (DeepSeek, Groq, OpenAI)
        if "/v1" not in url and not url.endswith("/chat/completions"):
            # If user provided a base URL, append standard path
            url += "/v1/chat/completions"
        elif url.endswith("/v1"):
            url += "/chat/completions"

    headers = {
        "Content-Type": "application/json"
    }
    
    # Pass Auth Key for Cloud providers
    if req.apiKey and req.apiKey.lower() not in ['local', 'none', '']:
        headers["Authorization"] = f"Bearer {req.apiKey}"

    # Dynamic Length Controls
    max_tokens = 300
    system_instruction = "You are a senior DFIR analyst. You receive structured forensic triage data. Be direct. No internal reasoning. No preamble."
    
    if req.length == 'quick':
        max_tokens = 150
        system_instruction += " Provide ONLY: a one-line Verdict, and one summary sentence."
    elif req.length == 'comprehensive':
        max_tokens = 600
        system_instruction += " Provide a detailed narrative, evidence list, and robust plan of action."
    else:
        max_tokens = 300
        system_instruction += " Provide ONLY: a one-line Verdict, a Key Evidence bullet list (max 5 items), and Immediate Actions (max 3 numbered steps)."

    payload = {
        "model": req.model,
        "messages": [
            {
                "role": "system",
                "content": system_instruction
            },
            {
                "role": "user",
                "content": req.prompt
            }
        ],
        "temperature": 0.0,
        "max_tokens": max_tokens,
        "stream": False
    }

    try:
        print(f"INFO: AI Request -> URL: {url} | Model: {req.model}")
        data = json.dumps(payload).encode('utf-8')
        request = urllib.request.Request(url, data=data, headers=headers, method='POST')
        
        # Heavy reasoning models (Qwen 9B, DeepSeek-R1) need more time
        with urllib.request.urlopen(request, timeout=180) as response:
            res_body = response.read().decode('utf-8')
            result = json.loads(res_body)
            
            answer = ""
            if 'choices' in result and len(result['choices']) > 0:
                answer = result['choices'][0]['message']['content']
            elif 'message' in result and 'content' in result['message']:
                answer = result['message']['content']
            elif 'response' in result:
                answer = result['response']
            else:
                raise HTTPException(status_code=500, detail=f"Unexpected AI response structure: {result}")

            # Universal suppression of reasoning headers/tags
            answer = re.sub(r'<thinking>.*?</thinking>', '', answer, flags=re.DOTALL | re.IGNORECASE)
            answer = re.sub(r'Thinking Process:.*?\n\n', '', answer, flags=re.DOTALL | re.IGNORECASE)
            answer = answer.strip()
                
            print(f"INFO: AI Response Received ({len(answer)} chars)")
            return {"summary": answer}
                
    except urllib.error.URLError as e:
        print(f"ERROR: AI Connection Failed: {str(e)}")
        raise HTTPException(status_code=502, detail=f"Target LLM unreachable: {str(e)}")
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"AI Bridge Bridge Error: {str(e)}")


# Mount at root
app.mount("/", StaticFiles(directory=BASE_DIR, html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
