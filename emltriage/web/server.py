import os
import shutil
import tempfile
import json
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from fastapi.responses import JSONResponse
from emltriage.core.parser import parse_eml_file, create_iocs_json
from emltriage.core.models import AnalysisMode
from emltriage.cti import CTIEngine, CTIProviderType
from emltriage.infra.robust_whois import RobustWhoisLookup, assess_domain
from emltriage.reporting.schemas import InvestigationReport
from emltriage.reporting.json_generator import generate_report_from_dict
from emltriage.reporting.ai_narrative import AIRegenerator


app = FastAPI(title="emltriage Backend")

# Define base path relative to this file
BASE_DIR = Path(__file__).parent.absolute()

@app.post("/api/analyze")
async def analyze_eml(file: UploadFile = File(...), vt_api_key: str = Form(None)):
    if not file.filename.endswith(('.eml', '.msg')):
        raise HTTPException(status_code=400, detail="Only .eml or .msg files are supported")

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

from pydantic import BaseModel

class CTIFastRequest(BaseModel):
    domains: list[str]

@app.post("/api/cti/fast")
async def analyze_cti_fast(req: CTIFastRequest):
    try:
        import asyncio
        import re

        dns_records = {}
        whois_data = {}

        # Asynchronous DNS Dig
        async def fetch_dig(domain):
            domain = domain.strip()
            if not domain:
                return domain, "Empty domain"
            try:
                proc = await asyncio.create_subprocess_exec(
                    'dig', '+short', 'A', domain,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                try:
                    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=3.0)
                except asyncio.TimeoutError:
                    proc.kill()
                    return domain, "Dig timeout"
                
                out = stdout.decode('utf-8').strip()
                if out:
                    # dig +short can return multiple lines like aliases then IPs, let's format nicely
                    lines = [ln.strip() for ln in out.split('\n') if ln.strip()]
                    return domain, " | ".join(lines)
                return domain, "No A Record"
            except Exception as e:
                return domain, f"Dig Error: {e}"

        # Asynchronous WHOIS with Multi-Layer Fallback
        async def fetch_whois(domain):
            domain = domain.strip()
            if not domain:
                return domain, {"error": "Empty domain", "registrar": "N/A", "creation": "N/A", "assessment": "Unknown"}
            
            try:
                async with RobustWhoisLookup(timeout=5.0) as lookup:
                    result = await lookup.lookup(domain)
                    
                    if result.error:
                        return domain, {
                            "error": result.error,
                            "registrar": result.registrar,
                            "creation": result.creation_date,
                            "assessment": result.assessment,
                            "raw": result.raw,
                            "source": result.source
                        }
                    
                    assessment = assess_domain(result.registrar, result.creation_date, domain)
                    
                    return domain, {
                        "registrar": result.registrar,
                        "creation": result.creation_date,
                        "assessment": assessment,
                        "raw": result.raw,
                        "source": result.source,
                        "error": None
                    }
            except Exception as e:
                return domain, {
                    "error": f"Lookup failed: {str(e)}",
                    "registrar": "Unknown",
                    "creation": "Unknown",
                    "assessment": "Unknown",
                    "raw": ""
                }

        domains_to_check = [d.strip() for d in req.domains if d.strip()]
        
        # Fire both dig and whois concurrently for all domains
        dns_results, whois_results = await asyncio.gather(
            asyncio.gather(*(fetch_dig(d) for d in domains_to_check)),
            asyncio.gather(*(fetch_whois(d) for d in domains_to_check))
        )
        
        for domain, result in dns_results:
            dns_records[domain] = result
            
        for domain, data in whois_results:
            whois_data[domain] = data

        return JSONResponse(content={"dns_records": dns_records, "whois": whois_data})
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Fast CTI failed: {str(e)}")

class CTIVTRequest(BaseModel):
    vt_api_key: str
    domains: list[str]
    ips: list[str]
    urls: list[str]

@app.post("/api/cti/vt")
async def analyze_cti_vt(req: CTIVTRequest):
    try:
        import os
        from emltriage.cti import CTIEngine, CTIProviderType
        from emltriage.core.models import IOCsExtracted, IOCEntry, IOCType
        
        os.environ["VIRUSTOTAL_API_KEY"] = req.vt_api_key
        engine = CTIEngine(offline=False, providers=[CTIProviderType.VIRUSTOTAL])
        
        import uuid
        vt_iocs = IOCsExtracted(
            run_id=uuid.uuid4().hex,
            domains=[IOCEntry(type=IOCType.DOMAIN, value=d, source='web', evidence_ref='web', first_seen_in='web') for d in req.domains],
            ips=[IOCEntry(type=IOCType.IP, value=i, source='web', evidence_ref='web', first_seen_in='web') for i in req.ips],
            urls=[IOCEntry(type=IOCType.URL, value=u, source='web', evidence_ref='web', first_seen_in='web') for u in req.urls],
            emails=[],
            hashes=[],
            filenames=[],
            infrastructure=[]
        )
        
        try:
            enrichments = engine.enrich_iocs(vt_iocs)
            cti_data = enrichments.model_dump(mode='json')
        except Exception as cti_err:
            print(f"WARN: CTI Enrichment failed: {cti_err}")
            cti_data = {"summary": {}, "enrichments": []}

        return JSONResponse(content={"enrichments": cti_data.get("enrichments", [])})
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"VT CTI failed: {str(e)}")


from pydantic import BaseModel

class AISummaryRequest(BaseModel):
    endpointUrl: str
    apiKey: str
    model: str
    prompt: str
    length: str = 'medium'

class DocxExportRequest(BaseModel):
    artifacts: dict
    ai_summary: str = None
    auto_open: bool = False

@app.post("/api/export/docx")
async def export_docx(req: DocxExportRequest):
    try:
        from emltriage.core.models import Artifacts
        from emltriage.reporting.docx import generate_docx_report
        import typing
        from fastapi.responses import FileResponse
        import uuid
        import os
        import sys
        import subprocess

        artifacts = Artifacts.model_validate(req.artifacts)
        
        # Save to a dedicated output folder (or temp)
        case_dir = Path.home() / "emltriage_cases"
        case_dir.mkdir(parents=True, exist_ok=True)
        
        run_id = artifacts.metadata.run_id or str(uuid.uuid4())
        filename = artifacts.metadata.input_filename or "email"
        
        out_path = case_dir / f"Report_{filename}_{run_id}.docx"
        generate_docx_report(artifacts, out_path, req.ai_summary)
        
        if req.auto_open:
            if sys.platform == "darwin":
                subprocess.call(["open", str(out_path)])
            elif sys.platform == "win32":
                os.startfile(str(out_path))
            else:
                subprocess.call(["xdg-open", str(out_path)])
                
        # Return file for download
        return FileResponse(
            path=out_path,
            media_type='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            filename=f"Report_{filename}.docx"
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Export failed: {str(e)}")

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


# Report Generation Endpoint
class ReportRequest(BaseModel):
    artifacts: dict
    case_id: str = ""
    include_ai: bool = True


@app.post("/api/report/generate")
async def generate_investigation_report(req: ReportRequest):
    """Generate investigation report JSON with optional AI narrative."""
    try:
        report = generate_report_from_dict(req.artifacts, case_id=req.case_id)
        
        if req.include_ai:
            ai_gen = AIRegenerator()
            if ai_gen.is_available():
                ai_outputs = await ai_gen.generate_narrative(report)
                report.ai_outputs = ai_outputs
            else:
                report.ai_outputs.ai_inputs = report.ai_inputs
                report.ai_outputs.posible_impacto = "Ollama no disponible"
        
        return JSONResponse(content=report.model_dump(mode='json'))
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")


@app.get("/api/ai/status")
async def ai_status():
    """Check AI provider status."""
    ai_gen = AIRegenerator()
    return {
        "available": ai_gen.is_available(),
        "provider": "ollama",
        "model": "llama3.1"
    }


# Mount at root
app.mount("/", StaticFiles(directory=BASE_DIR, html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
