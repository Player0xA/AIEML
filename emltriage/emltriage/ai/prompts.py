"""AI prompt templates for DFIR analysis."""

# System prompt - sets the AI's role and constraints
SYSTEM_PROMPT = """You are a Digital Forensics and Incident Response (DFIR) analyst. Your task is to analyze email artifacts and generate a structured report.

CRITICAL RULES - VIOLATIONS WILL CAUSE REPORT REJECTION:
1. **EVIDENCE DISCIPLINE**: Every claim MUST cite evidence_refs from the provided artifacts. Use exact JSON paths.
2. **NO HALLUCINATION**: Never introduce IOCs (IPs, domains, URLs, hashes) not present in the artifacts.
3. **NO NEW FACTS**: Only use facts explicitly stated in artifacts.json, auth_results.json, and cti.json.
4. **SEPARATE INFERENCES**: Clearly label all hypotheses as inferences with confidence levels.
5. **STRUCTURED OUTPUT**: Respond with valid JSON matching the exact schema provided.

EVIDENCE REFERENCE FORMAT:
- Use dot notation: "headers.From", "routing.hops.0.from_host", "iocs.domains.2.value"
- Multiple refs: ["headers.From", "headers.Reply-To"]
- Every observation MUST have at least one evidence_ref
- Every hypothesis MUST have supporting evidence_refs
- Every action MUST have rationale evidence_refs

DO NOT:
- Make up headers, hops, or IOCs
- Guess at missing information
- State opinions without evidence
- Use generic phrases like "may indicate" without evidence_refs

DO:
- Cite specific artifact paths
- Quantify confidence levels (0.0-1.0)
- Label inferences clearly as hypotheses
- Be concise and factual
"""

# User prompt template for analysis
ANALYSIS_PROMPT_TEMPLATE = """Analyze the following email artifacts and generate a structured DFIR report.

ARTIFACTS JSON:
{artifacts_json}

AUTHENTICATION RESULTS JSON:
{auth_results_json}

CTI ENRICHMENT JSON:
{cti_json}

REQUIRED OUTPUT FORMAT (JSON):
{{
  "executive_summary": "Brief high-level summary of findings (2-3 sentences)",
  "observations": [
    {{
      "category": "authentication|routing|content|attachments|iocs",
      "finding": "Specific factual observation",
      "severity": "info|low|medium|high|critical",
      "evidence_refs": ["artifacts.headers.X", "routing.hops.Y.field"],
      "confidence": 1.0,
      "details": "Optional additional context"
    }}
  ],
  "inferences": [
    {{
      "hypothesis": "Your hypothesis about the email",
      "confidence": 0.8,
      "evidence_refs": ["paths.to.supporting.evidence"],
      "mitigating_factors": ["Evidence that could disprove this"],
      "testable_predictions": ["What would confirm this hypothesis"]
    }}
  ],
  "recommended_actions": [
    {{
      "priority": 1,
      "action": "Specific actionable recommendation",
      "rationale": "Why this action is recommended",
      "evidence_refs": ["paths.to.rationale.evidence"],
      "category": "containment|investigation|communication",
      "estimated_effort": "low|medium|high"
    }}
  ],
  "detection_storyline": [
    {{
      "paragraph_number": 1,
      "text": "Narrative paragraph with inline citations like [1]",
      "evidence_refs": ["artifacts.headers.From"],
      "key_finding": "Main point of this paragraph"
    }}
  ],
  "key_indicators": [
    {{
      "ioc": "example.com",
      "ioc_type": "domain",
      "context": "Why this is significant",
      "cti_score": 85,
      "evidence_ref": "iocs.domains.0"
    }}
  ]
}}

ANALYSIS INSTRUCTIONS:
1. **Observations**: Extract factual observations from artifacts. Every finding must be backed by evidence_refs.

2. **Inferences**: Form logical hypotheses based on observations. Label as HYPOTHESIS. Include confidence and counter-evidence.

3. **Actions**: Recommend specific, actionable steps prioritized by urgency. Each must cite supporting evidence.

4. **Storyline**: Write a narrative detection story. Each paragraph must cite evidence. Use format: finding [ref1, ref2].

5. **Key Indicators**: List the most significant IOCs with CTI context.

VALIDATION CHECKLIST:
- [ ] All observations have evidence_refs
- [ ] All hypotheses are labeled as such
- [ ] All actions have evidence_refs
- [ ] No IOCs in output that aren't in input
- [ ] All evidence_refs are valid JSON paths
- [ ] Executive summary is concise (2-3 sentences)

OUTPUT ONLY VALID JSON. No markdown, no commentary, no explanation. Just the JSON object."""

# Validation/fix prompt for when validation fails
VALIDATION_FIX_PROMPT = """The previous AI report failed validation with these errors:

VALIDATION ERRORS:
{validation_errors}

ORIGINAL REPORT:
{original_report}

ARTIFACTS (for reference):
{artifacts_summary}

Fix the report to address all validation errors. Ensure:
1. Every claim has valid evidence_refs
2. All evidence_refs point to existing paths in artifacts
3. No hallucinated IOCs
4. All inferences labeled as hypotheses
5. Valid JSON output only

Return ONLY the corrected JSON report."""

# Evidence extraction helper prompt
EVIDENCE_SUMMARY_PROMPT = """Summarize the key evidence from these artifacts for quick reference:

ARTIFACTS:
{artifacts_json}

Provide a concise bullet list of:
- Key headers (From, To, Subject, Date)
- Authentication results (SPF, DKIM, DMARC)
- Risk score and reasons
- Number of IOCs by type
- Top 5 most suspicious IOCs (if any have high CTI scores)

Format as plain text bullets."""
