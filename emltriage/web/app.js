/**
 * emltriage Web UI - Main Application
 * Handles file loading, rendering, theme switching, and visual effects
 */

// Demo Data for testing without files
const DEMO_DATA = {
  artifacts: {
    metadata: {
      run_id: "demo-001",
      timestamp: "2026-03-05T10:00:00Z",
      input_filename: "suspicious_email.eml",
      analysis_mode: "deep"
    },
    headers: [
      { name: "From", raw_value: "sender@evil-domain.com", decoded_value: "sender@evil-domain.com", parsed: { addresses: [{ address: "sender@evil-domain.com", domain: "evil-domain.com" }] } },
      { name: "To", raw_value: "victim@company.com", decoded_value: "victim@company.com", parsed: { addresses: [{ address: "victim@company.com", domain: "company.com" }] } },
      { name: "Subject", raw_value: "Urgent: Action Required", decoded_value: "Urgent: Action Required" },
      { name: "Date", raw_value: "Wed, 05 Mar 2026 10:00:00 +0000", parsed: { timestamp: "2026-03-05T10:00:00Z" } },
      { name: "Message-ID", raw_value: "<123456789@evil-domain.com>" },
      { name: "Authentication-Results", raw_value: "spf=fail; dkim=fail; dmarc=fail" }
    ],
    routing: [
      { hop_number: 0, from_host: "evil-domain.com", by_host: "mail-relay.example.com", timestamp: "2026-03-05T09:55:00Z", anomalies: ["suspicious_sender"] },
      { hop_number: 1, from_host: "mail-relay.example.com", by_host: "company-mail-gateway.com", timestamp: "2026-03-05T09:58:00Z" },
      { hop_number: 2, from_host: "company-mail-gateway.com", by_host: "exchange.company.com", timestamp: "2026-03-05T10:00:00Z" }
    ],
    authentication: {
      parsed_results: [{
        domain: "evil-domain.com",
        results: [
          { mechanism: "spf", result: "fail", reason: "IP not authorized" },
          { mechanism: "dkim", result: "fail", reason: "Signature verification failed" },
          { mechanism: "dmarc", result: "fail", reason: "SPF and DKIM failed" }
        ]
      }],
      dkim_verified: false
    },
    iocs: [
      { value: "evil-domain.com", type: "domain", source: "headers", evidence_ref: "headers.From" },
      { value: "phishing-link.com", type: "domain", source: "body", evidence_ref: "bodies.0" },
      { value: "192.168.1.100", type: "ipv4", source: "routing", evidence_ref: "routing.hops.0" },
      { value: "malware.exe", type: "filename", source: "attachments", evidence_ref: "attachments.0" },
      { value: "outlook.com", type: "domain", source: "headers", evidence_ref: "headers.Received" },
      { value: "protection.outlook.com", type: "domain", source: "routing", evidence_ref: "routing.hops.2" }
    ],
    urls: [
      { raw: "http://phishing-link.com/login", normalized: "http://phishing-link.com/login", deobfuscated: "http://phishing-link.com/login", source: "html_href" }
    ],
    attachments: [
      { id: "att-001", filename_raw: "invoice.pdf.exe", filename_decoded: "invoice.pdf.exe", content_type: "application/x-msdos-program", size: 1024000, hashes: { sha256: "abc123..." }, is_risky: true, risk_flags: ["double_extension", "executable"] }
    ],
    risk: {
      score: 85,
      severity: "high",
      reasons: [
        { code: "auth_failure_spf", description: "SPF authentication failed", weight: 20, severity: "high", evidence_refs: ["authentication.parsed_results.0.results.0"] },
        { code: "auth_failure_dkim", description: "DKIM signature verification failed", weight: 25, severity: "high", evidence_refs: ["authentication.parsed_results.0.results.1"] },
        { code: "risky_attachment", description: "Risky attachment: invoice.pdf.exe", weight: 25, severity: "high", evidence_refs: ["attachments.0"] },
        { code: "impersonation_detected", description: "Potential brand impersonation detected (2 findings, 1 high confidence)", weight: 40, severity: "high", evidence_refs: ["impersonation.0", "impersonation.1"] }
      ]
    },
    impersonation: [
      {
        brand_candidate: "Microsoft",
        detected_domain: "m1crosoft-security.com",
        technique: "typosquat",
        score: 0.92,
        severity: "critical",
        evidence_fields: ["headers.From", "urls.html_href"],
        algorithm: "weighted",
        source: "impersonation_detector",
        query: "m1crosoft-security.com vs Microsoft",
        timestamp: "2026-03-05T10:00:00Z",
        normalized_tokens: ["m1crosoft", "security", "m1crosoft-security"],
        confidence: 1.0,
        cost: 0,
        explanation: "Domain 'm1crosoft-security.com' appears to be a typo-squat of 'Microsoft' (edit distance: 1)"
      },
      {
        brand_candidate: "PayPal",
        detected_domain: "paypa1-verification.net",
        technique: "homoglyph",
        score: 0.88,
        severity: "high",
        evidence_fields: ["urls.html_href"],
        algorithm: "weighted",
        source: "impersonation_detector",
        query: "paypa1-verification.net vs PayPal",
        timestamp: "2026-03-05T10:00:00Z",
        normalized_tokens: ["paypa1", "verification", "paypa1-verification"],
        confidence: 1.0,
        cost: 0,
        explanation: "Domain 'paypa1-verification.net' contains homoglyph characters resembling 'PayPal' (ASCII: 'paypal-verification')"
      }
    ]
  },

  iocs: {
    run_id: "demo-001",
    domains: [
      { value: "evil-domain.com", type: "domain", source: "headers" },
      { value: "phishing-link.com", type: "domain", source: "body" }
    ],
    ips: [
      { value: "192.168.1.100", type: "ipv4", source: "routing" }
    ],
    infrastructure: [
      { value: "outlook.com", type: "domain", source: "headers" },
      { value: "protection.outlook.com", type: "domain", source: "routing" }
    ]
  },

  auth_results: {
    parsed_results: [{
      domain: "evil-domain.com",
      results: [
        { mechanism: "spf", result: "fail", reason: "IP not authorized" },
        { mechanism: "dkim", result: "fail", reason: "Signature verification failed" },
        { mechanism: "dmarc", result: "fail", reason: "SPF and DKIM failed" }
      ]
    }],
    dkim_verified: false
  }
};

// App State
const state = {
  currentTheme: localStorage.getItem('theme') || 'system',
  reducedMotion: localStorage.getItem('reducedMotion') === 'true',
  saveKeys: localStorage.getItem('saveKeys') !== 'false', // Default to true
  data: null,
  activePanel: 'overview',
  apiKeys: {
    vt: localStorage.getItem('vt_api_key') || '',
    abuse: localStorage.getItem('abuse_api_key') || '',
    openai: localStorage.getItem('openai_api_key') || ''
  },
  saveKeys: localStorage.getItem('saveKeys') !== 'false',
  llm: {
    endpoint: localStorage.getItem('llm_endpoint') || 'http://localhost:11434/v1',
    model: localStorage.getItem('llm_model') || 'qwen3.5:9b'
  },
  impersonation: {
    excludedBrands: [], // Brands to exclude from display
    severityFilter: 'all', // all, critical, high, medium
    findings: [] // Current findings after filtering
  }
};

// DOM Elements
const elements = {};

// Initialize App
document.addEventListener('DOMContentLoaded', () => {
  initializeElements();
  initializeTheme();
  initializeMotion();
  initializeEventListeners();
  initializeCanvas();
  checkApiKeys();

  showToast('Welcome to emltriage. Load a file or use demo data.', 'info');
});

// Element References
function initializeElements() {
  elements.app = document.getElementById('app');
  elements.dropZone = document.getElementById('drop-zone');
  elements.fileInput = document.getElementById('file-input');
  elements.panels = document.getElementById('panels');
  elements.demoControls = document.getElementById('demo-controls');
  elements.fileStatus = document.getElementById('file-status');
  elements.apiStatus = document.getElementById('api-status');
  elements.sidebar = document.querySelector('.sidebar');
  elements.sidebarToggle = document.getElementById('sidebar-toggle');
  elements.themeToggle = document.getElementById('theme-toggle');
  elements.motionToggle = document.getElementById('motion-toggle');
  elements.exportBtn = document.getElementById('export-btn');
  elements.spotlight = document.querySelector('.spotlight');
  elements.canvas = document.getElementById('ray-canvas');

  // Panel elements
  elements.riskScore = document.getElementById('risk-score');
  elements.riskSeverity = document.getElementById('risk-severity');
  elements.riskBar = document.getElementById('risk-bar');
  elements.riskReasons = document.getElementById('risk-reasons');
  // API Indicators
  elements.apiVT = document.getElementById('api-vt');
  elements.apiAbuse = document.getElementById('api-abuse');
  elements.apiOpenAI = document.getElementById('api-openai');
  elements.saveKeys = document.getElementById('save-keys-setting');

  elements.iocBadge = document.getElementById('ioc-badge');
  elements.ctiBadge = document.getElementById('cti-badge');
  elements.impersonationBadge = document.getElementById('impersonation-badge');

  // Search
  elements.iocSearch = document.getElementById('ioc-search');
}

// Theme Management
function initializeTheme() {
  const savedTheme = localStorage.getItem('theme') || 'system';
  applyTheme(savedTheme);
}

function applyTheme(theme) {
  state.currentTheme = theme;

  if (theme === 'system') {
    document.documentElement.removeAttribute('data-theme');
  } else {
    document.documentElement.setAttribute('data-theme', theme);
  }

  localStorage.setItem('theme', theme);
}

function toggleTheme() {
  const themes = ['system', 'light', 'dark'];
  const currentIndex = themes.indexOf(state.currentTheme);
  const nextTheme = themes[(currentIndex + 1) % themes.length];
  applyTheme(nextTheme);

  // Sync select element
  const themeSelect = document.getElementById('theme-select');
  if (themeSelect) themeSelect.value = nextTheme;

  showToast(`Theme: ${nextTheme}`, 'info');
}

// Reduced Motion Management
function initializeMotion() {
  const savedMotion = localStorage.getItem('reducedMotion') === 'true';
  state.reducedMotion = savedMotion;
  applyMotionPreference(savedMotion);
}

function applyMotionPreference(reduced) {
  state.reducedMotion = reduced;
  document.documentElement.setAttribute('data-reduced-motion', reduced);
  localStorage.setItem('reducedMotion', reduced);

  // Pause/resume canvas
  if (reduced) {
    stopCanvas();
  } else {
    startCanvas();
  }
}

function toggleMotion() {
  const newValue = !state.reducedMotion;
  applyMotionPreference(newValue);

  // Sync setting checkbox
  const motionSetting = document.getElementById('reduced-motion-setting');
  if (motionSetting) motionSetting.checked = newValue;

  showToast(newValue ? 'Reduced motion enabled' : 'Effects enabled', 'info');
}

// Canvas Shader Effects (Raytracing-like)
let canvasContext = null;
let canvasAnimationId = null;
let mouseX = 0;
let mouseY = 0;

function initializeCanvas() {
  if (!elements.canvas || state.reducedMotion) return;

  const ctx = elements.canvas.getContext('2d');
  canvasContext = ctx;

  resizeCanvas();
  window.addEventListener('resize', resizeCanvas);

  // Mouse tracking for spotlight
  document.addEventListener('mousemove', (e) => {
    mouseX = e.clientX;
    mouseY = e.clientY;
    updateSpotlight();
  });

  startCanvas();
}

function resizeCanvas() {
  if (!elements.canvas) return;
  elements.canvas.width = window.innerWidth;
  elements.canvas.height = window.innerHeight;
}

function startCanvas() {
  if (!canvasContext || state.reducedMotion) return;
  animateCanvas();
}

function stopCanvas() {
  if (canvasAnimationId) {
    cancelAnimationFrame(canvasAnimationId);
    canvasAnimationId = null;
  }
  if (canvasContext) {
    canvasContext.clearRect(0, 0, elements.canvas.width, elements.canvas.height);
  }
}

function updateSpotlight() {
  if (!elements.spotlight || state.reducedMotion) return;
  elements.spotlight.style.left = `${mouseX}px`;
  elements.spotlight.style.top = `${mouseY}px`;
}

// Simple light scattering effect
let time = 0;
function animateCanvas() {
  if (state.reducedMotion || document.hidden) {
    canvasAnimationId = requestAnimationFrame(animateCanvas);
    return;
  }

  const ctx = canvasContext;
  const w = elements.canvas.width;
  const h = elements.canvas.height;

  ctx.clearRect(0, 0, w, h);

  // Create light sources
  const lights = [
    { x: w * 0.2, y: h * 0.3, color: 'rgba(0, 113, 227, 0.08)', radius: 300 },
    { x: w * 0.8, y: h * 0.7, color: 'rgba(0, 113, 227, 0.06)', radius: 250 },
    { x: w * 0.5 + Math.sin(time * 0.001) * 100, y: h * 0.5 + Math.cos(time * 0.001) * 50, color: 'rgba(255, 255, 255, 0.04)', radius: 200 }
  ];

  // Draw lights with additive blending
  ctx.globalCompositeOperation = 'screen';

  lights.forEach(light => {
    const gradient = ctx.createRadialGradient(
      light.x, light.y, 0,
      light.x, light.y, light.radius
    );
    gradient.addColorStop(0, light.color);
    gradient.addColorStop(1, 'transparent');

    ctx.fillStyle = gradient;
    ctx.fillRect(0, 0, w, h);
  });

  // Add some noise/fog
  ctx.globalCompositeOperation = 'source-over';
  ctx.fillStyle = 'rgba(255, 255, 255, 0.01)';

  time += 16;
  canvasAnimationId = requestAnimationFrame(animateCanvas);
}

// Event Listeners
function initializeEventListeners() {
  // Drag and drop
  elements.dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    elements.dropZone.classList.add('drag-over');
  });

  elements.dropZone.addEventListener('dragleave', () => {
    elements.dropZone.classList.remove('drag-over');
  });

  elements.dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    elements.dropZone.classList.remove('drag-over');
    handleFiles(e.dataTransfer.files);
  });

  // File input
  elements.fileInput.addEventListener('change', (e) => {
    handleFiles(e.target.files);
  });

  elements.dropZone.addEventListener('click', () => {
    elements.fileInput.click();
  });

  // Demo data
  document.getElementById('load-demo').addEventListener('click', loadDemoData);

  // Theme toggle
  elements.themeToggle.addEventListener('click', toggleTheme);

  // Motion toggle
  elements.motionToggle.addEventListener('click', toggleMotion);

  // Sidebar toggle
  elements.sidebarToggle.addEventListener('click', () => {
    elements.sidebar.classList.toggle('collapsed');
  });

  // Navigation
  document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', () => {
      const panel = item.dataset.panel;
      switchPanel(panel);

      // Mobile: close sidebar
      if (window.innerWidth <= 768) {
        elements.sidebar.classList.remove('open');
      }
    });
  });

  // Export dropdown
  elements.exportBtn.addEventListener('click', () => {
    elements.exportBtn.parentElement.classList.toggle('active');
  });

  document.querySelectorAll('[data-export]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const type = e.target.dataset.export;
      exportData(type);
      elements.exportBtn.parentElement.classList.remove('active');
    });
  });

  // Close dropdown when clicking outside
  document.addEventListener('click', (e) => {
    if (!e.target.closest('.dropdown')) {
      document.querySelectorAll('.dropdown').forEach(d => d.classList.remove('active'));
    }
  });

  // Search listener
  elements.iocSearch.addEventListener('input', () => {
    filterIOCs();
  });

  // Impersonation panel controls
  const severityFilter = document.getElementById('impersonation-severity-filter');
  if (severityFilter) {
    severityFilter.addEventListener('change', (e) => {
      state.impersonation.severityFilter = e.target.value;
      renderImpersonation();
    });
  }

  // Brand filter modal
  const filterBtn = document.getElementById('btn-filter-brands');
  const filterModal = document.getElementById('brand-filter-modal');
  if (filterBtn && filterModal) {
    filterBtn.addEventListener('click', () => {
      filterModal.classList.remove('hidden');
    });

    // Close modal
    filterModal.querySelector('.close-modal')?.addEventListener('click', () => {
      filterModal.classList.add('hidden');
    });

    // Apply filter
    document.getElementById('btn-apply-brand-filter')?.addEventListener('click', () => {
      const checkboxes = filterModal.querySelectorAll('.brand-filter-item input[type="checkbox"]');
      const excluded = [];
      checkboxes.forEach(cb => {
        if (!cb.checked) {
          excluded.push(cb.value);
        }
      });
      state.impersonation.excludedBrands = excluded;
      filterModal.classList.add('hidden');
      renderImpersonation();
      showToast(`Excluded ${excluded.length} brands from view`, 'info');
    });

    // Reset filter
    document.getElementById('btn-reset-brand-filter')?.addEventListener('click', () => {
      state.impersonation.excludedBrands = [];
      const checkboxes = filterModal.querySelectorAll('.brand-filter-item input[type="checkbox"]');
      checkboxes.forEach(cb => cb.checked = true);
      renderImpersonation();
      showToast('Brand filters reset', 'success');
    });

    // Close on backdrop click
    filterModal.addEventListener('click', (e) => {
      if (e.target === filterModal) {
        filterModal.classList.add('hidden');
      }
    });
  }

  // DOCX export modal
  const btnGenDocx = document.getElementById('btn-generate-docx');
  if (btnGenDocx) {
    btnGenDocx.addEventListener('click', async () => {
      const summary = document.getElementById('docx-ai-summary').value;
      const autoOpen = document.getElementById('docx-auto-open').checked;
      document.getElementById('docx-export-modal').classList.add('hidden');
      
      showToast('Generating DOCX report...', 'info');
      try {
        const response = await fetch('/api/export/docx', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            artifacts: state.data.artifacts,
            ai_summary: summary,
            auto_open: autoOpen
          })
        });
        
        if (!response.ok) {
          const err = await response.json();
          throw new Error(err.detail || 'Failed to generate report');
        }
        
        // Handle file download
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        const filename = state.data.artifacts?.metadata?.input_filename || 'email';
        a.download = `Report_${filename.replace(/[^a-z0-9]/gi, '_')}.docx`;
        a.click();
        URL.revokeObjectURL(url);
        
        showToast('DOCX report generated successfully', 'success');
      } catch (err) {
        showToast(`Export error: ${err.message}`, 'error');
        console.error('Docx export failed:', err);
      }
    });
  }
  
  // JSON Report Export
  const btnGenJson = document.getElementById('btn-generate-json-report');
  if (btnGenJson) {
    btnGenJson.addEventListener('click', async () => {
      if (!state.data || !state.data.artifacts) {
        showToast('No analysis data available. Please analyze an email first.', 'error');
        return;
      }
      
      showToast('Generating JSON report...', 'info');
      try {
        const response = await fetch('/api/report/generate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            artifacts: state.data.artifacts,
            case_id: '',
            include_ai: true
          })
        });
        
        if (!response.ok) {
          const err = await response.json();
          throw new Error(err.detail || 'Failed to generate report');
        }
        
        const report = await response.json();
        
        // Download as JSON file
        const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        const filename = state.data.artifacts?.metadata?.input_filename || 'email';
        a.download = `Report_${filename.replace(/[^a-z0-9]/gi, '_')}.json`;
        a.click();
        URL.revokeObjectURL(url);
        
        showToast('JSON report generated successfully', 'success');
      } catch (err) {
        showToast(`Report error: ${err.message}`, 'error');
        console.error('JSON report failed:', err);
      }
    });
  }
  
  const btnCancelDocx = document.getElementById('btn-cancel-docx');
  if (btnCancelDocx) {
    btnCancelDocx.addEventListener('click', () => {
      document.getElementById('docx-export-modal').classList.add('hidden');
    });
  }
  
  const docxModal = document.getElementById('docx-export-modal');
  if (docxModal) {
    docxModal.querySelector('.close-modal')?.addEventListener('click', () => {
      docxModal.classList.add('hidden');
    });
    docxModal.addEventListener('click', (e) => {
      if (e.target === docxModal) {
        docxModal.classList.add('hidden');
      }
    });
  }

  // Visibility change (pause canvas)
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      stopCanvas();
    } else if (!state.reducedMotion) {
      startCanvas();
    }
  });
}

// File Handling
function handleFiles(files) {
  const fileList = Array.from(files);

  // Separate JSON and EML files
  const jsonFiles = fileList.filter(f => f.name.endsWith('.json'));
  const emlFiles = fileList.filter(f => f.name.toLowerCase().endsWith('.eml') || f.name.toLowerCase().endsWith('.msg'));

  // Handle EML files - upload to backend
  if (emlFiles.length > 0) {
    const file = emlFiles[0];
    uploadEML(file);
    return;
  }

  if (jsonFiles.length === 0) {
    showToast('Please select JSON files (artifacts.json, iocs.json, etc.)', 'error');
    return;
  }

  const loadedData = {};
  let loadedCount = 0;
  let hasError = false;

  showToast(`Loading ${jsonFiles.length} file(s)...`, 'info');

  jsonFiles.forEach(file => {
    const reader = new FileReader();

    reader.onload = (e) => {
      try {
        const data = JSON.parse(e.target.result);

        // Detect file type by structure
        if (data.metadata && (data.headers || data.iocs || data.routing)) {
          loadedData.artifacts = data;
        } else if (data.run_id && (data.domains !== undefined || Array.isArray(data))) {
          loadedData.iocs = data;
        } else if (data.parsed_results && Array.isArray(data.parsed_results)) {
          loadedData.auth_results = data;
        } else if (data.enrichments && Array.isArray(data.enrichments)) {
          loadedData.cti = data;
        }

        loadedCount++;

        if (loadedCount === jsonFiles.length && !hasError) {
          if (Object.keys(loadedData).length === 0) {
            showToast('No valid emltriage data found in files', 'error');
          } else {
            loadData(loadedData);
          }
        }
      } catch (err) {
        hasError = true;
        showToast(`Error parsing ${file.name}: ${err.message}`, 'error');
      }
    };

    reader.onerror = () => {
      hasError = true;
      showToast(`Error reading ${file.name}`, 'error');
    };

    reader.readAsText(file);
  });
}

async function uploadEML(file) {
  showToast(`Analyzing ${file.name}...`, 'info');
  elements.fileStatus.querySelector('.status-text').textContent = 'Analyzing...';

  const formData = new FormData();
  formData.append('file', file);

  try {
    const response = await fetch('/api/analyze', {
      method: 'POST',
      body: formData
    });

    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.detail || 'Analysis failed');
    }

    const data = await response.json();
    loadData(data);
    showToast('Analysis complete', 'success');

    // Background async CTI Enrichment
    fetchCTIAsync();

  } catch (err) {
    showToast(`Backend error: ${err.message}`, 'error');
    elements.fileStatus.querySelector('.status-text').textContent = 'Analysis failed';
    console.error('Upload error:', err);
  }
}

async function fetchCTIAsync() {
  if (!state.data || (!state.data.iocs && !state.data.artifacts?.iocs)) return;

  const rawIocs = state.data.iocs || state.data.artifacts.iocs;
  const iocList = Array.isArray(rawIocs) ? rawIocs : [
    ...(rawIocs.domains || []),
    ...(rawIocs.ips || []),
    ...(rawIocs.urls || [])
  ];

  if (!iocList || iocList.length === 0) return;

  if (!state.data.cti) {
    state.data.cti = { dns_records: {}, whois: {}, enrichments: [] };
  }

  const safe_infra = ['namprd', 'outlook.com', 'schemas.microsoft.com', 'w3.org', 'protection.outlook.com', '.png', '.jpg', '.jpeg', '.gif', '.svg'];
  const isSafe = (val) => typeof val === 'string' && safe_infra.some(s => val.toLowerCase().includes(s));
  
  const domains = [...new Set(iocList.filter(i => (i.type === 'domain' || i.type === 'domain_name') && !isSafe(i.value)).map(i => i.value))].slice(0, 5);
  const ips = [...new Set(iocList.filter(i => (i.type === 'ip' || i.type === 'ipv4' || i.type === 'ipv6')).map(i => i.value))].slice(0, 3);
  const urls = [...new Set(iocList.filter(i => i.type === 'url' && !isSafe(i.value)).map(i => i.value))].slice(0, 3);

  if (domains.length === 0 && ips.length === 0 && urls.length === 0) return;

  state.isPollingCTI = true;
  renderCTI();

  let vtPromise = Promise.resolve();
  
  // Fire FAST CTI (DNS/WHOIS)
  if (domains.length > 0) {
    fetch('/api/cti/fast', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domains })
    }).then(res => res.json()).then(fastData => {
      if (state.data && state.data.cti) {
        state.data.cti.dns_records = fastData.dns_records || {};
        state.data.cti.whois = fastData.whois || {};
      }
      renderCTI(); // Update view with fast data immediately!
    }).catch(e => console.error("Fast CTI fetch error:", e));
  }

  // Fire SLOW CTI (VirusTotal) completely concurrently
  const vtKey = state.apiKeys?.vt;
  if (vtKey) {
    vtPromise = fetch('/api/cti/vt', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ vt_api_key: vtKey, domains, ips, urls })
    }).then(res => res.json()).then(slowData => {
      if (state.data && state.data.cti) {
        state.data.cti.enrichments = slowData.enrichments || [];
      }
    }).catch(e => console.error("Slow CTI fetch error:", e));
  } else {
    state.isPollingCTI = false;
    renderCTI();
  }

  await vtPromise;
  state.isPollingCTI = false;
  renderCTI();
}

function loadDemoData() {
  loadData(DEMO_DATA);
  showToast('Demo data loaded', 'success');
}

function loadData(data) {
  state.data = data;
  elements.dropZone.style.display = 'none';
  elements.demoControls.style.display = 'none';
  elements.panels.classList.add('active');
  elements.fileStatus.classList.add('loaded');
  elements.fileStatus.querySelector('.status-text').textContent = 'File loaded';

  renderOverview();
  renderAuth();
  renderRouting();
  renderIOCs();
  renderAttachments();
  renderHeaders();
  renderBodies();
  renderImpersonation();
  renderCTI();

  if (data.iocs || data.artifacts?.iocs) {
    const iocs = data.iocs || data.artifacts.iocs;
    let count = 0;
    if (Array.isArray(iocs)) {
      count = iocs.length;
    } else {
      count = (iocs.domains?.length || 0) +
        (iocs.ips?.length || 0) +
        (iocs.urls?.length || 0);
    }
    elements.iocBadge.textContent = count;
    elements.iocBadge.classList.remove('hidden');
  }

  // Update impersonation badge
  if (data.artifacts?.impersonation?.length > 0) {
    elements.impersonationBadge.textContent = data.artifacts.impersonation.length;
    elements.impersonationBadge.classList.remove('hidden');
  }

  showToast('Analysis loaded successfully', 'success');
}

// Panel Rendering
function switchPanel(panelName) {
  state.activePanel = panelName;

  const mainContent = document.getElementById('main-content');
  const isDataLoaded = !!state.data;
  const isSettings = panelName === 'settings';

  if (isDataLoaded || isSettings) {
    elements.panels.classList.add('active');
    mainContent.classList.remove('welcome-state');
  } else {
    elements.panels.classList.remove('active');
    mainContent.classList.add('welcome-state');
  }

  // Update navigation items
  document.querySelectorAll('.nav-item').forEach(item => {
    item.classList.toggle('active', item.dataset.panel === panelName);
    item.setAttribute('aria-current', item.dataset.panel === panelName ? 'page' : 'false');
  });

  // Populate DOCX summary when report-builder opens
  if (panelName === 'report-builder') {
    const summaryArea = document.getElementById('docx-ai-summary-panel');
    const currentSummaryEl = document.querySelector('#ai-summary-content');
    
    // Auto-populate if it's empty or hasn't been modified yet, and AI summary exists
    if (!summaryArea.dataset.edited && currentSummaryEl && currentSummaryEl.textContent && !currentSummaryEl.textContent.includes('Click "Generate Summary"')) {
      summaryArea.value = currentSummaryEl.textContent.trim();
      summaryArea.dataset.edited = "true"; // Mark as populated
    }
  }

  // Update panel elements
  document.querySelectorAll('.panel').forEach(panel => {
    const isActive = panel.id === `panel-${panelName}`;
    panel.classList.toggle('active', isActive);
    panel.hidden = !isActive;
  });
}

function renderOverview() {
  const data = state.data.artifacts;
  if (!data) return;

  // Risk score
  if (data.risk) {
    elements.riskScore.textContent = data.risk.score;
    elements.riskSeverity.textContent = data.risk.severity;
    elements.riskSeverity.className = `severity-badge ${data.risk.severity}`;
    elements.riskBar.style.width = `${data.risk.score}%`;

    // Risk reasons
    elements.riskReasons.innerHTML = data.risk.reasons.map(r => `
      <div class="reason-item">
        <span class="reason-weight">+${r.weight}</span>
        <div>
          <div>${r.description}</div>
          <small style="color: var(--text-secondary);">${r.code}</small>
        </div>
      </div>
    `).join('');
  }

  // Run ID
  const runIdEl = document.getElementById('run-id');
  if (runIdEl && data.metadata) {
    runIdEl.textContent = data.metadata.run_id;
  }

  // Auth chips
  const authResults = state.data.auth_results || data.authentication;
  if (authResults?.results || authResults?.parsed_results?.[0]?.results) {
    const auth = authResults.results || authResults.parsed_results[0].results;
    const spf = auth.find(r => r.mechanism === 'spf');
    const dkim = auth.find(r => r.mechanism === 'dkim');
    const dmarc = auth.find(r => r.mechanism === 'dmarc');

    const getStatus = (result) => {
      if (!result) return 'unknown';
      if (result.result === 'pass') return 'pass';
      if (result.result === 'fail') return 'fail';
      return 'softfail';
    };

    const chipsEl = document.getElementById('auth-chips');
    if (chipsEl) {
      chipsEl.innerHTML = `
          <div class="auth-chip ${getStatus(spf)}" data-auth="spf">
            <span class="label">SPF</span>
            <span class="status">${spf?.result || 'unknown'}</span>
          </div>
          <div class="auth-chip ${getStatus(dkim)}" data-auth="dkim">
            <span class="label">DKIM</span>
            <span class="status">${dkim?.result || 'unknown'}</span>
          </div>
          <div class="auth-chip ${getStatus(dmarc)}" data-auth="dmarc">
            <span class="label">DMARC</span>
            <span class="status">${dmarc?.result || 'unknown'}</span>
          </div>
        `;
    }
  }

  // Stats
  document.getElementById('stat-urls').textContent = data.urls?.length || 0;

  let domainCount = 0;
  let ipCount = 0;
  if (Array.isArray(data.iocs)) {
    domainCount = data.iocs.filter(i => i.type === 'domain').length;
    ipCount = data.iocs.filter(i => i.type?.includes('ip')).length;
  } else if (state.data.iocs) {
    domainCount = state.data.iocs.domains?.length || 0;
    ipCount = state.data.iocs.ips?.length || 0;
  }

  document.getElementById('stat-domains').textContent = domainCount;
  document.getElementById('stat-ips').textContent = ipCount;
  document.getElementById('stat-attachments').textContent = data.attachments?.length || 0;
  document.getElementById('stat-hops').textContent = data.routing?.length || 0;

  // Top indicators
  const allIocs = [];
  if (Array.isArray(data.iocs)) allIocs.push(...data.iocs);
  if (state.data.iocs) {
    if (state.data.iocs.urls) allIocs.push(...state.data.iocs.urls);
    if (state.data.iocs.domains) allIocs.push(...state.data.iocs.domains);
    if (state.data.iocs.ips) allIocs.push(...state.data.iocs.ips);
  }

  // Deduplicate and filter noise
  const uniqueSuspicious = [];
  const seenVals = new Set();

  for (const ioc of allIocs) {
    if (!ioc || !ioc.value) continue;
    const val = ioc.value.toLowerCase();

    // Skip if noise or already seen
    if (seenVals.has(val) || isInfrastructureNoise(val)) continue;

    seenVals.add(val);
    uniqueSuspicious.push(ioc);
  }

  const suspicious = uniqueSuspicious
    .sort((a, b) => {
      // Prioritize CTI malicious scores if available
      const scoreA = a.malicious_score || (a.type?.includes('malicious') ? 100 : 0);
      const scoreB = b.malicious_score || (b.type?.includes('malicious') ? 100 : 0);
      if (scoreB !== scoreA) return scoreB - scoreA;

      // Secondary: prioritize bodies over headers
      const sourceWeight = (s) => (s?.includes('body') ? 2 : s?.includes('url') ? 1 : 0);
      return sourceWeight(b.source) - sourceWeight(a.source);
    })
    .slice(0, 10);

  document.getElementById('top-indicators').innerHTML = suspicious.map(ioc => `
    <div class="indicator-item">
      <span class="indicator-value" title="${ioc.source || ''}">${ioc.value}</span>
      <div class="indicator-tags">
        <span class="tag ${ioc.malicious_score > 0 ? 'malicious' : 'suspicious'}">${ioc.type}</span>
      </div>
    </div>
  `).join('') || '<p class="empty">No high-confidence indicators found</p>';
}

function renderAuth() {
  const container = document.getElementById('auth-content');
  const data = state.data.auth_results || state.data.artifacts?.authentication;

  if (!data) {
    container.innerHTML = '<p class="empty">Load artifacts to view authentication results</p>';
    return;
  }

  container.innerHTML = `
    <div class="card">
      <h3>Authentication Results</h3>
      <table>
        <thead>
          <tr>
            <th>Domain</th>
            <th>SPF</th>
            <th>DKIM</th>
            <th>DMARC</th>
          </tr>
        </thead>
        <tbody>
          ${(data.parsed_results || []).map(r => `
            <tr>
              <td>${r.domain}</td>
              <td class="${r.results.find(x => x.mechanism === 'spf')?.result === 'pass' ? 'good' : 'danger'}">
                ${r.results.find(x => x.mechanism === 'spf')?.result || 'none'}
              </td>
              <td class="${r.results.find(x => x.mechanism === 'dkim')?.result === 'pass' ? 'good' : 'danger'}">
                ${r.results.find(x => x.mechanism === 'dkim')?.result || 'none'}
              </td>
              <td class="${r.results.find(x => x.mechanism === 'dmarc')?.result === 'pass' ? 'good' : 'danger'}">
                ${r.results.find(x => x.mechanism === 'dmarc')?.result || 'none'}
              </td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
    
    <div class="card" style="margin-top: var(--space-lg)">
      <h3>DKIM Verification</h3>
      <p>${data.dkim_verified === true ? '✅ Signature cryptographically verified' :
      data.dkim_verified === false ? '❌ Signature verification failed' :
        '⚠️ Verification not performed'}</p>
    </div>
  `;
}

function renderIOCs() {
  const iocsData = state.data.iocs || state.data.artifacts?.iocs || [];
  const container = document.getElementById('ioc-tables');

  if (!iocsData || (Array.isArray(iocsData) && iocsData.length === 0)) {
    container.innerHTML = '<p class="empty">No IOCs found</p>';
    return;
  }

  // Group by type
  const byType = {
    all: [],
    urls: [],
    domains: [],
    ips: [],
    hashes: [],
    infrastructure: []
  };

  if (Array.isArray(iocsData)) {
    iocsData.forEach(ioc => {
      if (isInfrastructureNoise(ioc)) return;
      byType.all.push(ioc);
      const type = ioc.type || 'unknown';
      if (type === 'url') byType.urls.push(ioc);
      else if (type === 'domain') byType.domains.push(ioc);
      else if (type.includes('ip')) byType.ips.push(ioc);
      else if (type.includes('hash')) byType.hashes.push(ioc);
      else byType.infrastructure.push(ioc);
    });
  } else {
    const list = [
      ...(iocsData.urls || []),
      ...(iocsData.domains || []),
      ...(iocsData.ips || []),
      ...(iocsData.hashes || []),
      ...(iocsData.infrastructure || [])
    ];
    list.forEach(ioc => {
      if (isInfrastructureNoise(ioc)) return;
      byType.all.push(ioc);
    });
    byType.urls = (iocsData.urls || []).filter(i => !isInfrastructureNoise(i));
    byType.domains = (iocsData.domains || []).filter(i => !isInfrastructureNoise(i));
    byType.ips = (iocsData.ips || []).filter(i => !isInfrastructureNoise(i));
    byType.hashes = (iocsData.hashes || []).filter(i => !isInfrastructureNoise(i));
    byType.infrastructure = (iocsData.infrastructure || []).filter(i => !isInfrastructureNoise(i));
  }

  const renderTable = (items) => {
    if (items.length === 0) return '<p class="empty" style="padding: 20px; text-align: center; color: var(--text-secondary)">No items (noise filtered)</p>';

    return `
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Value</th>
              <th>Type</th>
              <th>Source</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            ${items.map(ioc => `
              <tr>
                <td><code style="word-break: break-all;">${ioc.value}</code></td>
                <td>${ioc.type}</td>
                <td>${ioc.source || 'unknown'}</td>
                <td>
                  <button class="btn" style="padding: 4px 8px; font-size: 11px;" onclick="copyToClipboard('${ioc.value}')">Copy</button>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  };

  container.innerHTML = `
    <div class="tab-panel active" data-tab="all">${renderTable(byType.all)}</div>
    <div class="tab-panel" data-tab="urls">${renderTable(byType.urls)}</div>
    <div class="tab-panel" data-tab="domains">${renderTable(byType.domains)}</div>
    <div class="tab-panel" data-tab="ips">${renderTable(byType.ips)}</div>
    <div class="tab-panel" data-tab="hashes">${renderTable(byType.hashes)}</div>
    <div class="tab-panel" data-tab="infrastructure">${renderTable(byType.infrastructure)}</div>
  `;

  // Re-attach tab events for IOC panel
  const iocPanel = document.getElementById('panel-iocs');
  if (iocPanel) {
    iocPanel.querySelectorAll('.tab-btn').forEach(btn => {
      btn.onclick = () => {
        const tab = btn.dataset.tab;
        iocPanel.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
        iocPanel.querySelectorAll('.tab-panel').forEach(p => p.classList.toggle('active', p.dataset.tab === tab));
        filterIOCs();
      };
    });
  }
}

function renderAttachments() {
  const container = document.getElementById('attachments-content');
  const data = state.data.artifacts?.attachments || [];

  if (data.length === 0) {
    container.innerHTML = '<p class="empty">No attachments found</p>';
    return;
  }

  container.innerHTML = `
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>Filename</th>
            <th>Type</th>
            <th>Size</th>
            <th>Risk</th>
          </tr>
        </thead>
        <tbody>
          ${data.map(att => `
            <tr>
              <td style="word-break: break-all;">${att.filename_decoded || att.filename_raw}</td>
              <td>${att.content_type}</td>
              <td>${formatBytes(att.size)}</td>
              <td>
                ${att.is_risky ?
      `<span class="tag malicious">${att.risk_flags?.join(', ') || 'risky'}</span>` :
      '<span class="tag unknown">safe</span>'}
              </td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  `;
}

function renderHeaders() {
  const container = document.getElementById('headers-content');
  const data = state.data.artifacts?.headers || [];

  if (data.length === 0) {
    container.innerHTML = '<p class="empty">No headers found</p>';
    return;
  }

  const importantHeaders = ['from', 'to', 'subject', 'date', 'message-id', 'authentication-results', 'received'];

  container.innerHTML = `
    <div class="card">
      <h3>Important Headers</h3>
      <div class="headers-list">
        ${data.filter(h => importantHeaders.includes(h.name.toLowerCase())).map(h => `
          <div class="header-item" style="margin-bottom: var(--space-md); padding: var(--space-md); background: var(--panel-solid); border-radius: 6px; border: 1px solid var(--border)">
            <strong style="color: var(--accent);">${h.name}:</strong>
            <div style="margin-top: var(--space-xs); font-family: var(--font-mono); font-size: 0.875rem; word-break: break-all;">
              ${h.decoded_value || h.raw_value}
            </div>
          </div>
        `).join('')}
      </div>
    </div>
    
    <div class="card" style="margin-top: var(--space-lg)">
      <h3>All Headers (Raw)</h3>
      <div id="raw-headers-box" style="background: var(--panel-solid); padding: var(--space-md); border-radius: 6px; overflow-x: auto; font-size: 0.75rem; max-height: 300px; white-space: pre-wrap; font-family: var(--font-mono); border: 1px solid var(--border)">${data.map(h => `${h.name}: ${h.raw_value}`).join('\n')}</div>
      <button class="btn" style="margin-top: var(--space-md);" onclick="copyToClipboard(document.getElementById('raw-headers-box').textContent)">Copy Raw Headers</button>
    </div>
  `;
}

// Body rendering shifted to professional sandboxed implementation

function renderCTI() {
  const container = document.getElementById('cti-content');
  const data = state.data.cti;

  if (!data && state.isPollingCTI) {
    container.innerHTML = `
      <div class="card" style="text-align: center; padding: var(--space-xl);">
        <div class="spinner" style="margin: 0 auto 15px; border-color: var(--primary); border-width: 3px; border-top-color: transparent; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite;"></div>
        <h3>Polling Intelligence...</h3>
        <p class="text-muted" style="margin-top: 10px;">Enriching indicators with native Dig, WHOIS, and VirusTotal.</p>
      </div>
      <style>@keyframes spin { 100% { transform: rotate(360deg); } }</style>
    `;
    return;
  }

  if (!data) {
    container.innerHTML = `
      <div class="card">
        <h3>CTI Enrichment</h3>
        <p class="empty">No CTI data loaded. To enable online enrichment, configure API keys in Settings and re-analyze.</p>
      </div>
    `;
    return;
  }

  const dnsRecords = data.dns_records || {};
  const whoisData = data.whois || {};

  container.innerHTML = `
    <div class="card">
      <h3>Context Details (DNS / WHOIS)</h3>
      <div style="display: flex; flex-direction: column; gap: 15px; margin-top: 10px;">
        ${Object.keys(whoisData).map(domain => {
          const w = whoisData[domain];
          const dns = dnsRecords[domain] || "No DNS Record";
          if (w.error) return '<div class="detail-row"><strong>' + domain + '</strong>: Error ' + w.error + '</div>';
          return `
            <div class="detail-row" style="background: var(--bg-card); padding: 10px; border-radius: 4px; border: 1px solid var(--border-color);">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 5px;">
                <strong style="font-size: 1.1em; color: var(--primary);">${domain}</strong>
                <span class="severity-badge ${w.assessment.includes('Suspicious') ? 'critical' : 'info'}">${w.assessment}</span>
              </div>
              <div style="font-size: 0.9em; display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                <div><strong>DNS Resolution:</strong> <code>${escapeHtml(dns)}</code></div>
                <div><strong>Registrar:</strong> ${escapeHtml(w.registrar)}</div>
                <div><strong>Creation:</strong> ${escapeHtml(w.creation)}</div>
              </div>
              <details style="margin-top: 10px;">
                <summary style="cursor: pointer; font-size: 0.8em; color: var(--text-secondary);">View Raw WHOIS</summary>
                <pre style="font-size: 0.8em; max-height: 200px; overflow-y: auto; margin-top: 5px; padding: 10px; background: #1e1e1e; color: #d4d4d4; border-radius: 4px;">${escapeHtml(w.raw || '')}</pre>
              </details>
            </div>
          `;
        }).join('')}
        ${Object.keys(whoisData).length === 0 && !state.isPollingCTI ? '<p class="text-muted">No external domains identified for WHOIS/DNS lookup.</p>' : ''}
        ${Object.keys(whoisData).length === 0 && state.isPollingCTI ? '<div class="spinner" style="border-width: 2px; width: 20px; height: 20px; border-color: var(--primary); border-top-color: transparent; border-radius: 50%; animation: spin 1s linear infinite; margin: 10px auto;"></div>' : ''}
      </div>
    </div>
    
    <div class="card" style="margin-top: var(--space-lg)">
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <h3>Third-Party Intelligence (VirusTotal)</h3>
        ${state.isPollingCTI ? '<div class="spinner" style="border-width: 2px; border-color: var(--primary); border-top-color: transparent; border-radius: 50%; width: 20px; height: 20px; animation: spin 1s linear infinite;"></div>' : ''}
      </div>
      ${(!state.isPollingCTI && (!data.enrichments || data.enrichments.length === 0)) ? `
        <p class="text-muted" style="margin-top:10px;">No VirusTotal enrichment data. (Check API keys or quota).</p>
      ` : `
      <div class="table-container" style="margin-top: 10px;">
        <table>
          <thead>
            <tr>
              <th>IOC</th>
              <th>Provider</th>
              <th>Score</th>
            </tr>
          </thead>
          <tbody>
            ${(data.enrichments || []).map(e => `
              <tr>
                <td><code>${e.ioc}</code></td>
                <td>${e.provider}</td>
                <td class="${e.malicious_score > 70 ? 'danger' : e.malicious_score > 30 ? 'warn' : 'good'}">
                  ${e.malicious_score || 0}
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
      `}
    </div>
  `;
}

// Brand Impersonation Detection Rendering
function renderImpersonation() {
  const container = document.getElementById('impersonation-content');
  const summaryTotal = document.getElementById('impersonation-total-count');
  const summaryCritical = document.getElementById('impersonation-critical-count');
  const summaryHigh = document.getElementById('impersonation-high-count');
  const summaryBrands = document.getElementById('impersonation-brands-detected');
  
  // Get findings from data
  let findings = [];
  if (state.data?.artifacts?.impersonation) {
    findings = state.data.artifacts.impersonation;
  } else if (state.data?.impersonation) {
    findings = state.data.impersonation;
  }
  
  // Apply brand filter
  if (state.impersonation.excludedBrands.length > 0) {
    findings = findings.filter(f => !state.impersonation.excludedBrands.includes(f.brand_candidate));
  }
  
  // Apply severity filter
  const severityFilter = state.impersonation.severityFilter;
  if (severityFilter !== 'all') {
    const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
    const filterLevel = severityOrder[severityFilter];
    findings = findings.filter(f => severityOrder[f.severity] >= filterLevel);
  }
  
  // Update summary stats
  if (summaryTotal) summaryTotal.textContent = findings.length;
  if (summaryCritical) summaryCritical.textContent = findings.filter(f => f.severity === 'critical').length;
  if (summaryHigh) summaryHigh.textContent = findings.filter(f => f.severity === 'high').length;
  
  const uniqueBrands = [...new Set(findings.map(f => f.brand_candidate))];
  if (summaryBrands) summaryBrands.textContent = uniqueBrands.length;
  
  // Store filtered findings in state
  state.impersonation.findings = findings;
  
  // Update brand filter list
  updateBrandFilterList(findings);
  
  if (findings.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <svg viewBox="0 0 24 24" width="48" height="48" style="opacity: 0.3; margin-bottom: 16px;">
          <path fill="currentColor" d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>
        </svg>
        <p>No brand impersonation detected</p>
        <p class="hint">Load an email with suspicious domains to see findings</p>
      </div>
    `;
    return;
  }
  
  // Render findings
  container.innerHTML = findings.map((finding, index) => {
    const severityClass = finding.severity;
    const techniqueClass = finding.technique;
    const scoreClass = finding.score >= 0.85 ? 'critical' : finding.score >= 0.75 ? 'high' : 'medium';
    
    // Format technique for display
    const techniqueDisplay = finding.technique
      .replace(/_/g, ' ')
      .replace(/\b\w/g, l => l.toUpperCase());
    
    // Get icon for technique
    const techniqueIcons = {
      typosquat: '📝',
      homoglyph: '🔤',
      keyword_match: '🔑',
      punycode: '🌐',
      display_name: '👤',
      reply_to_mismatch: '↩️',
      subdomain_abuse: '📁'
    };
    const icon = techniqueIcons[finding.technique] || '⚠️';
    
    return `
      <div class="impersonation-finding ${severityClass}" data-index="${index}" data-brand="${escapeHtml(finding.brand_candidate)}">
        <div class="finding-header">
          <div class="finding-brand">
            <div class="brand-icon">${icon}</div>
            <div>
              <div class="brand-name">${escapeHtml(finding.brand_candidate)} Impersonation</div>
              <span class="brand-target">Target: ${escapeHtml(finding.detected_domain)}</span>
            </div>
          </div>
          <div class="finding-meta">
            <span class="finding-score ${scoreClass}">${(finding.score * 100).toFixed(0)}%</span>
            <span class="finding-technique ${techniqueClass}">${techniqueDisplay}</span>
            <span class="severity-badge ${severityClass}">${finding.severity}</span>
          </div>
        </div>
        
        <div class="finding-body">
          <div class="finding-domain">${escapeHtml(finding.detected_domain)}</div>
          <div class="finding-explanation">${escapeHtml(finding.explanation)}</div>
        </div>
        
        <details class="finding-evidence">
          <summary>Evidence & Technical Details</summary>
          <div class="evidence-content">
            <p><strong>Algorithm:</strong> ${finding.algorithm}</p>
            <p><strong>Query:</strong> ${escapeHtml(finding.query)}</p>
            <p><strong>Source:</strong> ${finding.source}</p>
            <p><strong>Timestamp:</strong> ${finding.timestamp}</p>
            <p><strong>Confidence:</strong> ${(finding.confidence * 100).toFixed(0)}%</p>
            <p><strong>Detected in:</strong></p>
            <ul class="evidence-list">
              ${finding.evidence_fields.map(field => `<li>${escapeHtml(field)}</li>`).join('')}
            </ul>
            ${finding.normalized_tokens?.length > 0 ? `
              <p><strong>Normalized Tokens:</strong></p>
              <code>${finding.normalized_tokens.join(', ')}</code>
            ` : ''}
          </div>
        </details>
      </div>
    `;
  }).join('');
}

function updateBrandFilterList(findings) {
  const list = document.getElementById('brand-filter-list');
  if (!list) return;
  
  // Get unique brands and their counts
  const brandCounts = {};
  findings.forEach(f => {
    brandCounts[f.brand_candidate] = (brandCounts[f.brand_candidate] || 0) + 1;
  });
  
  const brands = Object.keys(brandCounts).sort();
  
  if (brands.length === 0) {
    list.innerHTML = '<p class="hint">No brands detected</p>';
    return;
  }
  
  list.innerHTML = brands.map(brand => {
    const isChecked = !state.impersonation.excludedBrands.includes(brand);
    const count = brandCounts[brand];
    return `
      <div class="brand-filter-item">
        <input type="checkbox" id="brand-${brand}" value="${escapeHtml(brand)}" ${isChecked ? 'checked' : ''}>
        <label for="brand-${brand}">${escapeHtml(brand)}</label>
        <span class="brand-count">${count}</span>
      </div>
    `;
  }).join('');
}

// Utility Functions
function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => {
    showToast('Copied to clipboard', 'success');
  }).catch(() => {
    showToast('Failed to copy', 'error');
  });
}

function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

function checkApiKeys() {
  const { vt, abuse, openai } = state.apiKeys;
  if (elements.apiVT) elements.apiVT.className = `api-indicator ${vt ? 'online' : 'offline'}`;
  if (elements.apiAbuse) elements.apiAbuse.className = `api-indicator ${abuse ? 'online' : 'offline'}`;
  if (elements.apiOpenAI) elements.apiOpenAI.className = `api-indicator ${openai ? 'online' : 'offline'}`;
  return !!(vt || abuse || openai);
}

function filterIOCs() {
  const query = (elements.iocSearch?.value || '').toLowerCase();
  const activeTabPanel = document.querySelector('.tab-panel.active');
  if (!activeTabPanel) return;
  const rows = activeTabPanel.querySelectorAll('tbody tr');
  rows.forEach(row => {
    const text = row.textContent.toLowerCase();
    row.style.display = text.includes(query) ? '' : 'none';
  });
}

function isInfrastructureNoise(ioc) {
  const value = typeof ioc === 'string' ? ioc : ioc.value;
  const type = typeof ioc === 'string' ? '' : (ioc.type || '');
  if (!value) return true;

  const lower = value.toLowerCase();

  const noisePatterns = [
    'outlook.com', 'microsoft.com', 'office.com', 'live.com', 'bing.com',
    'google.com', 'googleapis.com', 'gstatic.com', 'gmail.com',
    'akamaized.net', 'azure.com', 'amazonaws.com', 'cloudfront.net',
    'apple.com', 'icloud.com', 'fonacot.gob.mx', 'seg-gto.gob.mx', // Common domains in user screenshot
    'header.from', 'header.to', 'header.subject', 'header.authentication-results', // Source labels
    'body_plain' // Source label
  ];

  if (noisePatterns.some(p => lower === p || lower.endsWith('.' + p))) return true;

  // Structural validation for domains (catch things like p.msonormal or image001.png)
  if (type === 'domain' || (!type && lower.includes('.') && !lower.match(/^[0-9\.]+$/))) {
    // Catch extracted HTML/CSS artifacts incorrectly tagged as domains
    const invalidExts = ['.png', '.jpg', '.jpeg', '.gif', '.css', '.js', '.svg', '.xml', '.json', '.html', '.htm', '.txt'];
    if (invalidExts.some(ext => lower.endsWith(ext))) return true;

    const cssPrefixes = ['p.', 'div.', 'span.', 'td.', 'tr.', 'table.', 'li.', 'ul.', 'ol.', 'a.', 'h1.', 'h2.', 'h3.', 'font.', 'body.', 'image'];
    if (cssPrefixes.some(prefix => lower.startsWith(prefix))) return true;

    // Must have a valid TLD structure
    const tldMatch = lower.match(/\.([a-z]{2,})$/);
    if (!tldMatch) return true;
  }

  return false;
}

function renderRouting() {
  const container = document.getElementById('routing-graph');
  const routingData = state.data.artifacts?.routing || [];

  container.innerHTML = '';

  if (routingData.length === 0) {
    container.innerHTML = '<div style="text-align: center; padding-top: 50px; color: var(--text-secondary);">No routing data found</div>';
    return;
  }

  // Create tooltip if it doesn't exist
  let tooltip = d3.select('body').select('.d3-tooltip');
  if (tooltip.empty()) {
    tooltip = d3.select('body').append('div').attr('class', 'd3-tooltip');
  }

  // Add Legend
  const legend = d3.select(container).append('div').attr('class', 'routing-legend');
  legend.html(`
    <div class="legend-item"><div class="legend-color" style="background:var(--accent)"></div><span>Standard Hop</span></div>
    <div class="legend-item"><div class="legend-color" style="background:var(--danger)"></div><span>Suspicious Delay / Anomaly</span></div>
    <div class="legend-item"><span style="color:var(--text-secondary)">〰️</span><span>Logical Flow</span></div>
    <div class="legend-item"><span style="color:var(--text-secondary)">╌</span><span>Significant Delay (>5m)</span></div>
  `);

  // Extract human names from headers
  const getHeaderValue = (name) => {
    const h = state.data.artifacts?.headers?.find(x => x.name.toLowerCase() === name.toLowerCase());
    return h ? (h.decoded_value || h.raw_value) : null;
  };

  const fromVal = getHeaderValue('from');
  const toVal = getHeaderValue('to');

  // Helper to extract display name or email
  const parseName = (val) => {
    if (!val) return null;
    const match = val.match(/^([^<]+)/);
    return match ? match[1].trim().replace(/^"|"$/g, '') : val;
  };

  const senderName = parseName(fromVal);
  const recipientName = parseName(toVal);

  const processedHops = routingData.map((hop, i) => {
    const time = hop.timestamp ? new Date(hop.timestamp).getTime() : null;
    let delay = 0;
    if (i > 0 && time && routingData[i - 1].timestamp) {
      const prevTime = new Date(routingData[i - 1].timestamp).getTime();
      delay = Math.max(0, (time - prevTime) / 1000); // seconds
    }
    return { ...hop, delay, id: i };
  });

  // Calculate dynamic width based on hops to prevent squashing
  const minHopWidth = 180;
  const calculatedWidth = Math.max(container.clientWidth || 800, (processedHops.length + 1) * minHopWidth);
  const height = 450;
  const nodeRadius = 28;
  const padding = 120;

  if (typeof d3 === 'undefined') {
    container.innerHTML = '<div style="text-align: center; padding-top: 50px; color: var(--danger);">D3.js failed to load.</div>';
    return;
  }

  const svg = d3.select('#routing-graph')
    .append('svg')
    .attr('width', calculatedWidth)
    .attr('height', height)
    .attr('viewBox', `0 0 ${calculatedWidth} ${height}`)
    .style('overflow', 'visible');

  // Definitions
  const defs = svg.append('defs');

  // Marker for arrow
  defs.append('marker')
    .attr('id', 'arrowhead')
    .attr('viewBox', '0 -5 10 10')
    .attr('refX', nodeRadius + 10)
    .attr('refY', 0)
    .attr('orient', 'auto')
    .attr('markerWidth', 9)
    .attr('markerHeight', 9)
    .append('path')
    .attr('d', 'M0,-5L10,0L0,5')
    .attr('fill', 'var(--text-secondary)');

  // Grad
  const grad = defs.append('linearGradient').attr('id', 'link-grad-v3').attr('gradientUnits', 'userSpaceOnUse');
  grad.append('stop').attr('offset', '0%').attr('stop-color', 'var(--accent)').attr('stop-opacity', 0.2);
  grad.append('stop').attr('offset', '100%').attr('stop-color', 'var(--accent)').attr('stop-opacity', 0.8);

  const xScale = d3.scaleLinear()
    .domain([0, Math.max(1, processedHops.length - 1)])
    .range([padding, calculatedWidth - padding]);

  const centerY = height / 2;

  const linkData = processedHops.slice(0, -1).map((d, i) => ({
    source: { x: i, y: centerY },
    target: { x: i + 1, y: centerY },
    id: i,
    isSuspicious: processedHops[i + 1].delay > 300
  }));

  // Draw Links (Bezier)
  svg.selectAll('.link')
    .data(linkData)
    .enter()
    .append('path')
    .attr('d', (d, i) => {
      const s = { x: xScale(d.source.x), y: d.source.y };
      const t = { x: xScale(d.target.x), y: d.target.y };
      const midX = (s.x + t.x) / 2;
      const curve = (i % 2 === 0 ? 30 : -30);
      return `M${s.x},${s.y} Q${midX},${centerY + curve} ${t.x},${t.y}`;
    })
    .attr('fill', 'none')
    .attr('stroke', d => d.isSuspicious ? 'var(--danger)' : 'url(#link-grad-v3)')
    .attr('stroke-width', 3)
    .attr('marker-end', 'url(#arrowhead)')
    .style('stroke-dasharray', d => d.isSuspicious ? '8,4' : 'none');

  // Link Labels
  svg.selectAll('.delay-text')
    .data(linkData)
    .enter()
    .append('text')
    .attr('x', d => (xScale(d.source.x) + xScale(d.target.x)) / 2)
    .attr('y', (d, i) => centerY + (i % 2 === 0 ? 35 : -35))
    .attr('text-anchor', 'middle')
    .attr('fill', d => d.isSuspicious ? 'var(--danger)' : 'var(--text-secondary)')
    .attr('font-size', '11px')
    .attr('font-weight', '600')
    .text(d => {
      const delay = processedHops[d.id + 1].delay;
      if (delay < 1) return '';
      if (delay > 3600) return Math.round(delay / 3600) + 'h delay';
      if (delay > 60) return Math.round(delay / 60) + 'm delay';
      return Math.round(delay) + 's delay';
    });

  // Icons Helper
  const getIcon = (i, total) => {
    if (i === 0) return '💻'; // Laptop (Sender)
    if (i === total - 1) return '📥'; // Inbox (Recipient)
    return '☁️'; // Cloud (Relay)
  };

  // Nodes
  const nodeGroups = svg.selectAll('.node')
    .data(processedHops)
    .enter()
    .append('g')
    .attr('transform', (d, i) => `translate(${xScale(i)}, ${centerY})`)
    .style('cursor', 'pointer')
    .on('mouseover', function (event, d) {
      d3.select(this).select('circle').attr('stroke-width', 4).attr('r', nodeRadius + 4);
      tooltip.transition().duration(200).style('opacity', 1);
      tooltip.html(`
        <strong>Hop ${d.id + 1}: ${d.id === 0 ? 'Origin' : d.id === processedHops.length - 1 ? 'Destination' : 'Relay'}</strong>
        <div>From: ${d.from_host || 'N/A'}</div>
        <div>By: ${d.by_host || 'N/A'}</div>
        <div>IP: ${d.ip || d.by_ip || 'N/A'}</div>
        <div>Time: ${d.timestamp ? new Date(d.timestamp).toLocaleString() : 'Unknown'}</div>
        ${d.delay > 0 ? `<div>Delay: ${Math.round(d.delay)}s</div>` : ''}
      `).style('left', (event.pageX + 15) + 'px').style('top', (event.pageY - 28) + 'px');
    })
    .on('mousemove', (event) => {
      tooltip.style('left', (event.pageX + 15) + 'px').style('top', (event.pageY - 28) + 'px');
    })
    .on('mouseout', function () {
      d3.select(this).select('circle').attr('stroke-width', 2).attr('r', nodeRadius);
      tooltip.transition().duration(200).style('opacity', 0);
    })
    .on('click', (event, d) => window.showHopInspector(d.id));

  nodeGroups.append('circle')
    .attr('r', (d, i) => (i === 0 || i === processedHops.length - 1) ? nodeRadius + 4 : nodeRadius)
    .attr('fill', 'var(--panel-solid)')
    .attr('stroke', d => d.anomalies?.length ? 'var(--danger)' : 'var(--accent)')
    .attr('stroke-width', 2);

  nodeGroups.append('text')
    .attr('y', -4)
    .attr('text-anchor', 'middle')
    .attr('font-size', '16px')
    .text((d, i) => getIcon(i, processedHops.length));

  nodeGroups.append('text')
    .attr('y', 14)
    .attr('text-anchor', 'middle')
    .attr('fill', 'var(--text)')
    .attr('font-weight', 'bold')
    .attr('font-size', '11px')
    .text(d => d.id + 1);

  // POLISHED LABELS
  const truncate = (str, len) => str.length > len ? str.substring(0, len - 3) + '...' : str;

  // Top Labels (Straight for endpoints, tilted/hidden for relays)
  nodeGroups.append('text')
    .attr('class', 'graph-label')
    .attr('x', 0)
    .attr('y', (d, i) => (i === 0 || i === processedHops.length - 1) ? -nodeRadius - 25 : -nodeRadius - 15)
    .attr('text-anchor', (d, i) => i === 0 ? 'end' : (i === processedHops.length - 1 ? 'start' : 'start'))
    .attr('fill', (d, i) => (i === 0 || i === processedHops.length - 1) ? 'var(--accent)' : 'var(--text)')
    .attr('font-size', (d, i) => (i === 0 || i === processedHops.length - 1) ? '12px' : '10px')
    .attr('font-weight', (d, i) => (i === 0 || i === processedHops.length - 1) ? 'bold' : 'normal')
    .attr('transform', (d, i) => {
      if (i === 0 || i === processedHops.length - 1) return ''; // Straight 
      return `rotate(-35, 5, ${-nodeRadius - 15})`; // Tilted for middle
    })
    .text((d, i) => {
      // Big endpoints
      if (i === 0) return senderName ? truncate(senderName, 40) : truncate(d.from_host || 'Origin', 35);
      if (i === processedHops.length - 1) return recipientName ? truncate(recipientName, 40) : truncate(d.from_host || 'Destination', 35);

      // Middle relays just say 'Hop X' to save space (details in tooltip)
      return `Hop ${i + 1}`;
    });

  // Bottom Labels (Only for endpoints, straight)
  nodeGroups.append('text')
    .attr('class', 'graph-label')
    .attr('x', 0)
    .attr('y', nodeRadius + 30)
    .attr('text-anchor', (d, i) => i === 0 ? 'start' : (i === processedHops.length - 1 ? 'end' : 'middle'))
    .attr('fill', 'var(--text-secondary)')
    .attr('font-size', '10px')
    // no rotation
    .text((d, i) => {
      if (i === 0 || i === processedHops.length - 1) {
        return truncate(d.by_host || d.ip || 'Unknown', 40);
      }
      return ''; // Hide middle bottom labels
    });
}


function renderBodies() {
  const container = document.getElementById('bodies-content');
  const data = state.data.artifacts?.bodies || [];

  if (data.length === 0) {
    container.innerHTML = '<p class="empty">No body content found</p>';
    return;
  }

  container.innerHTML = data.map((body, i) => {
    // SECURITY: Use sandboxed iframe for HTML body rendering
    const isHtml = body.content_type?.includes('html');
    const safeContent = body.content || 'No content';

    return `
      <div class="card" style="margin-bottom: var(--space-lg)">
        <h3>Body ${i + 1}: ${body.content_type}</h3>
        <div style="background: var(--panel-solid); padding: var(--space-md); border-radius: 6px; border: 1px solid var(--border);">
          ${isHtml ? `
            <div style="background: white; border-radius: 4px; overflow: hidden; position: relative;">
              <iframe 
                sandbox="allow-same-origin" 
                style="width: 100%; height: 500px; border: none;"
                srcdoc="${safeContent.replace(/&/g, '&amp;').replace(/"/g, '&quot;')}"
              ></iframe>
              <div style="position: absolute; bottom: 0; left: 0; right: 0; background: rgba(0,0,0,0.05); padding: 4px 10px; font-size: 10px; color: #666; pointer-events: none;">
                🛡️ Sandboxed Preview
              </div>
            </div>
          ` : `
            <pre style="white-space: pre-wrap; word-break: break-word; font-size: 13px; max-height: 500px; overflow-y: auto;">${escapeHtml(safeContent)}</pre>
          `}
        </div>
      </div>
    `;
  }).join('');
}

function exportData(type) {
  if (!state.data) {
    showToast('No data loaded', 'error');
    return;
  }
  let content, filename, mimeType;
  switch (type) {
    case 'ioc-csv':
      const iocs = state.data.iocs || state.data.artifacts?.iocs || [];
      const iocList = Array.isArray(iocs) ? iocs : [...(iocs.urls || []), ...(iocs.domains || []), ...(iocs.ips || [])];
      content = 'IOC,Type,Source\n' + iocList.map(i => `${i.value},${i.type},${i.source || 'unknown'}`).join('\n');
      filename = 'iocs.csv';
      mimeType = 'text/csv';
      break;
    case 'report':
      content = '# emltriage Report\n\n' + JSON.stringify(state.data.artifacts, null, 2);
      filename = 'report.md';
      mimeType = 'text/markdown';
      break;
    case 'graph':
      content = JSON.stringify(state.data.artifacts?.routing || [], null, 2);
      filename = 'graph.json';
      mimeType = 'application/json';
      break;
  }
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
  showToast(`Exported ${filename}`, 'success');
}

// Settings Management
document.addEventListener('change', (e) => {
  if (e.target.id === 'theme-select') {
    applyTheme(e.target.value);
  }

  if (e.target.id === 'reduced-motion-setting') {
    applyMotionPreference(e.target.checked);
  }

  // API key inputs
  if (e.target.id?.endsWith('-api-key')) {
    const id = e.target.id;
    const key = id === 'vt-api-key' ? 'vt' : id === 'abuse-api-key' ? 'abuse' : 'openai';
    state.apiKeys[key] = e.target.value;

    if (state.saveKeys) {
      localStorage.setItem(`${key}_api_key`, e.target.value);
    } else {
      localStorage.removeItem(`${key}_api_key`);
    }
    checkApiKeys();
  }

  if (e.target.id === 'save-keys-setting') {
    state.saveKeys = e.target.checked;
    localStorage.setItem('saveKeys', state.saveKeys);

    if (!state.saveKeys) {
      // Clear persistence if disabled
      ['vt', 'abuse', 'openai'].forEach(k => localStorage.removeItem(`${k}_api_key`));
    } else {
      // Persist current keys
      ['vt', 'abuse', 'openai'].forEach(k => {
        if (state.apiKeys[k]) localStorage.setItem(`${k}_api_key`, state.apiKeys[k]);
      });
    }
  }
});

// Initialize settings values
document.addEventListener('DOMContentLoaded', () => {
  const themeSelect = document.getElementById('theme-select');
  if (themeSelect) themeSelect.value = state.currentTheme;

  const motionSetting = document.getElementById('reduced-motion-setting');
  if (motionSetting) motionSetting.checked = state.reducedMotion;

  const saveSetting = document.getElementById('save-keys-setting');
  if (saveSetting) saveSetting.checked = state.saveKeys;

  if (state.apiKeys.vt) document.getElementById('vt-api-key').value = state.apiKeys.vt;
  if (state.apiKeys.abuse) document.getElementById('abuse-api-key').value = state.apiKeys.abuse;
  if (state.apiKeys.openai) document.getElementById('openai-api-key').value = state.apiKeys.openai;

  const endpointUrlInput = document.getElementById('llm-endpoint-url');
  if (endpointUrlInput) {
    endpointUrlInput.value = state.llm.endpoint;
    endpointUrlInput.addEventListener('change', (e) => {
      state.llm.endpoint = e.target.value;
      localStorage.setItem('llm_endpoint', e.target.value);
    });
  }

  const modelInput = document.getElementById('llm-model-name');
  if (modelInput) {
    modelInput.value = state.llm.model;
    modelInput.addEventListener('change', (e) => {
      state.llm.model = e.target.value;
      localStorage.setItem('llm_model', e.target.value);
    });
  }

  // Cloud Endpoint Detection
  if (endpointUrlInput) {
    endpointUrlInput.addEventListener('input', (e) => {
      const val = e.target.value.toLowerCase();
      if (val.includes('deepseek') && !val.includes('http')) {
        e.target.value = 'https://api.deepseek.com';
        state.llm.endpoint = 'https://api.deepseek.com';
      }
    });
  }

  // AI Generation Wire-up
  const btnGen = document.getElementById('btn-generate-ai');
  if (btnGen) btnGen.onclick = () => generateAISummary();

  const viewPromptLink = document.getElementById('link-view-prompt');
  if (viewPromptLink) {
    viewPromptLink.onclick = (e) => {
      e.preventDefault();
      if (!state.data) {
        showToast('Load an email first to see the prompt.', 'info');
        return;
      }
      const toon = constructTOONPrompt();
      // Use a textarea-based modal so the full text is never truncated
      const win = window.open('', '_blank', 'width=700,height=600,scrollbars=yes');
      win.document.write(`<html><body style="margin:0"><textarea style="width:100%;height:100%;font-family:monospace;font-size:13px;border:none;padding:12px;box-sizing:border-box">${toon.replace(/</g, '&lt;')}</textarea></body></html>`);
    };
  }

  checkApiKeys();
});

// Build a compact TOON-format prompt from the current artifact data.
// TOON = structured plain-text Key=Value. Avoids JSON parsing overhead in the LLM.
function constructTOONPrompt() {
  if (!state.data) return null;
  const a = state.data.artifacts;

  // --- HEADER ---
  const subject = a.headers?.find(h => h.name.toLowerCase() === 'subject')?.raw_value || 'Unknown';
  const from = a.headers?.find(h => h.name.toLowerCase() === 'from')?.raw_value || 'Unknown';
  const to = a.headers?.find(h => h.name.toLowerCase() === 'to')?.raw_value || 'Unknown';
  const date = a.headers?.find(h => h.name.toLowerCase() === 'date')?.raw_value || 'Unknown';
  const msgId = a.headers?.find(h => h.name.toLowerCase() === 'message-id')?.raw_value || 'Unknown';

  // --- RISK ---
  const risk = a.risk?.score ?? 0;
  const severity = a.risk?.severity ?? 'unknown';
  const reasons = (a.risk?.reasons || []).map(r => `  - [+${r.weight}] ${r.description} (${r.code})`).join('\n') || '  - None';

  // --- AUTH ---
  const authLines = [];
  for (const ar of (a.authentication?.parsed_results || [])) {
    for (const res of (ar.results || [])) {
      authLines.push(`  ${(res.mechanism || '?').toUpperCase()}=${res.result} domain=${ar.domain}`);
    }
  }
  const auth = authLines.length ? authLines.join('\n') : '  None';

  // --- ROUTING HOPS ---
  const hopLines = (a.routing || []).map((r, i) => {
    const anomalies = (r.anomalies || []).join(', ') || 'none';
    return `  Hop${i + 1}: ${r.from_host || '?'} -> ${r.by_host || '?'} [IP=${r.ip || '?'}] anomalies=${anomalies}`;
  });
  const hops = hopLines.length ? hopLines.join('\n') : '  None';

  // --- IOCs ---
  const uniqueIocs = [];
  const seenIocVals = new Set();

  for (const ioc of (a.iocs || [])) {
    if (!ioc || !ioc.value) continue;
    const lowerVal = ioc.value.toLowerCase();
    // Deduplicate and strip out known noisy infrastructure entirely
    if (!seenIocVals.has(lowerVal) && !isInfrastructureNoise(lowerVal)) {
      seenIocVals.add(lowerVal);
      uniqueIocs.push(ioc);
    }
  }

  const sortedIocs = uniqueIocs.sort((aObj, bObj) => {
    // Highest malicious score first
    const scoreDiff = (bObj.malicious_score || 0) - (aObj.malicious_score || 0);
    if (scoreDiff !== 0) return scoreDiff;
    return 0;
  });

  const iocLines = sortedIocs.slice(0, 40).map(ioc =>
    `  ${ioc.type}=${ioc.value}${ioc.malicious_score > 0 ? ` score=${ioc.malicious_score}` : ''}`
  );
  const iocs = iocLines.length ? iocLines.join('\n') : '  None';

  // --- ATTACHMENTS ---
  const attachLines = (a.attachments || []).map(att =>
    `  ${att.filename} [${att.content_type}] sha256=${att.sha256 || 'n/a'}`
  );
  const attachments = attachLines.length ? attachLines.join('\n') : '  None';

  return [
    '=== EMAIL FORENSIC TRIAGE REPORT ===',
    `Subject   = ${subject}`,
    `From      = ${from}`,
    `To        = ${to}`,
    `Date      = ${date}`,
    `MessageID = ${msgId}`,
    '',
    `RiskScore = ${risk}/100 (${severity})`,
    'RiskFactors:',
    reasons,
    '',
    'Authentication:',
    auth,
    '',
    'RoutingPath:',
    hops,
    '',
    'IOCs:',
    iocs,
    '',
    'Attachments:',
    attachments,
    '',
    '=== REQUEST ===',
    'Produce a forensic summary incorporating the RiskScore and RiskFactors into the Verdict.',
    length === 'quick' ? 'Format strictly as:\nVerdict: (Malicious/Suspicious/Benign) - Brief explanation.\nBottom Line: (One sentence summary)' :
      length === 'comprehensive' ? 'Format strictly as:\nVerdict: (Malicious/Suspicious/Benign) - Detailed explanation of score.\nAttack Chain Narrative: (Full paragraph analyzing how the attack works or why it is suspicious based on headers/links).\nIndicators: (List of extracted entities)\nRecommended Actions: (Prioritized list)' :
        'Format strictly as:\nVerdict: (Malicious/Suspicious/Benign) - Brief explanation of score.\nKey Evidence: (bullet list, max 5 items, one sentence each)\nImmediate Actions: (numbered list, max 3 actionable steps)'
  ].join('\n');
}

// Simple Markdown to HTML parser for AI output
function parseAIMarkdown(text) {
  if (!text) return '';
  let html = text
    // Remove thinking tags if they leaked into the main text box
    .replace(/<thinking>[\s\S]*?<\/thinking>/g, '')
    // Headers
    .replace(/^### (.*$)/gim, '<h4>$1</h4>')
    .replace(/^## (.*$)/gim, '<h3>$1</h3>')
    // Bold
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    // Italic
    .replace(/\*(.*?)\*/g, '<em>$1</em>')
    // Unordered lists
    .replace(/^\s*-\s+(.*)/gim, '<li>$1</li>')
    .replace(/(<li>.*<\/li>)/s, '<ul>$1</ul>')
    // Ordered lists
    .replace(/^\s*\d+\.\s+(.*)/gim, '<li>$1</li>')
    .replace(/(<li>.*?<\/li>(?!<li>))/s, '<ol>$1</ol>')
    // Paragraphs (double newlines)
    .replace(/\n\n/g, '</p><p>')
    // Single newlines
    .replace(/\n/g, '<br>');

  return `<p>${html}</p>`;
}

// AI Summary Generation
async function generateAISummary() {
  if (!state.data) {
    showToast('Load an email artifact first.', 'warning');
    return;
  }

  const btn = document.getElementById('btn-generate-ai');
  const content = document.getElementById('ai-summary-content');
  const lengthSelect = document.getElementById('ai-length-select');
  const selectedLength = lengthSelect ? lengthSelect.value : 'medium';

  if (!state.apiKeys.openai && state.llm.endpoint.includes('openai.com')) {
    showToast('Please configure an OpenAI API key or set it to "local" in Settings.', 'warning');
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Generating...';
  content.innerHTML = '<p class="empty" style="color: var(--accent);">Waiting for LLM response...<br><small style="opacity: 0.7;">(Note: Qwen 9B Reasoning can take up to 2 mins on first run)</small></p>';

  // Build TOON prompt with active length
  const promptText = constructTOONPrompt(selectedLength);

  // Log prompt for auditing
  console.log(`TOON Prompt (${selectedLength}) being sent:\n` + promptText);

  try {
    const resp = await fetch('/api/ai/summarize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        endpointUrl: state.llm.endpoint,
        model: state.llm.model,
        apiKey: state.apiKeys.openai,
        prompt: promptText,
        length: selectedLength
      })
    });

    if (!resp.ok) {
      const err = await resp.json();
      throw new Error(err.detail || 'Failed to fetch AI summary');
    }

    const reply = await resp.json();

    // Apply markdown formatting
    const finalHtml = parseAIMarkdown(reply.summary);

    content.innerHTML = `<div class="ai-result markdown-body" style="font-size: 0.95em; line-height: 1.5;">${finalHtml}</div>`;

  } catch (err) {
    console.error(err);
    content.innerHTML = `<p class="empty" style="color: var(--danger)">Error: ${escapeHtml(err.message)}</p>`;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Regenerate Summary';
  }
}
