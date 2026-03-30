# PhishGuard

PhishGuard is a lightweight phishing detection web app built with vanilla HTML/CSS/JavaScript on the frontend and Node.js + Express on the backend. It scans a suspicious URL, then combines evidence from TinyFish, VirusTotal, and RDAP/WHOIS into a single report with a risk score, verdict, redirect chain, threat indicators, and JSON export.

## Architecture

```
Browser (user)
     │
     │  HTTP POST /api/scan
     ▼
┌─────────────────────────────────────────┐
│              Express server             │
│  server.js                              │
│                                         │
│  ┌──────────┐  ┌──────────────────────┐ │
│  │Rate limit│  │  Input validation    │ │
│  └────┬─────┘  └──────────┬───────────┘ │
│       └────────────┬───────┘            │
│                    │ parallel           │
│         ┌──────────┼──────────┐         │
│         ▼          ▼          ▼         │
│    TinyFish    VirusTotal   RDAP/WHOIS  │
│    (browser    (multi-      (domain     │
│    analysis)   engine scan) intel)      │
│         └──────────┼──────────┘         │
│                    │ merge              │
│                    ▼                    │
│            Risk score + verdict         │
│            (heuristic fallback)         │
└─────────────────────────────────────────┘
     │
     │  JSON response
     ▼
Browser renders report
     │
     │  Export JSON report
     ▼
phishguard-report-<timestamp>.json
```

## Features

- TinyFish integration for live browser-style phishing analysis
- VirusTotal integration for multi-engine URL reputation checks
- RDAP / WHOIS integration for domain age and registration intelligence
- fallback heuristic scoring if TinyFish is unavailable
- rate limiting and backend-side validation
- frontend URL normalization and input validation
- safer backend-only secret handling to avoid browser-side CORS and API key exposure
- JSON report export with structured scan data
- copy-to-clipboard action for scanned URLs

## Tech stack

- Frontend: HTML (`index.html`), CSS (`style.css`), vanilla JavaScript (`script.js`)
- Backend: Node.js, Express
- Middleware: cors, express-rate-limit, dotenv
- External services: TinyFish, VirusTotal, RDAP

## Project structure

```text
tinyfish-phishguard/
  public/
    index.html          # markup only — links to style.css and script.js
    style.css           # all styles
    script.js           # all frontend logic, including JSON export
    index.original.html # original single-file version (reference)
  server.js
  package.json
  .env.example
```

## Run locally

```bash
npm install
cp .env.example .env
npm start
```

Open `http://localhost:3000`.

## Environment variables

```env
PORT=3000
NODE_ENV=development
CORS_ORIGIN=*
TINYFISH_API_KEY=your_tinyfish_key
VIRUSTOTAL_API_KEY=your_virustotal_key
```

## JSON export

After a scan completes, click **Export JSON Report** to download a structured `.json` file. The export includes:

```json
{
  "exported_at": "ISO timestamp of export",
  "scanned_at": "ISO timestamp of scan",
  "url": "scanned URL",
  "domain": "extracted domain",
  "verdict": "phishing | suspicious | clean | unknown",
  "risk_score": 0,
  "summary": "human-readable summary",
  "threat_signals": [],
  "redirects": [],
  "whois": {
    "domain": "",
    "registrar": "",
    "country": "",
    "created": "",
    "expires": "",
    "age_days": 0
  },
  "virustotal": {
    "malicious": 0,
    "suspicious": 0,
    "harmless": 0,
    "undetected": 0
  },
  "raw": {}
}
```

The `raw` field contains the full unmodified API response from the backend.

## Deployment notes

### Backend

Deploy the whole app to Render or any Node-compatible host.

Start command:

```bash
node server.js
```

### CORS

If your frontend is hosted on a different origin, set:

```env
CORS_ORIGIN=https://your-frontend-domain.com
```

Do not include a trailing slash.

## What was improved

- fixed browser-side integration architecture by moving API calls server-side
- added timeout handling for external API calls
- added Express rate limiting
- added safer input validation and user-facing error messages
- improved fallback scoring logic
- replaced PDF export with structured JSON export
- separated frontend into `index.html`, `style.css`, and `script.js`
- preserved the original uploaded HTML as `public/index.original.html`

## Notes

End-to-end live verification of TinyFish and VirusTotal depends on valid API keys and the exact behavior of those external APIs at runtime.
