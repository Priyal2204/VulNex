# VulNex — LLM-Powered Vulnerability Detection Tool

A full-stack, LLM-powered security vulnerability detection tool that combines static analysis with AI-driven assessment. Upload your code files, get real-time scan progress, detailed vulnerability findings with Gemini-generated fix suggestions, and downloadable security reports. Live at https://vulnex-llm-powered.onrender.com/

---

## Features

- Upload single files, multiple files, or ZIP archives (.py, .js, .ts, .java, .cpp, .c, .cs, .rb, .php, .go, .rs)
- Static analysis via **Bandit** (Python) and **Semgrep** (multi-language)
- AI-powered vulnerability explanations and fix suggestions via **Google Gemini** and **HuggingFace**
- Three-stage scanning pipeline: static analysis → AI analysis → CVE mapping
- Real-time progress tracking per stage
- Vulnerability details with CWE IDs, severity levels, line numbers, and code snippets
- Downloadable reports in **PDF** and **Excel** formats
- Mark vulnerabilities as reviewed

---

## Tech Stack

### Frontend
- React 18 + TypeScript
- Vite (build tool)
- shadcn/ui + Radix UI + Tailwind CSS
- TanStack Query (data fetching)
- Wouter (routing)
- Framer Motion (animations)

### Backend
- Node.js + Express.js + TypeScript
- Multer (file uploads)
- In-memory storage (no DB required for dev)
- Python child processes for scanning and AI analysis

### Python Services
- `scanner.py` — runs Bandit + Semgrep, outputs structured JSON
- `ai_analyzer.py` — calls Gemini / HuggingFace for fix suggestions
- `report_generator.py` — generates PDF (ReportLab) and Excel (openpyxl) reports

---

## Project Structure

```
VulNex/
├── client/               # React frontend
│   └── src/
│       ├── components/
│       ├── pages/
│       └── services/
├── server/               # Express backend
│   ├── services/
│   │   ├── scanner.py
│   │   ├── ai_analyzer.py
│   │   └── report_generator.py
│   ├── index.ts
│   ├── routes.ts
│   ├── storage.ts
│   └── vite.ts
├── shared/               # Shared types/schema
├── uploads/              # Uploaded files (auto-created)
├── reports/              # Generated reports (auto-created)
├── requirements.txt      # Python dependencies
├── package.json
└── render.yaml           # Render deployment config
```

---

## Local Setup

### Prerequisites
- Node.js 20+
- Python 3.11+
- pip

### Install dependencies

```bash
npm install
pip install -r requirements.txt
```

### Configure environment

Create a `.env` file in the root:

```env
GEMINI_API_KEY=your_gemini_api_key
GEMINI_MODEL=gemini-flash-lite-latest
USE_GEMINI=true
HUGGINGFACE_API_KEY=your_huggingface_token
PYTHONUTF8=1
PYTHONIOENCODING=utf-8
```

Get your keys:
- Gemini: https://aistudio.google.com/app/apikey
- HuggingFace: https://huggingface.co/settings/tokens

### Run in development

```bash
npm run dev
```

App runs at `http://localhost:3000`

---

## Production Build

```bash
npm run build
npm run start
```

Or use the combined build command (used by Render):

```bash
npm install && npm run build && pip install -r requirements.txt
```

---

## Deploy to Render

The repo includes a `render.yaml` for one-click deployment.

1. Go to [render.com](https://render.com) → New Web Service
2. Connect the GitHub repo: `https://github.com/Priyal2204/VulNex`
3. Render will auto-detect `render.yaml` — or set manually:
   - **Build command:** `npm install && npm run build && pip install -r requirements.txt`
   - **Start command:** `npm run start`

### Environment variables to set on Render

| Variable | Value |
|---|---|
| `NODE_ENV` | `production` |
| `PORT` | `10000` |
| `GEMINI_API_KEY` | your Gemini API key |
| `GEMINI_MODEL` | `gemini-flash-lite-latest` |
| `USE_GEMINI` | `true` |
| `HUGGINGFACE_API_KEY` | your HuggingFace token |
| `PYTHONUTF8` | `1` |
| `PYTHONIOENCODING` | `utf-8` |

---

## Scanning Pipeline

1. **Static Analysis** — Bandit scans Python files for common security issues; Semgrep scans all supported languages using the `auto` ruleset
2. **AI Analysis** — Each vulnerability is passed to Gemini (primary) or HuggingFace (fallback) for a natural-language explanation and a concrete fix suggestion
3. **CVE Mapping** — Vulnerabilities are mapped to CWE IDs and OWASP categories

If no API keys are configured, the AI stage falls back to deterministic rule-based suggestions (still useful, just not LLM-powered).

---

## Supported Languages

`.py` `.js` `.ts` `.java` `.cpp` `.c` `.cs` `.rb` `.php` `.go` `.rs` and ZIP archives containing any of the above.

---

## Python Dependencies

```
bandit
semgrep
reportlab
openpyxl
python-dotenv
google-generativeai
requests
```
