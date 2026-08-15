# ThreatVigil – Threat Intelligence & Malware Scanner

A full-stack cybersecurity threat intelligence application built with **Next.js (App Router)**, **TypeScript**, **Tailwind CSS**, and multi-source API integrations with **VirusTotal API v3**, **AbuseIPDB**, and **Google Safe Browsing API v4**.

![Threat Scanner Preview](https://images.unsplash.com/photo-1550751827-4bd374c3f58b?auto=format&fit=crop&w=1200&q=80)

---

## ⚡ Key Features

1. **🌐 URL Threat Scanner**
   - Queries VirusTotal API v3 and Google Safe Browsing API v4 concurrently.
   - Categorizes threat types (Phishing, Social Engineering, Malware Distribution).
   - Shows individual vendor engine flags, HTTP status, and final redirected endpoints.

2. **📡 IP Reputation & Threat Lookup**
   - Submits IPv4/IPv6 to AbuseIPDB and VirusTotal.
   - Displays Abuse Confidence Score (0-100%), ISP, Geolocation, ASN, Usage Type (VPN/Tor/Datacenter), and recent community incident reports.

3. **🧬 Cryptographic Hash Lookup**
   - Accepts **MD5** (32 hex), **SHA-1** (40 hex), or **SHA-256** (64 hex).
   - Identifies malware families (WannaCry, Emotet, Ransomware, etc.), known names, first/last seen timestamps, and AV detection ratios.

4. **📁 File Upload Scanner**
   - Computes **SHA-256 client-side** using Web Crypto API (`crypto.subtle.digest`) to save bandwidth.
   - Queries VirusTotal hash database first to avoid redundant uploads.
   - If not found, uploads payload to VirusTotal `/api/v3/files` and polls analysis status in real time.

5. **📷 QR Code Scanner**
   - Decodes QR codes client-side using `jsQR` via **image drag-and-drop** or **live webcam stream**.
   - Extracts embedded URLs and automatically runs them through the threat scanner.

6. **🛡️ Dual Mode: Live API & Realistic Demo**
   - When API keys are configured, queries live security feeds.
   - If keys are not yet configured, automatically enters an interactive demo mode with realistic sample threat payloads (EICAR test file, Cobalt Strike C2 IP, Phishing links).

7. **📊 SOC Analyst Workstation UX**
   - Cyber-dark SOC aesthetic with color-coded risk levels (Clean / Suspicious / Malicious).
   - 70+ vendor detection matrix with instant search and status filters.
   - Local investigation history stored in `localStorage` with JSON export/clear.
   - One-click copy executive summary report to clipboard or download JSON report.

---

## 🔑 How to Get Free API Keys

All services integrated offer generous **100% free tiers**:

### 1. VirusTotal API v3
- **Quota**: 500 requests/day, 4 requests/minute.
- **Steps**:
  1. Go to [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) and sign up for a free account.
  2. Verify your email and log in.
  3. Click your profile avatar in the top right → **API Key**.
  4. Copy your 64-character API key.

### 2. AbuseIPDB API v2
- **Quota**: 1,000 IP lookups/day.
- **Steps**:
  1. Go to [abuseipdb.com/register](https://www.abuseipdb.com/register) and create a free account.
  2. Verify your email and log in.
  3. Go to **Account** → **API** → **Create Key**.
  4. Copy your API key.

### 3. Google Safe Browsing API v4
- **Quota**: 10,000 requests/day free.
- **Steps**:
  1. Go to [Google Cloud Console](https://console.cloud.google.com/).
  2. Create a new project (or select an existing one).
  3. Search for **Safe Browsing API** in the API Library and click **Enable**.
  4. Go to **APIs & Services** → **Credentials** → **Create Credentials** → **API Key**.
  5. Copy your generated API key.

---

## 🚀 Quickstart & Setup

### Prerequisites
- Node.js 18.x or higher
- npm, pnpm, or yarn

### 1. Clone & Install Dependencies
```bash
git clone <repository-url>
cd "treat detection app"
npm install
```

### 2. Configure Environment Variables
Copy the `.env.example` template:
```bash
cp .env.example .env.local
```

Open `.env.local` and add your keys:
```env
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
GOOGLE_SAFE_BROWSING_API_KEY=your_google_safe_browsing_api_key_here
```

*(Note: You can also enter or test API keys directly in the web UI via the **API Settings** modal in the top header).*

### 3. Run Development Server
```bash
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) in your browser.

### 4. Build for Production
```bash
npm run build
npm run start
```

---

## 🔒 Security & Architecture

- **Server-Side API Proxying**: External threat intelligence API keys are strictly kept server-side in Next.js App Router API routes and are never leaked to client browsers.
- **Backend Rate Limiting**: In-memory token bucket sliding window protects your free-tier quotas from spam or client exhaustion.
- **Input Sanitization**: Strict regex checks for IPv4/IPv6, URL protocols, and MD5/SHA1/SHA256 hex lengths prevent malformed payloads.
- **Client-Side Hashing & QR Processing**: SHA-256 computation and QR image decoding are processed directly inside the user's browser using Web Crypto API and `jsQR`.

---

## 📁 Project Structure

```
treat detection app/
├── src/
│   ├── app/
│   │   ├── api/
│   │   │   ├── scan/
│   │   │   │   ├── url/route.ts        # VirusTotal & Safe Browsing URL proxy
│   │   │   │   ├── ip/route.ts         # AbuseIPDB & VirusTotal IP proxy
│   │   │   │   ├── hash/route.ts       # VirusTotal file hash proxy
│   │   │   │   ├── file/route.ts       # Secure file upload proxy
│   │   │   │   └── file/status/route.ts# VT analysis polling route
│   │   │   └── status/route.ts         # Health & API configuration check
│   │   ├── globals.css                 # SOC dark theme & radar glow styles
│   │   ├── layout.tsx                  # Root layout & SEO tags
│   │   └── page.tsx                    # Main Threat Intelligence Dashboard
│   ├── components/
│   │   ├── Header.tsx                  # SOC navigation, live status, modals
│   │   ├── common/
│   │   │   └── ScanningProgress.tsx    # Radar animation & multi-stage stepper
│   │   ├── scanners/
│   │   │   ├── UrlScanner.tsx          # URL scan form & samples
│   │   │   ├── IpScanner.tsx           # IP reputation form & samples
│   │   │   ├── HashScanner.tsx         # Hash lookup form & samples
│   │   │   ├── FileScanner.tsx         # Drag-drop file upload & hash pre-check
│   │   │   └── QrScanner.tsx           # QR image decoder & live webcam scan
│   │   ├── results/
│   │   │   ├── VerdictBanner.tsx       # Color-coded threat verdict & gauge
│   │   │   ├── VendorMatrix.tsx        # 70+ vendor detection table & search
│   │   │   └── ReportDetails.tsx       # Technical metadata & raw JSON view
│   │   ├── history/
│   │   │   └── HistoryDrawer.tsx       # Local scan history & JSON export
│   │   └── settings/
│   │       └── ApiConfigModal.tsx      # Browser API key management
│   ├── lib/
│   │   ├── api-keys.ts                 # Server & client key extractors
│   │   ├── demo-data.ts                # Realistic mock threats for demo mode
│   │   ├── rate-limiter.ts             # In-memory sliding window rate limiter
│   │   ├── storage.ts                  # LocalStorage history & custom keys
│   │   ├── threat-scorer.ts            # Score normalization & verdict engine
│   │   └── validators.ts               # Input validation (IP/URL/Hash)
│   └── types/
│       └── threat.ts                   # TypeScript interfaces & types
├── .env.example                        # Template for environment variables
├── package.json
├── tailwind.config.ts
└── tsconfig.json
```

---

## 📄 License
MIT License. Built for security analysts, incident responders, and developers.
