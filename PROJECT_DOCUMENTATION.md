# PROJECT DOCUMENTATION REPORT

---

# 🛡️ ThreatVigil: Multi-Source Cyber Threat Intelligence & Malware Detection Platform

**Submitted by:** Chinthala Nani  
**Project Role:** Lead Creator & Full-Stack Architect  
**Live Production URL:** [https://threat-detection-scanner-opal.vercel.app](https://threat-detection-scanner-opal.vercel.app)  
**GitHub Repository:** [https://github.com/chinthalanani/threat-detection-scanner](https://github.com/chinthalanani/threat-detection-scanner)  
**Technology Stack:** Next.js 14 (App Router), React, TypeScript, Tailwind CSS, VirusTotal API v3, AbuseIPDB API v2, Google Safe Browsing API v4, Web Crypto API, jsQR  
**Date:** August 2026  

---

## 📑 Table of Contents
1. [Executive Summary / Abstract](#1-executive-summary--abstract)
2. [Problem Statement](#2-problem-statement)
3. [Project Objectives & Scope](#3-project-objectives--scope)
4. [System Architecture & Data Flow](#4-system-architecture--data-flow)
5. [Detailed Module Breakdown (7 Threat Scanners)](#5-detailed-module-breakdown-7-threat-scanners)
   - [5.1 URL Threat Scanner & Redirect Tracer](#51-url-threat-scanner--redirect-tracer)
   - [5.2 IP Reputation & Threat Lookup](#52-ip-reputation--threat-lookup)
   - [5.3 Cryptographic Hash Lookup](#53-cryptographic-hash-lookup)
   - [5.4 File Upload & Binary Malware Scanner](#54-file-upload--binary-malware-scanner)
   - [5.5 QR Code Threat Scanner (Quishing Shield)](#55-qr-code-threat-scanner-quishing-shield)
   - [5.6 Email & Phishing Threat Scanner](#56-email--phishing-threat-scanner)
   - [5.7 Domain & WHOIS / DNS Security Scanner](#57-domain--whois--dns-security-scanner)
   - [5.8 Security Operations Center (SOC) UI/UX](#58-security-operations-center-soc-uiux)
   - [5.9 Security, Rate Limiting & Proxy Architecture](#59-security-rate-limiting--proxy-architecture)
6. [Technology Stack & Tools Used](#6-technology-stack--tools-used)
7. [Threat Intelligence API Integrations](#7-threat-intelligence-api-integrations)
8. [Testing & Quality Assurance](#8-testing--quality-assurance)
9. [Installation, Configuration & Deployment Guide](#9-installation-configuration--deployment-guide)
10. [Conclusion & Future Roadmap](#10-conclusion--future-roadmap)

---

## 1. Executive Summary / Abstract

In the modern digital landscape, cyber threats have evolved beyond simple malicious attachments into complex multi-vector campaigns encompassing credential harvesting phishing websites, QR code deceptive payloads (**Quishing**), stealth IP loggers, dynamic C2 (Command & Control) botnet infrastructures, brand typo-squatting, and sophisticated obfuscated binaries.

**ThreatVigil** is a full-stack, enterprise-grade Cyber Threat Intelligence and Malware Detection Web Application developed by **Chinthala Nani**. The platform provides automated, multi-source cybersecurity threat evaluation across **seven critical vectors**:
1. **URLs & Shortlinks**
2. **IPv4 / IPv6 Addresses**
3. **Cryptographic File Hashes** (MD5, SHA-1, SHA-256)
4. **Binary File Uploads** (with in-browser Web Crypto pre-hashing)
5. **QR Codes** (with client-side image decoding and live webcam reticle)
6. **Email Addresses & Phishing Content** (disposable inbox detection, brand typo-squatting, breach lookups)
7. **Domains & WHOIS / DNS Records** (domain age, SSL certificate health, SPF/DMARC, DGA entropy)

By leveraging real-time telemetry from **70+ authoritative antivirus vendors (via VirusTotal API v3)**, **AbuseIPDB API v2**, and **Google Safe Browsing API v4**, alongside custom heuristics and client-side privacy algorithms, ThreatVigil empowers security analysts, incident responders, developers, and everyday internet users with instant, actionable threat verdicts.

---

## 2. Problem Statement

1. **Information Fragmentation**: Threat telemetry is scattered across disjointed platforms (VirusTotal, AbuseIPDB, Google Safe Browsing, WHOIS), forcing analysts to waste critical minutes manually aggregating data.
2. **Bandwidth & Privacy Inefficiencies**: Traditional cloud scanners require uploading entire multi-megabyte binaries over the network before checking if they are already known malware samples.
3. **Emergence of Quishing & Stealth Trackers**: Users scanning QR codes on mobile devices or receiving disguised tracking links (`iplogger`, `grabify`) are vulnerable to silent IP logging, geolocation harvesting, and credential theft.
4. **Email Spoofing & Phishing Urgency**: Attackers exploit homoglyph domains (`paypa1.com`) and throwaway email providers to deceive victims with high-urgency financial lures.
5. **Quota Exhaustion & API Key Exposure**: Exposing commercial or free-tier threat intel keys client-side leads to security vulnerabilities and quota depletion.

ThreatVigil solves these challenges by uniting 7-in-1 multi-source intelligence, client-side pre-hashing, built-in tracker shields, and secure serverless proxying under a sleek, dark SOC analyst workstation interface.

---

## 3. Project Objectives & Scope

- **Unified 7-in-1 Threat Intelligence Suite**: Seamlessly analyze URLs, IPs, Hashes, Files, QR codes, Emails, and Domains in a single dashboard.
- **Authoritative Multi-Source Feeds**: Query 70+ AV engines (Kaspersky, Sophos, BitDefender, Microsoft Defender, CrowdStrike, ESET) concurrently with Google Safe Browsing and AbuseIPDB.
- **Client-Side Privacy & Bandwidth Optimization**: Compute SHA-256 digests in-browser using the Web Crypto API to check hash databases before uploading large files.
- **In-Browser QR Decoding**: Decode QR codes client-side via image upload or live webcam streams without sending raw video feeds across the internet.
- **Tracker & IP Logger Shield**: Proactively detect and neutralize IP grabbers (`iplogger.com`, `grabify.link`, `2no.co`, `yip.su`, etc.) and follow HTTP 301/302 redirects.
- **Email Phishing & Typo-squatting Protection**: Screen for 500+ disposable domains, brand impersonations, and extract embedded links for auto-scanning.
- **Zero-Setup Usability**: Support a dual-mode engine that operates in full live API mode or interactive realistic simulation mode with built-in test signatures (e.g. EICAR, WannaCry, Cobalt Strike C2).

---

## 4. System Architecture & Data Flow

```
┌───────────────────────────────────────────────────────────────────────────────────────────┐
│                                   CLIENT BROWSER (React)                                  │
│  ┌─────────────────────────┐  ┌───────────────────────────┐  ┌─────────────────────────┐  │
│  │ 7 Scanner Input Modules │  │ Web Crypto SHA-256        │  │ jsQR Engine             │  │
│  │ (URL/IP/Hash/File/QR/   │  │ In-Browser Hashing        │  │ Client QR Decoding      │  │
│  │  Email/Domain)          │  │                           │  │ (Drag-Drop / Webcam)    │  │
│  └────────────┬────────────┘  └─────────────┬─────────────┘  └────────────┬────────────┘  │
│               └─────────────────────────────┼─────────────────────────────┘               │
│                                             ▼                                             │
│                               LocalStorage (Scan History & Keys)                          │
└─────────────────────────────────────────────┬─────────────────────────────────────────────┘
                                              │ HTTPS (API Proxy Request)
                                              ▼
┌───────────────────────────────────────────────────────────────────────────────────────────┐
│                            NEXT.JS SERVERLESS BACKEND (Vercel)                            │
│  ┌─────────────────────────────────────────────────────────────────────────────────────┐  │
│  │ In-Memory Sliding Window Rate Limiter (Token Bucket)                                │  │
│  └──────────────────────────────────────────┬──────────────────────────────────────────┘  │
│                                             ▼                                             │
│  ┌─────────────────────────────────────────────────────────────────────────────────────┐  │
│  │ Input Validation & Sanitization (IPv4/IPv6, MD5/SHA1/SHA256, URL, Domain, Email)    │  │
│  └──────────────────────────────────────────┬──────────────────────────────────────────┘  │
│                                             ▼                                             │
│  ┌─────────────────────────────────────────────────────────────────────────────────────┐  │
│  │ Threat Scoring, Verdict Normalization & Heuristic Analysis Engine                   │  │
│  └──────────────────────────────────────────┬──────────────────────────────────────────┘  │
└─────────────────────────────────────────────┼─────────────────────────────────────────────┘
                                              │
                    ┌─────────────────────────┼─────────────────────────┐
                    ▼                         ▼                         ▼
          ┌───────────────────┐     ┌───────────────────┐     ┌───────────────────┐
          │ VirusTotal API v3 │     │  AbuseIPDB API v2 │     │Google SafeBrowsing│
          │(70+ AV Engines &  │     │(IP Abuse Scores & │     │(Phishing & Malware│
          │ File Hash Feeds)  │     │ Incident Reports) │     │ Domain Blacklists)│
          └───────────────────┘     └───────────────────┘     └───────────────────┘
```

---

## 5. Detailed Module Breakdown (7 Threat Scanners)

### 5.1 URL Threat Scanner & Redirect Tracer
- **Endpoints**: `POST /api/scan/url`
- **Capabilities**:
  - Validates and normalizes target URL syntax.
  - Queries **VirusTotal API v3** and **Google Safe Browsing API v4** in parallel.
  - Built-in **Privacy & Tracker Shield** intercepts known IP grabbers (`iplogger.com`, `grabify.link`, `2no.co`, `blasze`, `stopify`) and assigns a **90/100 Malicious Risk Score**.
  - **Redirect Tracer**: Follows HTTP `301`, `302`, `307` headers to unmask destination redirect targets.

### 5.2 IP Reputation & Threat Lookup
- **Endpoints**: `POST /api/scan/ip`
- **Capabilities**:
  - Queries **AbuseIPDB API v2** for Abuse Confidence Scores (0-100%), total incident reports, ISP name, country code, and distinct reporter metrics.
  - Integrates **VirusTotal IP endpoint** to fetch ASN, network CIDR, and engine detections.
  - Detects Botnet nodes, SSH brute-force attackers, and Tor/VPN exit nodes.

### 5.3 Cryptographic Hash Lookup
- **Endpoints**: `POST /api/scan/hash`
- **Capabilities**:
  - Auto-identifies hash algorithm: **MD5** (32 hex), **SHA-1** (40 hex), or **SHA-256** (64 hex).
  - Queries VirusTotal file repository (`/api/v3/files/{hash}`).
  - Extracts malware family classifications (**WannaCry**, **Emotet**, **RedLine Stealer**, **Mirai**), known file names, compilation timestamps, and detection ratios.

### 5.4 File Upload & Binary Malware Scanner
- **Endpoints**: `POST /api/scan/file`, `GET /api/scan/file/status`
- **Capabilities**:
  - Computes file SHA-256 client-side using `crypto.subtle.digest` in under 50ms.
  - Performs a **hash-first lookup** to avoid redundant bandwidth consumption for known files.
  - If unindexed, securely uploads the multipart binary (up to 32MB) to VirusTotal and polls analysis status asynchronously with real-time UI feedback.
  - Flags dangerous double extensions (e.g. `invoice.pdf.exe`, `photo.jpg.scr`).

### 5.5 QR Code Threat Scanner (Quishing Shield)
- **Component**: `src/components/scanners/QrScanner.tsx`
- **Capabilities**:
  - Decodes QR codes client-side using the `jsQR` library.
  - Supports **drag-and-drop image upload** and **live webcam video capture** with a targeting reticle overlay.
  - Automatically pipes decoded URLs directly into the URL Threat Scanner.

### 5.6 Email & Phishing Threat Scanner
- **Endpoints**: `POST /api/scan/email`
- **Capabilities**:
  - **Dual-Mode Input**: Single Email Address OR Raw Email Headers/Body text.
  - Checks against a database of **500+ disposable/throwaway email providers** (`mailinator`, `tempmail`, `10minutemail`).
  - Detects **Brand Typo-squatting / Homoglyphs** (`paypa1.com`, `micros0ft.com`, `g00gle.com`, `app1e.com`, `netf1ix.com`).
  - Analyzes social engineering urgency keywords ("account suspended", "wire transfer", "IRS refund").
  - **Link Extractor**: Automatically extracts and screens all embedded URLs in the email body.
  - Surfaces known public data breach exposures.

### 5.7 Domain & WHOIS / DNS Security Scanner
- **Endpoints**: `POST /api/scan/domain`
- **Capabilities**:
  - Resolves authoritative DNS records (A, MX, NS, TXT) via DNS-over-HTTPS.
  - Flags **Newly Registered Domains (< 30 days)** commonly deployed in zero-day phishing campaigns.
  - Audits **SSL/TLS Certificate health** (issuer authority, validity days remaining, self-signed detection).
  - Evaluates **SPF, DMARC, and DKIM** email security compliance.
  - Computes **Shannon Entropy for DGA (Domain Generation Algorithm)** detection.

### 5.8 Security Operations Center (SOC) UI/UX
- **Verdict Banner**: Visual threat level display (**Clean** / **Suspicious** / **Malicious** / **Unknown**) with circular Risk Index meter (0-100).
- **Vendor Detection Matrix**: Filterable, searchable table displaying individual flags for all 70+ security vendors.
- **Report Details**: Deep technical tabs (Overview, Phishing Indicators, DNS & SSL, Signatures, Abuse Incident Logs, Raw JSON).
- **Scan History Manager**: Persists past scans in `localStorage` with type filters, 1-click reload, and JSON download.
- **Interactive About Page**: Comprehensive user guide, API key tutorials, and creator attribution (**Developed by Chinthala Nani**).

### 5.9 Security, Rate Limiting & Proxy Architecture
- **Server-Side Secret Protection**: External API keys reside safely in server environment variables and are never leaked to client browsers.
- **In-Memory Sliding Window Rate Limiter**: Limits requests per IP (15-20 req/min) to safeguard free-tier API quotas.
- **Client Custom Key Override**: Users can optionally supply their own API keys via the **API Settings** modal stored in their local browser.

---

## 6. Technology Stack & Tools Used

| Layer | Technology / Library | Purpose |
| :--- | :--- | :--- |
| **Frontend Framework** | **Next.js 14+ (App Router)** | Full-stack React framework with server components & routing |
| **Language** | **TypeScript 5.6** | Static type safety and comprehensive interface definitions |
| **Styling** | **Tailwind CSS 3.4** | Modern SOC dark theme, glassmorphism, glowing threat badges |
| **Icons** | **Lucide React** | Cyber-themed iconography across all tabs and result states |
| **QR Code Engine** | **jsQR 1.4** | In-browser QR code matrix extraction from images & video |
| **Client Hashing** | **Web Crypto API** | Native high-speed in-browser SHA-256 calculation |
| **Feedback Animations**| **Canvas-Confetti** | Celebration visual when clean scans are confirmed |
| **Backend & Routing** | **Next.js API Routes** | Secure serverless API proxies for VirusTotal, AbuseIPDB, GSB |
| **Hosting & CI/CD** | **Vercel Cloud Platform** | Global CDN deployment, automatic SSL, and 24/7 serverless runtime |
| **Version Control** | **Git & GitHub** | Source code version control and continuous deployment pipeline |

---

## 7. Threat Intelligence API Integrations

```
┌────────────────────────┬───────────────────┬──────────────────────────────────────────┐
│ Provider               │ Free Quota        │ Core Capabilities Used                   │
├────────────────────────┼───────────────────┼──────────────────────────────────────────┤
│ VirusTotal API v3      │ 500 requests/day  │ URL scanning, IP telemetry, File hash    │
│                        │ 4 requests/min    │ lookups, Multipart binary file analysis  │
├────────────────────────┼───────────────────┼──────────────────────────────────────────┤
│ AbuseIPDB API v2       │ 1,000 checks/day  │ IP reputation score, abuse categories,   │
│                        │                   │ ISP/ASN data, community incident reports │
├────────────────────────┼───────────────────┼──────────────────────────────────────────┤
│ Google Safe Browsing v4│ 10,000 req/day    │ Social Engineering, Malware distribution,│
│                        │                   │ and Phishing domain identification       │
└────────────────────────┴───────────────────┴──────────────────────────────────────────┘
```

---

## 8. Testing & Quality Assurance

### 8.1 Automated Build Verification
The project was tested using strict production compilation:
```bash
npm run build
```
- **Result**: 0 TypeScript errors, 0 ESLint warnings.
- Generated static routes (`/`, `/about`, `/_not-found`) and dynamic serverless API endpoints (`/api/scan/*`, `/api/status`).

### 8.2 Heuristic & Test Payload Validation
1. **Email Scanner Test**: Scanned `security-alert@paypa1-account-verification.com` → Correctly flagged as **Malicious (Typosquatting target: PayPal Inc., Risk Score: 92/100)**.
2. **Domain Scanner Test**: Scanned `secure-login-apple-support-auth892.xyz` → Flagged as **Malicious Newly Registered Phishing Domain with High DGA Entropy**.
3. **IP Logger Test**: Scanned `https://iplogger.com/2fEeb6` → Correctly intercepted by the *ThreatVigil Privacy Shield* and flagged as **Malicious IP Logger / Tracking Redirect** (Risk Index: 90/100).
4. **EICAR Standard Antivirus Test**: Evaluated EICAR test string and hash → Instantly identified as **EICAR-Test-File** across all engines.
5. **WannaCry Ransomware Hash**: Scanned `ed01ebf83334a19373140c2a21f4ea96fc51e07dc43141400d31654a260e40cb` → Categorized as **WannaCry.Ransomware.Cryptor** (Threat Score: 96/100).
6. **Clean DNS IP Test**: Scanned `8.8.8.8` (Google DNS) → Verified 0% abuse score, 100% clean verdict.
7. **QR Code Webcam Test**: Tested live webcam video stream with camera reticle → Successfully decoded embedded payload within 100ms.

---

## 9. Installation, Configuration & Deployment Guide

### 9.1 Local Development Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/chinthalanani/threat-detection-scanner.git
   cd threat-detection-scanner
   ```

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Configure Environment Variables (Optional)**:
   Create a `.env.local` file:
   ```env
   VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
   ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
   GOOGLE_SAFE_BROWSING_API_KEY=your_google_safe_browsing_api_key_here
   ```

4. **Run the local development server**:
   ```bash
   npm run dev
   ```
   Open [http://localhost:3000](http://localhost:3000) in your browser.

---

### 9.2 Docker Deployment

Build and run using Docker Compose:
```bash
docker-compose up -d --build
```

---

### 9.3 Cloud Deployment on Vercel

1. Import the repository on [Vercel](https://vercel.com/).
2. Set Environment Variables under **Project Settings → Environment Variables**.
3. Deploy! Vercel automatically handles serverless API routing, CDN caching, and SSL certificate provisioning.

---

## 10. Conclusion & Future Roadmap

**ThreatVigil** demonstrates how modern web engineering, serverless architectures, and multi-source threat intelligence APIs can be combined to deliver a fast, responsive, and privacy-preserving cybersecurity scanning suite.

### Future Roadmap Enhancements:
- **Sandbox Dynamic Analysis**: Integration with CAPE or Cuckoo sandbox for automated behavioral detonation of uploaded executables.
- **Threat Graph Visualization**: Interactive force-directed node graphs linking malicious IPs, domains, and associated file hashes.
- **Browser Extension**: Manifest V3 extension providing real-time URL and QR code inspection directly inside web browsers.

---

### 👨‍💻 Project Submission Attribution

**Project Name:** ThreatVigil – Threat Intelligence & Malware Scanner  
**Developed by:** Chinthala Nani  
**Live Application:** [https://threat-detection-scanner-opal.vercel.app](https://threat-detection-scanner-opal.vercel.app)  
**GitHub Repository:** [https://github.com/chinthalanani/threat-detection-scanner](https://github.com/chinthalanani/threat-detection-scanner)  

*Built with passion for cybersecurity and threat intelligence.*
