# PhishGuard.AI — Real-Time Background QR Threat Detection & Quishing Shield 🛡️⚡

An enterprise-grade, real-time cybersecurity platform and browser extension for zero-day phishing, quishing (QR-code phishing), and social engineering threat mitigation with Explainable AI (SHAP) and cross-device Android synchronization.

---

## 🚀 Key Features

### 1. Real-Time Visible Tab QR Shield (`Ctrl + Shift + Q`)
- **Single-Shortcut Activation**: Press `Ctrl + Shift + Q` on any webpage (WhatsApp Web, Gmail, Instagram, Banking portals, Discord).
- **Privacy-First In-Memory Capture**: Captures **only the visible active browser tab** in memory (never the OS desktop).
- **Multi-Source QR Decoder**: Automatically detects and decodes QR codes inside images, HTML5 `<canvas>`, SVGs, or dynamically rendered DOM elements.
- **Normalized Threat Scoring (0–100)**:
  - `0 - 20`: **SAFE**
  - `21 - 40`: **LOW RISK**
  - `41 - 60`: **SUSPICIOUS**
  - `61 - 80`: **HIGH RISK**
  - `81 - 100`: **CRITICAL**
- **In-Page Cyberpunk HUD**: Renders glowing bounding box overlays directly over webpage QR codes and a modern floating HUD card with clear, human-readable security reasons.
- **Automatic Navigation Blocking**: Automatically intercepts and blocks navigation if `threatScore >= 80`.

### 2. Dual-Screen Android Companion Synchronization
- **Encrypted Real-Time Event Stream**: Streams live scan results from your laptop browser to your paired Android mobile over Server-Sent Events (SSE).
- **Instant High-Risk Push Alerts**: Dispatches native Android notifications for `HIGH RISK` and `CRITICAL` quishing lures.
- **One-Time Pairing Protocol**: Securely pair laptop with Android using a 6-digit one-time code or QR code.
- **Web & Native Support**: Includes both native Jetpack Compose Kotlin codebase (`android/`) and built-in interactive web simulator (`/android-companion`).

### 3. Persistent Database Architecture
- **Single Source of Truth**: SQLite relational database (`backend/phishguard.db`).
- **Audit Tables**:
  - `qr_scans`: Scan telemetry, page URLs, payload types, normalized threat scores, severity, and block status.
  - `threat_analysis`: Deep technical indicators (HTTPS, IP address, Punycode, TLD risk, credential harvesting keywords).
  - `paired_devices`: Registered Android companion devices and active tokens.
  - `users`: User identity, hashed passwords (bcrypt), and adaptive risk profile tiers.

---

## 📂 Project Architecture

```text
phishguard-ai/
├── extension/                     # Manifest V3 Chrome Extension
│   ├── manifest.json              # Extension manifest with Ctrl+Shift+Q command
│   ├── background.js              # Background service worker (tab capture & API caller)
│   ├── content.js                 # In-page radar HUD, jsQR decoder & bounding boxes
│   ├── content.css                # Cyberpunk glassmorphism styles & animations
│   ├── popup.html / popup.js      # Extension popup with quick scan & live stats
│   ├── options.html / options.js  # Settings & Android pairing manager
│   └── jsqr.js                    # In-memory QR code decoder
│
├── backend/                       # FastAPI High-Performance Python Backend
│   ├── app/
│   │   ├── models/                # SQLAlchemy models (qr_scans, paired_devices, users)
│   │   ├── services/              # QR threat engine & SSE device sync manager
│   │   ├── api/v1/routes/         # REST & SSE endpoints (/qr, /devices, /auth, /scan)
│   │   └── core/                  # Security (bcrypt, JWT) & config
│   ├── phishguard.db              # SQLite Database
│   └── run.py                     # Backend server entrypoint (Port 8000)
│
├── frontend/                      # React / Vite Modern Cyber SOC Dashboard
│   ├── src/
│   │   ├── pages/
│   │   │   ├── BackgroundProtection.jsx  # Live QR Shield dashboard & pairing generator
│   │   │   ├── AndroidCompanion.jsx      # Mobile Companion Simulator
│   │   │   ├── Scanner.jsx               # Universal Threat Scanner & SHAP explainer
│   │   │   └── QRScanner.jsx             # Dedicated QR Code Camera/Upload Scanner
│   └── package.json
│
└── android/                       # Native Android Companion App (Jetpack Compose)
    ├── app/src/main/
    │   ├── AndroidManifest.xml
    │   └── java/ai/phishguard/companion/
    │       ├── MainActivity.kt           # Jetpack Compose UI
    │       ├── networking/SseClient.kt   # OkHttp SSE Live Event Listener
    │       └── notifications/NotificationHelper.kt # Push alerts
    └── README.md
```

---

## 🛠️ How to Run & Test Everything

### Step 1: Start Backend & Frontend
Both servers run concurrently:
```powershell
# 1. Backend Server (Port 8000)
cd c:\Users\VICTUS\zero\backend
& "c:\Users\VICTUS\zero\backend\.venv\Scripts\python.exe" run.py

# 2. Frontend Dev Server (Port 5173)
cd c:\Users\VICTUS\zero\frontend
npm run dev
```

- **Frontend Dashboard**: [http://localhost:5173](http://localhost:5173)
- **Interactive Backend API Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Direct Database Inspector**: [Open phishguard.db in DB Browser for SQLite](file:///c:/Users/VICTUS/zero/open_phishguard_db.bat)

---

### Step 2: Load the Browser Extension in Chrome / Edge / Brave

1. Open your browser and navigate to `chrome://extensions/` (or `edge://extensions/`).
2. Toggle on **"Developer mode"** in the top-right corner.
3. Click **"Load unpacked"**.
4. Select the directory:
   ```text
   C:\Users\VICTUS\zero\extension
   ```
5. The **PhishGuard AI** extension is now installed and active!

---

### Step 3: Test Real-Time QR Detection (`Ctrl + Shift + Q`)

1. Open any webpage containing a QR code (e.g. WhatsApp Web, a website login, or an image search for QR codes).
2. Press:
   ```text
   Ctrl + Shift + Q
   ```
3. Watch the real-time workflow execute automatically:
   - **Radar HUD** pulses: *"Scanning visible page for QR threats..."*
   - **Bounding Box** highlights the QR code directly on the webpage.
   - **HUD Result Card** displays the Threat Level, Normalized Score (e.g. `87/100`), Classification, and Explanatory Reasons.
   - If the code is high-risk/malicious (`Threat Score >= 80`), navigation is **automatically blocked**.
   - The scan is persisted into SQLite `qr_scans` table and streamed live to your Android companion!

---

### Step 4: Test Android Companion Dual-Screen Sync

1. Open **[http://localhost:5173/android-companion](http://localhost:5173/android-companion)** on your laptop (or run the native app from `android/`).
2. Trigger any scan using `Ctrl + Shift + Q` or the extension popup.
3. The Android companion will instantly receive the live event via SSE and show the real-time card and push notification!

---

## 🧪 Automated Tests

Run the full automated test suite anytime:
```powershell
& "c:\Users\VICTUS\zero\backend\.venv\Scripts\python.exe" "c:\Users\VICTUS\zero\backend\test_qr_shield_e2e.py"
```
All unit heuristics, multi-code scoring, database persistence, pairing flows, and privacy deletions are 100% verified.
