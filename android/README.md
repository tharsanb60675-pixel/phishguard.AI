# PhishGuard.AI Android Companion App 🛡️📱

The native Android companion application for **PhishGuard.AI Real-Time Background Threat & QR Shield**.

Synchronizes seamlessly with your laptop browser extension over an encrypted Server-Sent Events (SSE) stream to provide dual-screen threat monitoring and high-risk push notifications.

---

## 🌟 Key Features

1. **Real-Time Cross-Device Sync**:
   - As soon as you press `Ctrl + Shift + Q` on your laptop, the decoded QR payload and threat score stream immediately to this Android companion.
2. **Instant High-Risk Push Alerts**:
   - `CRITICAL` and `HIGH RISK` QR threats automatically dispatch an Android system notification.
3. **One-Time Secure Pairing**:
   - Pair via 6-digit one-time code or QR code generated on your laptop.
4. **Offline Threat History**:
   - Caches previous threat detections for quick offline review.

---

## 🛠️ Architecture

- **UI Framework**: Modern declarative UI with **Jetpack Compose** & Material 3 Dark Theme.
- **Networking**: **OkHttp SSE (Server-Sent Events)** for real-time live event streaming from `http://localhost:8000/api/v1/devices/events`.
- **Notifications**: `NotificationManagerCompat` with high-priority channels and action intents.
- **Local Persistence**: **Room DB** for offline threat ledger caching.

---

## 🚀 How to Run & Test

### Option A: Using the Built-In Web Android Simulator
You can test the exact Android companion experience directly inside the web platform without opening Android Studio:
1. Start the PhishGuard web app: `http://localhost:5173`
2. Open **[http://localhost:5173/android-companion](http://localhost:5173/android-companion)**
3. Press `Ctrl + Shift + Q` in any browser tab with the extension installed — watch the mobile screen update and dispatch real-time alerts live!

### Option B: Build with Android Studio
1. Open the `android/` directory in **Android Studio Hedgehog / Iguana / Jellyfish**.
2. Sync Gradle dependencies.
3. Launch an Android Emulator (API 26+) or connect a physical Android device via USB debugging.
4. If testing on the standard Android emulator, the server URL defaults to `http://10.0.2.2:8000/api/v1`.
5. Enter your laptop's 6-digit pairing code from the **Background Protection** page to link.
