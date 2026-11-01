# MailGuard1 — Email Security, Authentication & Gmail Threat Intelligence

MailGuard1 is an email security application designed to inspect incoming emails and detect phishing, fraudulent domain spoofing, and bulk spam attacks before they compromise user security. It features secure Google OAuth 2.0 login/signup, explicit least-privileged Gmail API integration (`gmail.readonly`), at-rest token encryption, and a modular threat heuristic engine.

---

## 1. System Architecture

```
MailGuard1/
│
├── MailGuard (4).html        # Main dashboard UI (HTML, CSS, SVG, layout)
├── MailGuard (4).original.html# Pristine backup copy of the original HTML
├── login.html                # Dedicated login page matching MailGuard design system
├── signup.html               # Dedicated signup page matching MailGuard design system
├── mailguard-api.js          # Separate frontend-to-backend API integration
├── mailguard.db              # SQLite database (Users, Sessions, Gmail Connections, Scans)
├── requirements.txt          # Python dependencies
├── .env.example              # Environment variables template
├── .gitignore                # Git exclusions
├── README.md                 # Project documentation & runbook
│
├── backend/
│   ├── __init__.py           # Package marker
│   ├── config.py             # Pydantic configuration, Google OAuth & session settings
│   ├── database.py           # SQLAlchemy SQLite engine & auto-migration
│   ├── models.py             # ORM entities (User, UserSession, GmailConnection, OAuthState, ScanRecord, AppConfig)
│   ├── schemas.py            # Pydantic request/response validation schemas
│   ├── main.py               # FastAPI application setup, middleware, and router mounting
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── health.py         # GET /api/health, GET /api
│   │   ├── auth.py           # Google Login, Callback, /api/auth/me, /api/auth/logout
│   │   ├── gmail.py          # Connect Gmail, Callback, /api/gmail/status, /api/gmail/scan, /api/gmail/disconnect
│   │   ├── scan.py           # POST /api/scan, POST /api/scan/receive, GET/POST /api/scan/{id}
│   │   ├── history.py        # GET /api/history, DELETE /api/history/{id}
│   │   └── dashboard.py      # GET /api/dashboard/stats, PUT /api/dashboard/threshold
│   └── services/
│       ├── __init__.py
│       ├── crypto.py         # Fernet token encryption at rest
│       ├── auth_service.py   # Server-side sessions and get_current_user dependencies
│       ├── google_auth.py    # Google OAuth 2.0 authorization, CSRF state validation, and profile retrieval
│       ├── gmail_service.py  # Official Gmail API client, MIME body parsing, and security scanning
│       ├── detector.py       # Modular heuristic baseline threat detection engine
│       └── scan_service.py   # Business logic, metrics aggregation, and DB persistence
│
└── tests/
    ├── __init__.py
    ├── conftest.py           # In-memory SQLite fixtures and TestClient setup
    ├── test_auth.py          # User creation, repeat login, session persistence, and logout tests
    ├── test_gmail.py         # Token encryption, Gmail connection, MIME parsing, and scanner tests
    ├── test_health.py        # Health endpoint, API root, and frontend serving tests
    ├── test_detector.py      # Spam, phishing, attachment, and brand heuristic tests
    ├── test_scan.py          # Scan creation, input validation, and restore tests
    └── test_history_and_db.py# History partitioning and dashboard KPI persistence tests
```

---

## 2. Authentication vs. Gmail Access

MailGuard strictly separates identity verification from mailbox permissions:

1. **Signing In / Signing Up**:
   * Uses Google OAuth 2.0 / OpenID Connect (`openid email profile`).
   * Verifies the user's stable Google subject identifier (`sub`) and email address.
   * Creates a secure server-side session stored in an `HttpOnly`, `SameSite=Lax` cookie.
   * **Does not grant access to the user's Gmail mailbox**.
2. **Connecting Gmail**:
   * Initiated only when the user explicitly clicks **"Connect Gmail"** on the dashboard.
   * Requests the minimum necessary permission: `https://www.googleapis.com/auth/gmail.readonly`.
   * Never requests send, delete, or manage permissions.
   * Refresh tokens are encrypted at rest using **Fernet symmetric encryption** before being stored in SQLite.
   * Users can disconnect at any time, which deletes stored tokens and revokes the grant with Google.

---

## 3. Google Cloud OAuth & Gmail API Setup Guide

To enable real Google authentication and live Gmail scanning:

### Step 1: Create a Google Cloud Project
1. Go to the [Google Cloud Console](https://console.cloud.google.com/).
2. Click the project dropdown at the top and select **New Project**. Name it `MailGuard1` and click **Create**.

### Step 2: Enable the Gmail API
1. In the Google Cloud Console, navigate to **APIs & Services** > **Library**.
2. Search for **Gmail API**, select it, and click **Enable**.

### Step 3: Configure the OAuth Consent Screen
1. Go to **APIs & Services** > **OAuth consent screen**.
2. Select **External** (or Internal if using Google Workspace) and click **Create**.
3. Fill in the required app details:
   * **App name**: `MailGuard`
   * **User support email**: Your email address
   * **Developer contact email**: Your email address
4. Click **Save and Continue**.
5. Under **Scopes**, click **Add or Remove Scopes** and add:
   * `openid`
   * `.../auth/userinfo.email`
   * `.../auth/userinfo.profile`
   * `https://www.googleapis.com/auth/gmail.readonly`
6. Under **Test users**, add your own Gmail address (since the app is in Testing mode).
7. Save and complete the consent screen configuration.

### Step 4: Create OAuth 2.0 Client Credentials
1. Go to **APIs & Services** > **Credentials**.
2. Click **Create Credentials** > **OAuth client ID**.
3. Select Application type: **Web application**.
4. Set Name to `MailGuard Web Client`.
5. Under **Authorized redirect URIs**, add:
   * `http://127.0.0.1:8000/api/auth/google/callback`
   * `http://127.0.0.1:8000/api/gmail/callback`
6. Click **Create** and copy your **Client ID** and **Client Secret**.

### Step 5: Configure Environment Variables
Copy `.env.example` to `.env` in the `MailGuard1` folder:
```powershell
Copy-Item .env.example .env
```
Open `.env` and fill in your credentials:
```env
GOOGLE_CLIENT_ID=your_client_id_here.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your_client_secret_here
GOOGLE_REDIRECT_URI=http://127.0.0.1:8000/api/auth/google/callback
GOOGLE_GMAIL_REDIRECT_URI=http://127.0.0.1:8000/api/gmail/callback
SESSION_SECRET=a_random_secure_secret_string
TOKEN_ENCRYPTION_KEY=
```

---

## 4. Running the Application (PowerShell)

### Step 1: Open Terminal in Project Directory
```powershell
cd "c:\Users\raj patil\OneDrive\Desktop\mini pjt\MailGuard1"
```

### Step 2: Activate the Virtual Environment
```powershell
.\.venv\Scripts\Activate.ps1
```

### Step 3: Start the Backend Server
```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

### Step 4: Access MailGuard1
* **Web App**: [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
* **Sign In Page**: [http://127.0.0.1:8000/login](http://127.0.0.1:8000/login)
* **Sign Up Page**: [http://127.0.0.1:8000/signup](http://127.0.0.1:8000/signup)
* **API Documentation (Swagger UI)**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

## 5. Running Automated Tests

Run the complete test suite (32 tests across auth, Gmail, detector, database, and health):
```powershell
.\.venv\Scripts\python.exe -m pytest -v
```
All tests use mocked Google API responses and an isolated in-memory SQLite database, requiring no live Google Cloud credentials to verify.

---

## 6. API Endpoints Reference

### Authentication
* `GET /api/auth/google/login`: Initiates Google OAuth login flow with CSRF protection.
* `GET /api/auth/google/callback`: Processes Google callback, creates user, and sets HttpOnly session cookie.
* `GET /api/auth/me`: Returns authenticated user profile and Gmail connection status.
* `POST /api/auth/logout`: Invalidates server session and clears session cookie.

### Gmail Integration
* `GET /api/gmail/connect`: Initiates OAuth flow for `gmail.readonly` permission.
* `GET /api/gmail/callback`: Stores encrypted refresh token and links Gmail account to user.
* `GET /api/gmail/status`: Returns current Gmail connection status.
* `POST /api/gmail/scan`: Fetches recent messages, runs phishing/spam analysis, and saves results.
* `POST /api/gmail/disconnect`: Revokes Google OAuth token and deletes connection from database.

### Email Scanning & History
* `POST /api/scan`: Analyze manual email and persist scan record.
* `POST /api/scan/receive`: Analyze simulated incoming email.
* `GET /api/history`: List scan records for Inbox or Quarantine (user-scoped if logged in).
* `DELETE /api/history/{scan_id}`: Remove an individual scan record from history.
* `GET /api/dashboard/stats`: Retrieve threat metrics, 7-day trend chart data, and repeat offenders.

### Dashboard Metrics
The dashboard reports **baseline + live** metrics. A fixed historical baseline (mirroring the
original MailGuard demo state) is always included so the trend chart, threat mix, and repeat
offender list are populated on a fresh install:

| Metric | Baseline source |
| --- | --- |
| `scanned` | `BASELINE_SCANNED` (1240) + number of live scan records |
| `days` | `BASELINE_DAYS` (7 × `[spam_blocked, fraud_blocked]`) + live blocked scans |
| `offenders` | `BASELINE_OFFENDERS` + live blocked scans grouped by sender domain |
| `threat_mix` / `threats_blocked_7d` | Derived from the merged `days` buckets |
| `fraud_pct` | Derived from the merged `days` buckets |
| `avg_latency_ms` | Derived from live scan records only (no baseline latency data) |

Live scans are always **layered on top of** the baseline rather than replacing it, and the
baseline constants are never mutated between requests. The constants are defined in
`backend/services/scan_service.py` and can be adjusted to match a deployment's history.