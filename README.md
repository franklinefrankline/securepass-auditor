# SecurePass Auditor – Password Strength Analysis and Security Audit System

A production-grade, cybersecurity-focused full-stack web application built with **Python (Flask)**, **PostgreSQL**, **HTML5**, **CSS3**, and **Vanilla JavaScript**. 

SecurePass Auditor evaluates password security in real time, computes strength scores from 0 to 100, detects vulnerabilities and predictable patterns, identifies commonly breached passwords, and logs immutable cryptographic audit records into PostgreSQL using **SHA-256 hashes**.

> [!IMPORTANT]
> **Zero-Knowledge Architecture**: Raw plaintext passwords are **never** stored in PostgreSQL, printed to terminal logs, cached in files, or transmitted in response payloads. Only irreversible 256-bit SHA-256 digests and calculated complexity flags are recorded.

---

## 1. Features

- **Real-Time Password Scoring (0–100)**: Evaluates complexity instantly with a 300ms debounce.
- **Dynamic Visual Strength Meter**: Real-time progress bar with color shifts:
  - `0 – 40`: **WEAK** (Crimson `#ef4444`)
  - `41 – 70`: **FAIR** (Amber `#f59e0b`)
  - `71 – 100`: **STRONG** (Emerald `#10b981`)
- **Common Password Detection**: Checks against a curated dictionary of breached passwords loaded into an in-memory Python `set` for $O(1)$ constant-time lookup. Common passwords have their score capped at 20.
- **Predictable Pattern Recognition**:
  - Consecutive character repetitions (e.g. `aaa`, `111`, `!!!`)
  - Ascending and descending numeric sequences (e.g. `123`, `4567`, `987`)
  - Keyboard walk sequences (e.g. `qwerty`, `asdf`, `zxcv`)
- **Password Analysis Checklist**: Interactive checkmarks for Uppercase, Lowercase, Numbers, Special Characters, Length $\ge 8$, and Length $\ge 12$.
- **Cryptographic Audit Logging**: Logs evaluations to PostgreSQL with SHA-256 hashes, timestamps, and character-type flags using parameterized queries.
- **Audit History Repository**:
  - Desktop table view of the latest 20 audits with truncated hashes (`8acf...91`) and timestamps.
  - Mobile-responsive card transformation preventing horizontal overflow.
  - In-place dynamic **Refresh** button staying on `/history`.
  - Direct navigation to `/` via **+ New Audit** and **Back to Password Checker**.
- **UI Customization & Settings Panel**:
  - **Themes**: Dark (Cybersecurity), Light (Clean Crisp), System Default.
  - **Accent Colors**: Blue, Purple, Green, Orange, Red (with interactive color swatches).
  - **Font Size**: Small (14px), Medium (16px), Large (18px).
  - **Layout Density**: Comfortable (spacious), Compact (dense).
  - **Strength Meter Styles**: Solid Dynamic Bar, Full Spectrum Gradient, Segmented Security Blocks.
  - **Interface Animations**: Enabled (smooth transitions) or Disabled (reduced motion).
  - **Persistent Preferences**: Saved in `localStorage` and automatically restored across page refreshes.
  - **Reset Settings**: Restores default UI preferences without modifying or deleting database audit records.
- **Fully Responsive & Touch-Friendly**:
  - Desktop ($\ge 1024$px), Tablet ($768$–$1023$px), Mobile ($< 768$px), Small Mobile ($< 480$px).
  - Touch-friendly tap targets ($\ge 44$px height), comfortable input fields, and mobile hamburger navigation drawer.
- **Security Hardening**:
  - `Content-Security-Policy`
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `X-XSS-Protection: 1; mode=block`
  - `Referrer-Policy: strict-origin-when-cross-origin`
- **Bonus Utilities**:
  - Cryptographically secure password generator (`secrets` module).
  - One-click copy to clipboard.
  - Password visibility toggle (Show/Hide).

---

## 2. Technology Stack

- **Backend**: Python 3.11+ / 3.14, Flask 3.0+
- **Database**: PostgreSQL 15+ (also supports 16, 17, 18)
- **Database Driver**: `psycopg2-binary`
- **Environment Management**: `python-dotenv`
- **Frontend**: Semantic HTML5, Vanilla CSS3 (Custom Cyber Dark Design System with CSS variables), Vanilla JavaScript (ES6+)
- **Security**: Python `hashlib` (SHA-256), `secrets`
- **Testing**: Python `unittest`

---

## 3. Application Flow & Architecture

```
                    SECUREPASS AUDITOR
                           |
             +-------------+-------------+
             |             |             |
             ▼             ▼             ▼
           Auditor       History       Settings
             |             |             |
             |             |             +--> UI customization (localStorage)
             |             |
             |             +-----------------> Latest 20 audits from PostgreSQL
             |
             +-------------------------------> Real-time score & POST /check
```

1. **User enters password** on the main page (`/`).
2. Keystrokes trigger debounced live evaluation (300ms) or clicking **CHECK PASSWORD** triggers manual audit.
3. Backend validates input, evaluates complexity, detects patterns/common passwords, generates a SHA-256 hash, and inserts the audit record into PostgreSQL.
4. JSON result updates the UI in place without page redirect.
5. User clicks **View History** to inspect `/history` or **Settings** to customize theme, accent color, and layout.

---

## 4. Project Structure

```
Password Strength Auditor/
│
├── app.py                  # Flask routes, API controllers, secure headers
├── scorer.py               # Password complexity engine & pattern analyzer
├── db.py                   # PostgreSQL connection & parameterized SQL queries
├── init_db.py              # CLI database schema initialization script
├── schema.sql              # Database DDL for audit_log table and indexes
├── common_passwords.txt    # Curated dictionary of common passwords
├── requirements.txt        # Python package dependencies
├── README.md               # Complete project documentation
├── .gitignore              # Git ignore file (safeguards .env and caches)
├── .env.example            # Environment configuration template
│
├── templates/
│   ├── index.html          # Main auditor interface & Settings modal
│   └── history.html        # Immutable audit history repository & Settings modal
│
├── static/
│   ├── style.css           # Vanilla CSS design system with CSS custom properties
│   └── app.js              # Real-time evaluation, navigation, and settings engine
│
└── tests/
    └── test_auditor.py     # Automated test suite (22 unit & integration tests)
```

---

## 5. Windows Setup & Installation (No Docker Required)

### Step 1: Clone or Navigate to the Project
```powershell
cd "d:\Password Strength Auditor"
```

### Step 2: Create and Activate Virtual Environment
```powershell
# Create virtual environment
python -m venv venv

# Activate virtual environment in PowerShell
.\venv\Scripts\Activate.ps1
```

### Step 3: Install Dependencies
```powershell
pip install -r requirements.txt
```

### Step 4: Create PostgreSQL Database & Schema
Ensure PostgreSQL is running, then run `psql` to create the database:
```powershell
# Adjust path to your PostgreSQL psql.exe version if needed
& "C:\Program Files\PostgreSQL\18\bin\psql.exe" -U postgres -c "CREATE DATABASE password_auditor;"
```
Apply `schema.sql`:
```powershell
& "C:\Program Files\PostgreSQL\18\bin\psql.exe" -U postgres -d password_auditor -f schema.sql
```
*Or initialize via the included Python utility:*
```powershell
python init_db.py
```

### Step 5: Configure Environment Variables
Copy `.env.example` to `.env`:
```powershell
Copy-Item .env.example .env
```
Ensure `.env` contains your PostgreSQL credentials:
```env
FLASK_ENV=development
FLASK_DEBUG=1
SECRET_KEY=dev-secret-key-change-in-production
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/password_auditor
```

---

## 6. Running the Application

Start the Flask development server:
```powershell
python app.py
```

Navigate to:
* **Auditor Main Dashboard**: [http://127.0.0.1:5000/](http://127.0.0.1:5000/)
* **Audit History**: [http://127.0.0.1:5000/history](http://127.0.0.1:5000/history)
* **Health Endpoint**: [http://127.0.0.1:5000/health](http://127.0.0.1:5000/health)

---

## 7. API Documentation

### `POST /check`
Analyzes password complexity, calculates score, checks dictionary and patterns, generates SHA-256 hash, and logs the audit.

**Request:**
```http
POST /check HTTP/1.1
Content-Type: application/json

{
    "password": "ExamplePassword123!",
    "log_audit": true
}
```

**Response (HTTP 200 OK):**
```json
{
    "score": 85,
    "level": "STRONG",
    "issues": [
        "Avoid sequential numbers"
    ],
    "suggestions": [
        "Avoid consecutive numeric sequences like 123 or 987"
    ],
    "length": 19,
    "has_upper": true,
    "has_lower": true,
    "has_digit": true,
    "has_symbol": true,
    "is_common": false,
    "truncated_hash": "b2f6c91a...390e",
    "logged": true
}
```

---

### `GET /history`
Returns the latest 20 audit evaluations.
- If requested by browser: renders `history.html`.
- If requested with `Accept: application/json`: returns JSON `{"history": [...]}`.

---

### `GET /health`
Smoke test endpoint returning service and database connectivity:
```json
{
    "status": "ok",
    "database": "connected",
    "message": "Database connection operational"
}
```

---

### `POST /generate`
Generates a cryptographically strong random password using Python's `secrets` module:
```json
{
    "generated_password": "k9#R!vQ8&mZx$2P@"
}
```

---

## 8. Scoring Algorithm Specifications

Scores range strictly between **0 and 100**:

| Criteria | Points |
| :--- | :--- |
| **Length $\ge$ 8** | +20 |
| **Length $\ge$ 12** | +10 |
| **Uppercase letter (A–Z)** | +15 |
| **Lowercase letter (a–z)** | +15 |
| **Numeric digit (0–9)** | +15 |
| **Special character** | +25 |
| **Repeated characters deduction** (e.g. `aaa`, `111`) | -10 |
| **Numeric sequence deduction** (e.g. `123`, `4567`) | -5 |
| **Keyboard pattern deduction** (e.g. `qwerty`, `asdf`) | -10 |
| **Common password detected** | **Score strictly capped at 20** |

---

## 9. Database Security Verification

To verify that **no raw passwords** are ever saved into PostgreSQL:
```powershell
& "C:\Program Files\PostgreSQL\18\bin\psql.exe" -U postgres -d password_auditor -c "SELECT id, password_hash, score, length, is_common, checked_at FROM audit_log;"
```
*Result: Only irreversible 64-character SHA-256 hex strings and complexity metrics are stored.*

---

## 10. Automated Tests

Run the complete 22-test automated test suite:
```powershell
python -m unittest tests/test_auditor.py -v
```

---

## 11. License

MIT License. Designed for cybersecurity education, auditing, and secure full-stack web engineering.
