# Password Strength Auditor

A production-grade, cybersecurity-focused web application built with **Python (Flask)**, **PostgreSQL**, **HTML5**, **CSS3**, and **Vanilla JavaScript**. 

The application analyzes password security in real time, computes strength scores from 0 to 100, detects weaknesses and predictable patterns, identifies commonly breached passwords, and logs immutable cryptographic audit records into PostgreSQL using **SHA-256 hashes**.

> [!IMPORTANT]
> **Zero-Knowledge Architecture**: Raw plaintext passwords are **never** stored in PostgreSQL, printed to terminal logs, cached in files, or transmitted in response payloads. Only irreversible 256-bit SHA-256 digests and calculated complexity flags are recorded.

---

## 1. Features

- **Real-Time Password Scoring (0–100)**: Evaluates complexity instantly with a 300ms debounce.
- **Dynamic Visual Strength Meter**: Real-time progress bar with color shifts:
  - `0 – 40`: **WEAK** (Crimson `#ef4444`)
  - `41 – 70`: **FAIR** (Amber `#f59e0b`)
  - `71 – 100`: **STRONG** (Emerald `#10b981`)
- **Common Password Detection**: Checks against a curated dictionary of breached passwords loaded in an in-memory Python `set` for $O(1)$ constant-time lookup. Common passwords have their score capped at 20.
- **Predictable Pattern Recognition**:
  - Consecutive character repetitions (e.g. `aaa`, `111`, `!!!`)
  - Ascending and descending numeric sequences (e.g. `123`, `4567`, `987`)
  - Keyboard walk sequences (e.g. `qwerty`, `asdf`, `zxcv`)
- **Security Requirements Checklist**: Interactive checkmarks for Length $\ge 8$, Length $\ge 12$, Uppercase, Lowercase, Numbers, and Special Characters.
- **Cryptographic Audit Logging**: Logs evaluations to PostgreSQL with SHA-256 hashes, timestamps, and character-type flags using parameterized queries.
- **Audit History Repository**: Responsive table viewing the latest 20 audits with truncated hashes (`8acf...91`) and timestamps.
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
- **Frontend**: Semantic HTML5, Vanilla CSS3 (Custom Cyber Dark Design System), Vanilla JavaScript (ES6+)
- **Security**: Python `hashlib` (SHA-256), `secrets`
- **Testing**: Python `unittest`

---

## 3. Project Structure

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
│   ├── index.html          # Main auditor interface
│   └── history.html        # Immutable audit history page
│
├── static/
│   ├── style.css           # Vanilla CSS cybersecurity design system
│   └── app.js              # Real-time debounced evaluation & DOM updates
│
└── tests/
    └── test_auditor.py     # Automated test suite (scoring, API, headers)
```

---

## 4. Windows Setup & Installation (No Docker Required)

### Step 1: Install Python
Ensure Python 3.11 or higher is installed and available in your PATH:
```powershell
py --version
# or
python --version
```

### Step 2: Install PostgreSQL
Ensure PostgreSQL is installed and the service is running:
```powershell
Get-Service -Name *postgres*
```

### Step 3: Create the Database
Launch PostgreSQL CLI (`psql`) as the `postgres` administrative user:
```powershell
& "C:\Program Files\PostgreSQL\18\bin\psql.exe" -U postgres
```
Create the `password_auditor` database:
```sql
CREATE DATABASE password_auditor;
\q
```

### Step 4: Configure Environment Variables
Copy `.env.example` to `.env`:
```powershell
Copy-Item .env.example .env
```
Open `.env` and configure your PostgreSQL username and password:
```env
FLASK_ENV=development
FLASK_DEBUG=1
SECRET_KEY=cybersecurity-super-secret-key
DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@localhost:5432/password_auditor
```
*(Replace `YOUR_PASSWORD` with your PostgreSQL password).*

### Step 5: Create and Activate Virtual Environment
```powershell
# Create virtual environment
py -m venv venv

# Activate virtual environment
.\venv\Scripts\Activate.ps1
```

### Step 6: Install Dependencies
```powershell
pip install -r requirements.txt
```

### Step 7: Initialize Database Schema
Run the initialization script or apply `schema.sql` directly:
```powershell
python init_db.py
```
*Or using psql:*
```powershell
& "C:\Program Files\PostgreSQL\18\bin\psql.exe" -U postgres -d password_auditor -f schema.sql
```

---

## 5. Running the Application

Start the Flask development server:
```powershell
python app.py
```

Open your browser and navigate to:
```
http://127.0.0.1:5000
```

To view the audit history:
```
http://127.0.0.1:5000/history
```

To run a health check:
```
http://127.0.0.1:5000/health
```

---

## 6. API Documentation

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
- If requested with `Accept: application/json` or `?format=json`: returns JSON.

**Response (JSON):**
```json
{
    "history": [
        {
            "id": 1,
            "password_hash": "b2f6c91a...390e",
            "score": 85,
            "strength": "Strong",
            "length": 19,
            "has_upper": true,
            "has_lower": true,
            "has_digit": true,
            "has_symbol": true,
            "is_common": false,
            "checked_at": "2026-09-11T10:00:00"
        }
    ]
}
```

---

### `GET /health`
Smoke test endpoint verifying application and database connectivity.

**Response:**
```json
{
    "status": "ok",
    "database": "connected",
    "message": "Database connection operational"
}
```

---

### `POST /generate`
Generates a cryptographically strong random password using Python's `secrets` module.

**Response:**
```json
{
    "generated_password": "k9#R!vQ8&mZx$2P@"
}
```

---

## 7. Scoring Algorithm Specifications

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
| **Common password detected** | **Score capped at 20** |

---

## 8. Security Concepts & Hardening

1. **SHA-256 One-Way Hashing**:
   Passwords undergo SHA-256 hashing via `hashlib.sha256(password.encode('utf-8')).hexdigest()`. The raw password is never stored or echoed back.
2. **Parameterized SQL Queries**:
   All database operations use `%s` parameter placeholders with `psycopg2`. No SQL injection vulnerabilities are possible.
3. **Defense-in-Depth HTTP Headers**:
   - `Content-Security-Policy`: Blocks untrusted script sources.
   - `X-Content-Type-Options: nosniff`: Prevents MIME confusion attacks.
   - `X-Frame-Options: DENY`: Prevents UI redressing / clickjacking.
   - `Referrer-Policy: strict-origin-when-cross-origin`: Restricts sensitive referrer leakage.
4. **Environment Isolation**:
   Credentials reside in `.env`, which is strictly excluded from version control via `.gitignore`.

---

## 9. Running Automated Tests

Run the automated test suite verifying scoring logic, pattern checks, API routes, and security headers:

```powershell
python -m unittest tests/test_auditor.py -v
```

---

## 10. Git / GitHub Setup

Initialize git repository and dev branch:
```powershell
# Initialize git
git init

# Verify that .env is ignored
git status

# Add and commit
git add .
git commit -m "Initial Password Strength Auditor project"

# Switch to development branch
git checkout -b dev
```

Verify that `.env` was never tracked:
```powershell
git log -- .env
```
*(Should return empty, proving credentials were never committed).*

---

## 11. License

MIT License. Designed for cybersecurity education, auditing, and secure full-stack web engineering.
