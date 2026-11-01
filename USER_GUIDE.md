# CwayPro — User Guide & Technical Architecture

CwayPro is a developer companion tool and server-rendered web dashboard designed to capture local code snippets, track terminal flags, encrypt sensitive configuration at rest, and stream telemetry to a centralized developer dashboard.

---

## 🛠️ Technology Stack & Architecture

| Layer | Component | Description |
| :--- | :--- | :--- |
| **Backend** | **Django 6.1 (Python 3.14)** | Classic monolithic architecture using Django Views, Django ORM, and Forms. |
| **Database** | **PostgreSQL** + **psycopg 3** | Robust relational persistence for users, projects, code files, historical revisions, and security audit logs. |
| **Authentication** | **django-allauth** + **Custom User Model** | OAuth 2.0 social authentication (**Google** & **GitHub**) alongside Personal Access Tokens (`APIToken`) for terminal CLI clients. |
| **Security & Cryptography** | **`cryptography` (Fernet)** | Symmetric envelope encryption (**AES-128 in CBC mode + HMAC-SHA256**) for at-rest code encryption. |
| **Security Translation Layer** | **Regex & Heuristic Scanners** | Automatic redaction of sensitive credentials (AWS keys, DB URIs, PATs, passwords) to prevent frontend/browser leakage. |
| **Frontend UI** | **Django Templates + Vanilla CSS** | Clean server-rendered HTML styled in the **Gruvbox Hard Dark** palette (`#1d2021`, `#282828`, `#fe8019`, `#ebdbb2`). |
| **Typography & Icons** | **Inter, Fira Code, Material Symbols** | Sans-serif typography for dashboard, monospace for code blocks, and Google Material Symbols. |
| **Static Serving** | **WhiteNoise** | High-performance static file compression and caching. |
| **Testing Suite** | **Django Test Runner** | 17 automated unit and integration tests with fast in-memory SQLite runner. |

---

## 🚀 How to Use CwayPro

### Step 1: Sign in with OAuth
1. Open your browser and navigate to `http://127.0.0.1:8000/accounts/login/`.
2. Choose **Continue with Google** or **Continue with GitHub**.
3. Once authenticated, you will be taken to your **Developer Workspace Dashboard** (`/`).

---

### Step 2: Generate an API Token for Your Terminal
Because terminal CLI tools cannot use browser cookies, CwayPro uses Personal Access Tokens:
1. In the top navigation bar, click **Tokens** (or navigate to `/tokens/`).
2. Click the **Generate New Token** button.
3. Provide a recognizable name (e.g. `Laptop Workstation`, `Ubuntu Dev Box`).
4. Click **Generate Token**.
5. **Copy your generated key** (`cwp_live_...`). For security, the full key is only displayed once!

---

### Step 3: Sync Local Code Files from the Terminal

Push files directly from your terminal using `curl` or the `cwaypro` CLI companion.

#### Standard File Push
```bash
curl -X POST http://127.0.0.1:8000/api/v1/sync/ \
  -H "Authorization: Bearer cwp_live_YOUR_TOKEN_HERE" \
  -H "Content-Type: application/json" \
  -d '{
    "project": "my-service",
    "file_path": "src/app.py",
    "content": "def main():\n    print(\"Hello CwayPro\")\n",
    "flags": {"new_file": true, "branch": "main"}
  }'
```

#### Encrypted File Push (Sensitive Files / Credentials)
Add `"encrypt": true` to encrypt the file with AES at rest in PostgreSQL:
```bash
curl -X POST http://127.0.0.1:8000/api/v1/sync/ \
  -H "Authorization: Bearer cwp_live_YOUR_TOKEN_HERE" \
  -H "Content-Type: application/json" \
  -d '{
    "project": "cloud-infra",
    "file_path": ".env.production",
    "content": "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF\nDATABASE_URL=postgres://app:secret@10.0.0.1:5432/main",
    "flags": {"encrypt": true, "new_file": true}
  }'
```

---

### Step 4: The Developer Dashboard (`/`)

The main dashboard provides an overview of your activity:
- **Telemetry Cards**: Track total **Repositories**, **Tracked Files**, **CLI Sync Events**, **Active Tokens**, and **Encrypted Files**.
- **Tracked Repositories**: Browse repositories, file counts, and visibility (`private` vs `public`). Click **+ Add** to initialize a new repository via the web UI.
- **Live CLI Sync Stream**: Chronological event feed showing file pushes and terminal flags (like `--new-file` and `--encrypt`).
- **Recently Synced Code Files**: Table of recent snippets with quick **Inspect** buttons.

---

### Step 5: File Inspection & Security Translation Layer

Click **Inspect** on any code file to open the dedicated file view:

1. **Automatic Secret Redaction**:
   - The Security Translation Layer automatically scans files for sensitive patterns (AWS Keys, Database URIs, GitHub Tokens, Passwords).
   - Any detected secrets are masked with redaction chips (e.g. `AKIA************CDEF [REDACTED_AWS_KEY]`) to prevent browser DOM and screen sharing leaks.
   - Lines with masked secrets are highlighted with a `.secret-line` visual indicator.
2. **Reveal / Mask Toggle**:
   - Click **Reveal Secrets** to view the cleartext credentials.
   - Click **Mask Secrets** before taking screenshots or sharing your screen.
   - Every unmask action is recorded in the `SecurityAuditLog`.
3. **End-to-End Encryption Banner**:
   - Encrypted files display a green **AES Encrypted at Rest** banner.
   - Click **Inspect Raw Ciphertext** to view the underlying Fernet token stored in the database.
4. **Copy Code**:
   - The **Copy Code** button copies code to your clipboard safely. If secrets are currently masked, the copied text preserves redactions to prevent clipboard leaks.
5. **Revision History**:
   - Review immutable past snapshots (`v1`, `v2`, etc.) created every time the file was synced from the terminal.

---

### Step 6: Audit & History Logs (`/history/`)

Navigate to **History** to view the full audit timeline:
- Filter events by **All Events**, **CLI Syncs**, **New Files (`--new-file`)**, or **File Updates**.
- Inspect timestamps, repository names, descriptions, and captured terminal flags.

---

## 💻 Developer Commands Cheat Sheet

```bash
# Activate virtual environment
source .venv/bin/activate

# Start local server
python manage.py runserver

# Run test suite
python manage.py test core

# Database migrations
python manage.py makemigrations core
python manage.py migrate

# Django superuser / admin access
python manage.py createsuperuser
```
