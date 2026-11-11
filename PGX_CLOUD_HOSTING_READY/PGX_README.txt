PGX CLOUD - UPDATED HOSTING PANEL
=================================

What was updated
----------------
- Rebranded the existing interface to PGX CLOUD (neon purple/blue styling).
- Preserved the existing Flask/Python hosting backend and existing project folders.
- Admin login uses the existing enabled admin record in users.json.
- This package does not reset or publish an admin password; use the current
  password already associated with your admin account.
- Added multiple-admin creation from the admin dashboard.
- Added live host CPU/RAM/disk overview.
- Added project inventory with per-project RAM/disk/CPU settings.
- Added an admin project inspector for project files, SQLite database tables
  and row counts, and the latest output.log lines.
- Added an admin activity audit log.
- Added login/session checks for project APIs and path checks for file operations
  and ZIP extraction.
- Added RAM monitoring for bot processes. A process is stopped if its measured
  resident memory exceeds its configured RAM value.
- Disabled Flask debug mode and added a persistent generated session secret.
- Added missing `psutil` and `requests` dependencies.

Run
---
1. Install Python 3.9+.
2. In the project directory run:
      python -m pip install -r requirements.txt
3. Start:
      python app.py
4. Open your deployed domain and visit /login.
5. Sign in with the admin username and password already stored in users.json.
   Do not assume a default password; this archive does not reset credentials.

IMPORTANT SECURITY / CAPACITY NOTES
-----------------------------------
- Change the initial SYCO password immediately after first login and keep the
  server private until the deployment is hardened.
- This application executes customer Python projects as child processes of the
  Flask service. It is NOT an OS/container sandbox. Do not offer public,
  untrusted multi-tenant hosting on a production server until projects are
  isolated using Docker/containerd or separate OS users with strict CPU, RAM,
  filesystem and network policies.
- RAM is monitored and over-limit processes are stopped, but this is not a
  hard kernel memory cgroup limit. There can be a short monitoring delay.
- CPU is monitored by the existing process monitor. Disk allocation is currently
  a plan/configuration value, not an enforced filesystem quota.
- A payment gateway and automated purchase/renewal workflow are not connected.
  They require a provider account and payment integration.
- The legacy `/api/create` provisioning endpoint is blocked for non-admin
  visitors by the request authorization guard.
- `users.json`, `bots/`, SQLite databases and project logs are retained in this
  package. The app migrates the legacy admin record only when it first loads.

Existing bot source, database and output files have not been intentionally
rewritten as part of this update.


GOOGLE LOGIN + FREE CLAIM UPDATE
--------------------------------
- User Google OAuth login is available from the landing/login pages.
- Verified Gmail, Google subject ID, display name, first/last login and login count are saved in google_accounts.json. No Google password or access token is stored.
- The same verified email and Google subject are linked to the user record in users.json. Existing user/project records are retained.
- Free Claim now runs inside PGX CLOUD. A Google account can claim one free Python project (1GB RAM allocation, 1GB disk allocation, 30% CPU plan, 3 days). Duplicate claims are blocked.
- Admin can view Gmail records in the Google Login Accounts section; the endpoint is admin-only.

Required environment variables
------------------------------
GOOGLE_CLIENT_ID=your-google-oauth-client-id
GOOGLE_CLIENT_SECRET=your-google-oauth-client-secret
GOOGLE_REDIRECT_URI=https://YOUR-DOMAIN/auth/google/callback
PGX_SECRET_KEY=use-a-long-random-secret
PGX_COOKIE_SECURE=1 (recommended when deployed over HTTPS)
PORT=5000 (optional; hosting provider may set this automatically)

In Google Cloud Console, configure the OAuth consent screen and add the exact deployed callback URL above to Authorized redirect URIs. Never put the client secret in HTML or commit it to the ZIP.

Deploy with a production WSGI server where supported, for example: gunicorn app:app. The app binds to 0.0.0.0 and reads PORT from the environment.
- `google_accounts.json` is created automatically on the first successful Google sign-in. Keep this file with the deployment data; it contains Gmail account records used by the admin view.
- Do not upload `.env` or expose `GOOGLE_CLIENT_SECRET` in frontend code. `.env.example` is a template only.
