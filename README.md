KPass
=====

Self-hosted password manager with a FastAPI backend and static HTML frontend.

Security notes:

- Account passwords are hashed with bcrypt through Passlib.
- Saved website passwords are encrypted with Fernet before they are stored.
- A separate master password is required before saved website passwords can be revealed.
- `JWT_SECRET_KEY` and `FERNET_KEY` must come from environment variables or a server-only `.env` file.
- Do not commit `.env`, database files, virtual environments, private keys, or generated caches.

Local backend setup:

```powershell
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
Copy-Item .env.example .env
uvicorn app.main:app --reload
```

Update `.env` with a strong `JWT_SECRET_KEY` and the generated `FERNET_KEY` before starting the app.

Frontend:

Open `frontend/index.html` directly during local development, or serve the `frontend` directory behind the same host as the API. When served over HTTP(S), the frontend calls `/api` on the current origin. For a different API host, define `window.KPASS_API_BASE` before loading `frontend/js/api.js`.

Deployment direction:

- Run the backend on the Ubuntu VM behind a process manager such as systemd.
- Serve the frontend and reverse proxy `/api` to Uvicorn with Nginx or Caddy.
- Keep the real `.env` only on the server.
- Expose the site through Cloudflare Tunnel for `subdomain.karlo-cavlovic.dev`.

2FA status:

The user model has `two_factor_enabled` and `two_factor_secret` fields reserved for TOTP. The setup/verification endpoints are intentionally still pending.
