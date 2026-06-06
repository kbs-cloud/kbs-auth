# KBS Cloud Identity (kbs-auth)

KBS Cloud Identity is a custom, lightweight Single Sign-On (SSO) authentication portal designed for games and apps in the KBS ecosystem, such as **Star-Swarm** and **Ticker-Clash**. 

The system leverages standard OAuth/SSO flows to securely authenticate users, manage active sessions, and issue signed JSON Web Tokens (JWT) for game node verification.

---

## 🌌 Key Features

1. **Dual Login Compatibility**: Log in using a standard local email and password, or use Google OAuth.
2. **Auto-Linking System**: Logging in via Google automatically links the OAuth provider with an existing local email account if registered under the same address.
3. **Password Management for OAuth**: Users registered via Google OAuth can create/set a local password, enabling them to optionally sign in using email/password or OAuth. Existing local passwords can be securely changed upon verification of their current password.
4. **Context-Sensitive Sci-Fi Styling**: Automatically switches client themes and branding based on the calling application (e.g. Neon Cyan/Yellow styling for the *Star-Swarm Terminal* secure command protocols, and Neon Pink/Green styling for the *Ticker-Clash* trader clearing systems).
5. **Master SSO Session**: Scopes cookies to permit seamless automatic authorization redirects when navigating between different client apps.
6. **SQLite Storage**: Efficient lightweight SQLite datastore managing persistent users, master sessions, and single-use authorization codes.

---

## 🛠 Tech Stack

* **Frontend**: React 19, TypeScript, Vite, Vanilla CSS (with Custom variables, CSS animations, and glassmorphism styling)
* **Backend**: Express, SQLite3 (via `sqlite3` driver), BcryptJS, Cookie-Parser, JSONWebToken, Google Auth Library
* **Process Manager**: Systemd service integration

---

## 📡 Architecture & Authentication Flows

```
 +------------------+            +------------------+            +-------------------+
 |  Game Client     |            |    SSO Portal    |            |   Game Server     |
 | (e.g. StarSwarm) |            |    (kbs-auth)    |            | (Backend Service) |
 +--------+---------+            +--------+---------+            +---------+---------+
          |                               |                                |
          | 1. Redirect to /api/authorize |                                |
          |------------------------------>|                                |
          |                               |                                |
          | 2. User logs in (SSO / OAuth) |                                |
          |                               |                                |
          | 3. Redirect back with ?code   |                                |
          |<------------------------------|                                |
          |                               |                                |
          | 4. Send auth code to backend  |                                |
          |--------------------------------------------------------------->|
          |                               |                                |
          |                               | 5. Exchange code for JWT       |
          |                               |    POST /api/auth/token        |
          |                               |<-------------------------------|
          |                               |                                |
          |                               | 6. Respond with identity JWT   |
          |                               |------------------------------->|
          |                                                                |
          | 7. User fully authenticated                                    |
          |<---------------------------------------------------------------|
```

### 🔑 Core APIs

* `GET /api/auth/authorize` - Evaluates the master SSO cookie session. If active, redirects with a single-use authorization code; otherwise, redirects the user to the portal login screen.
* `POST /api/auth/token` - Backend-to-backend token exchange. Game nodes submit the authorization code and receive the signed JWT identity token.
* `POST /api/auth/login` - Local email/password login, generating the master SSO session.
* `POST /api/auth/register` - Creates a local user account.
* `GET /api/auth/me` - Resolves the current SSO session and returns the user payload (including display name, Google linked status, and password configuration status).
* `POST /api/auth/change-password` - Allows changing or creating a local password.
* `GET /api/auth/google` & `GET /api/auth/callback/google` - Initiate and complete Google OAuth 2.0 flow.

---

## 🚀 Getting Started

### 📋 Prerequisites
* Node.js (v20+ recommended)
* NPM

### ⚙️ Installation & Setup

1. Install project dependencies:
   ```bash
   npm install
   ```

2. Configure Environment Variables. Ensure the following environment variables are loaded in `/etc/environment` or your environment manager:
   * `JWT_SECRET`: Secret key for signing identity JWTs.
   * `GOOGLE_CLIENT_ID`: Google Client ID for OAuth login.
   * `GOOGLE_CLIENT_SECRET`: Google Client Secret for OAuth login.
   * `GOOGLE_CALLBACK_URL`: Direct callback URI (e.g., `https://auth.kbs-cloud.com/api/auth/callback/google`).
   * `PORT`: Server port (defaults to `3000`).

3. Start the Development Server (concurrently spins up the Express API and Vite frontend):
   ```bash
   npm run dev
   ```
   * Open `http://localhost:8080` to view the portal.
   * Vite proxies `/api/*` requests automatically to the Express server running on port `3000`.

---

## 📦 Production Build & Deployment

The repository includes an automated `deploy.sh` script to build and deploy the application locally.

### Automated Deployment
Execute:
```bash
./deploy.sh
```

The script automates:
1. Frontend compilation (`npm run build`).
2. Staging files inside `/servers/auth`.
3. Installing production node packages (`npm ci --omit=dev`).
4. Writing the Systemd unit configuration (`/etc/systemd/system/kbs-auth.service`).
5. Reloading systemctl daemons and restarting the `kbs-auth` service.

---

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
