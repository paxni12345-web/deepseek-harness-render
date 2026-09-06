# DeepSeek Harness (dsh) on Render — deploy wrapper

Runs the DeepSeek Harness web UI (**`@deepseek-ai/dsh`**) as an always-on Render
Web Service, headless/non-interactive, with GitHub Actions triggering deploys.

Upstream: https://github.com/deepseek-ai/deepseek-harness (MIT, "developer preview")

---

## 🔴 Before anything: rotate leaked credentials
A GitHub token (`ghp_…`) and a Render API key (`rnd_…`) were pasted into chat earlier.
Treat both as **compromised** — revoke/regenerate them. **Never** put a Render *account API key*
into repo files, CI logs, or chat. Deploys here use only the **per-service Deploy Hook URL**,
stored in GitHub Secrets.

---

## 🔒 Security: this tool can run arbitrary code — do NOT expose it publicly
DeepSeek Harness is an **agent/plugin "harness"**; its web server is a **remote-code-execution
surface**, which is exactly why dsh **refuses to bind `0.0.0.0`** (verified: it prints
*"it would expose remote code execution to the network; use 127.0.0.1 instead"*). It also
**auth-gates** the UI (a fresh `dsh web` returned **HTTP 401**). Putting a public
`*.onrender.com` URL on top of it is risky. Strongly prefer:
- a **Render Private Service** (reachable only over Render's private network / your VPN), or
- at minimum, keep dsh's auth enabled and never publish it without it.
Proceed with a public service only if you understand and accept this.

## Why a proxy (`proxy.js`) is required (verified on dsh 0.1.2-rc.1)
`dsh web` *does* accept `--host`/`--port`, but **hard-refuses `--host 0.0.0.0`** and will only
bind **`127.0.0.1`**. Render requires your process to listen on **`0.0.0.0`** on the injected
**`$PORT`**, or the load balancer never reaches the app. So dsh can't serve Render traffic by
itself — `proxy.js` is the bridge (it also forwards websockets):

```
Render LB ──▶ proxy.js (0.0.0.0:$PORT) ──http/ws──▶ dsh web (127.0.0.1:3080)
```

`proxy.js` also launches dsh headless: `--no-open` (no browser) plus `CI=true`, `BROWSER=none`.

## Files
| File | Purpose |
|------|---------|
| `package.json` | deps (`@deepseek-ai/dsh`, `http-proxy`) + `start`/`build` |
| `proxy.js` | 0.0.0.0 reverse proxy + non-interactive dsh launcher |
| `render.yaml` | Blueprint (Web Service, **paid** `starter` plan, no sleep) |
| `.nvmrc` | pins Node 20 |
| `.gitignore` | keeps `node_modules`, `.env`, `dsh.config.json` out of git |
| `.github/workflows/deploy.yml` | curl POST to the Render deploy hook on every push to `main` |

---

## ⚠️ One thing you must verify yourself: auth / config
The upstream README documents **no env var or config path for login**, and in testing a fresh
`dsh web` returned **HTTP 401** — it is **auth-gated**. If dsh needs first-run setup it must be
supplied **non-interactively**, or the process will effectively block / deny all traffic on
Render. dsh exposes `--patch <path>`, `--dump-config`, `--dump-default-config` for this.
`proxy.js` already forwards `--patch ./dsh.config.json` (when present) and
`--trusted-host $RENDER_EXTERNAL_HOSTNAME` so the proxied UI's `/api` trust-fence accepts the
Render hostname.

On your local machine, discover the schema and create a non-secret config template:
```bash
npx @deepseek-ai/dsh web --help
npx @deepseek-ai/dsh web --dump-default-config > dsh.config.json   # inspect the keys it wants
```
- Put **non-secret defaults** in `dsh.config.json` (committed or via a build step).
- Put **secrets** (e.g. an API key) in **Render Secret Environment Variables** — see next section.
`proxy.js` auto-adds `--patch ./dsh.config.json` when that file exists, so the run stays non‑interactive.

### Getting `dsh.config.json` onto Render without committing secrets
`dsh.config.json` is git‑ignored. Pick one:
1. **Secret file (best for secrets):** Render → Environment → *Add → Secret File*, name it
   `DSH_CONFIG`, paste content. At build time write it out — change `buildCommand` to:
   ```
   npm install && cp "$DSH_CONFIG" dsh.config.json
   ```
2. **Commit a secrets‑free template:** remove the secret line from `dsh.config.json`, commit it,
   and supply the secret via an env var dsh reads (confirm the var name from `--dump-default-config`).

---

## Deploy steps
1. **Create repo & push** (do NOT use the leaked token; re-auth with a fresh one):
   ```bash
   cd dsh-render
   git init -b main && git add -A && git commit -m "Add dsh Render deploy wrapper"
   git remote add origin https://github.com/<you>/<repo>.git
   git push -u origin main
   ```
2. **Create the service on Render via the Blueprint:** Render → *New → Blueprint* → pick the repo.
   Render reads `render.yaml`. (Paid `starter` plan → no sleep.)
3. **Add secrets:** Render → service → Environment → add your API key / secret file (above).
   First deploy runs `npm install` then `node proxy.js`.
4. **Copy the Deploy Hook:** Render → service → *Settings → Deploy* → **Deploy Hook URL**
   (looks like `https://api.render.com/deploy/srv-XXXX?key=YYYY`).
5. **Store the hook in GitHub Secrets** (step 4 of your plan):
   - GitHub repo → **Settings → Secrets and variables → Actions → New repository secret**
   - Name: `RENDER_DEPLOY_HOOK_URL`  ·  Value: the Deploy Hook URL from step 4
   Now every `git push` to `main` triggers the workflow → Render pulls the latest code and redeploys.
6. **Open the service URL** in a browser to use the dsh Web UI.

## Passphrase gate (REQUIRED in production)

`proxy.js` auto-completes dsh's launch-token exchange for visitors, so **without further
protection the public URL is an unauthenticated remote-code-execution surface** (dsh ships
bash/agent tools). `gate.js` closes that at the edge: every request, API call and WebSocket
upgrade must first carry a `dshgate` cookie, which is issued only after a single shared
passphrase login at **`/-gate`** (HttpOnly, SameSite=Lax, 30 days, `Secure` behind Render's
HTTPS). dsh's own auth is left fully intact — nothing in its `packages/web/src` is patched.

Setup: Render → service → Environment → **Add Secret Environment Variable** → `DSH_PASS`
= your passphrase. With `DSH_PASS` unset the gate is disabled and the proxy logs a loud
warning at boot. For local testing: `DSH_PASS=devpass PORT=8080 node proxy.js`.
A redeploy does not log browsers out (the cookie is derived from the passphrase, not from
per-boot state). To revoke access, change the value of `DSH_PASS` and redeploy.

## Test locally first
```bash
cd dsh-render
npm install
DSH_PASS=devpass PORT=8080 node proxy.js   # in another terminal:
curl -i http://localhost:8080/   # 401 login page until you POST the passphrase to /-gate
```

## Notes / caveats
- `dsh` is in **developer preview** — a newer `@deepseek-ai/dsh` may change flags; pin an exact
  version in `package.json` once you confirm what works (e.g. `"@deepseek-ai/dsh": "0.1.2-rc.1"`).
- If dsh needs persistent state (login/profile/plugins), Render's filesystem is ephemeral —
  attach a **Disk** to the service (in `render.yaml`: `disks: [{ name: dsh-data, mountPath: /var/dsh-data, sizeGB: 1 }]`)
  and point dsh's state dir there if it exposes such an option.
- `region: singapore` and `plan: starter` are suggestions — adjust to your account/needs.
```
