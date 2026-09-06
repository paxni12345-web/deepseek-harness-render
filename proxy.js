// Render-ready reverse proxy around `dsh web`.
//
// WHY a proxy is mandatory (verified against dsh 0.1.2-rc.1):
//   dsh REJECTS `--host 0.0.0.0` on purpose ("expose remote code execution to the
//   network; use 127.0.0.1 instead"). Render needs a listener on 0.0.0.0:$PORT, so
//   dsh cannot serve Render traffic by itself -> this proxy is the bridge.
//
// WHY this proxy also has to do auth (verified against dsh 0.1.2-rc.1 internals):
//   dsh web is AUTH-GATED and there is NO config to disable it (the `client-connection`
//   plugin schema only exposes trustedHosts / cookieMaxAgeDays / maxRequestBodyBytes).
//   Its model is:
//     * On boot it mints a per-process RANDOM launch token (randomBytes, kept only in
//       a WeakMap -- NOT persisted, NOT settable) and prints:
//         dsh web: http://127.0.0.1:3080/?token=<TOKEN>
//     * GET /?token=<TOKEN> mints a 30-day signed session cookie whose JWT binds the
//       request's authority (the Host header), then 303-redirects to clean /.
//     * Every /api/* request must pass BOTH the Host/Origin browser-trust fence (needs
//       --trusted-host, else 403) AND a valid authority-bound cookie (else 401). The
//       Settings -> Models page calls /api for the provider directory, so a visitor
//       that never obtained the cookie sees "settings are unavailable in this browser".
//   On a headless server the printed URL is loopback-only and the token changes on
//   every boot, so a remote browser can NEVER complete the exchange by itself.
//   -> This proxy captures the launch token from dsh's stdout and transparently
//      performs the exchange for each first visit, relaying the Set-Cookie back to the
//      browser. The raw token never reaches the client; the browser just ends up
//      holding a valid cookie bound to the public authority.
//
// ACCESS CONTROL (added on top of the bootstrap, see gate.js):
//   Because the bootstrap auto-mints a valid dsh session for ANY anonymous visitor, the
//   raw URL would otherwise be an unauthenticated remote-code-execution endpoint (dsh
//   ships bash/agent tools). So EVERY request — index navigations, /api, static assets
//   and WebSocket upgrades — must first carry the `dshgate` cookie, which is issued by
//   a single shared passphrase login at /-gate. Set DSH_PASS as a Render secret;
//   with it unset the gate is disabled and a loud warning is printed at boot.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import HttpProxy from 'http-proxy';
import { createGate } from './gate.js';

const PORT = Number(process.env.PORT || 8080); // Render injects PORT (binds 0.0.0.0 here)
const UPSTREAM = { host: '127.0.0.1', port: 3080 }; // dsh web only ever binds loopback
const PATCH = process.env.DSH_CONFIG_PATCH || './dsh.config.json';

const gate = createGate(process.env.DSH_PASS);
if (!gate.enabled) {
  console.error('[proxy] *** WARNING: DSH_PASS is not set — the passphrase gate is DISABLED.');
  console.error('[proxy]     Anyone who finds this URL can drive a remote-code-execution agent.');
  console.error('[proxy]     Add DSH_PASS as a secret in Render -> Environment. ***');
} else {
  console.error('[proxy] passphrase gate ON (login at /-gate; set DSH_PASS in Render secrets)');
}

// dsh defaults to 127.0.0.1:3080; --no-open keeps it headless; never pass --host 0.0.0.0.
const args = ['--no-install', 'dsh', 'web', '--no-open'];
if (fs.existsSync(PATCH)) args.push('--patch', PATCH); // non-interactive config (avoids first-run prompt)
// The /api browser-trust fence rejects unknown Host headers (e.g. *.onrender.com).
// Tell dsh to trust Render's public hostname so proxied API calls are not 403'd.
// Accept the canonical Render value plus any extra bare hosts via env.
for (const h of new Set([
  process.env.RENDER_EXTERNAL_HOSTNAME,
  ...String(process.env.DSH_EXTRA_TRUSTED_HOSTS || '').split(',').map((s) => s.trim()),
].filter(Boolean))) {
  args.push('--trusted-host', h);
}

// The per-process launch token, parsed from dsh's stdout. Until dsh prints its boot
// line we have nothing to inject, so unauthenticated first hits get a 503 (retry).
let launchToken;

const child = spawn('npx', args, {
  // stdout piped so we can scrape the token (and re-emit it for Render's log stream);
  // stderr inherited because dsh also logs startup noise there.
  stdio: ['ignore', 'pipe', 'inherit'],
  // NO_COLOR keeps the boot line ANSI-free so the token regex matches cleanly.
  env: { ...process.env, CI: 'true', NO_COLOR: '1', BROWSER: 'none' },
});
child.on('exit', (code, sig) => {
  console.error(`[proxy] dsh exited code=${code} sig=${sig}`);
  process.exit(code ?? 1);
});

// Scan dsh's stdout for the printed authenticated URL and remember its `?token=`.
// Keep a small rolling buffer so a line split across chunks still matches.
let stdoutBuf = '';
child.stdout.on('data', (chunk) => {
  process.stdout.write(chunk); // keep dsh's logs visible in Render
  if (launchToken) return;
  stdoutBuf = (stdoutBuf + chunk).slice(-4096);
  const m = stdoutBuf.match(/[?&]token=([A-Za-z0-9_-]+)/);
  if (m) {
    launchToken = m[1];
    console.error('[proxy] captured dsh launch token (auto-auth ready)');
  }
});

// A top-level GET navigation to the SPA index is the only thing that needs the token
// exchange. Static assets and /api arrive afterwards, already carrying the cookie.
const isIndexNav = (req) => {
  if (req.method !== 'GET') return false;
  const path = (req.url || '/').split('?')[0];
  if (path !== '/' && path !== '/index.html') return false;
  const accept = req.headers.accept || '';
  return path === '/' || accept.includes('text/html') || accept === '';
};

// Sentinel query the browser carries back after a completed exchange. dsh answers the
// token exchange with a 303 to clean `/`; we rewrite that Location to `/?<BOOTSTRAP>` so
// the redirected follow-up is recognised as "already bootstrapped" and is NOT re-injected
// (which would otherwise 303 forever). Keeping the sentinel in the URL rather than in
// proxy state means the no-reinject rule survives across requests.
const BOOTSTRAP = 'dshboot';
const alreadyBootstrapped = (req) =>
  new RegExp(`[?&]${BOOTSTRAP}(=|&|$)`).test(req.url || '');

// Render's filesystem is ephemeral, so a redeploy regenerates dsh's cookie-signing
// secret and every pre-existing browser cookie goes stale (dsh then 401s even though the
// browser "has" a cookie). Re-running the exchange on EVERY fresh index navigation fixes
// this transparently: the sentinel hop is the only one we skip.
const proxy = HttpProxy.createProxyServer({
  ws: true,
  target: `http://${UPSTREAM.host}:${UPSTREAM.port}`,
});

// Inject the launch token into the upstream request so dsh performs the exchange and
// answers 303 + Set-Cookie (relayed to the browser). Tag the request so proxyRes can
// rewrite the redirect target to carry the bootstrap sentinel.
proxy.on('proxyReq', (proxyReq, req) => {
  if (launchToken && isIndexNav(req) && !alreadyBootstrapped(req)) {
    const path = (req.url || '/').split('?')[0];
    const originalQuery = (req.url || '/').split('?')[1];
    // Send the token (plus any original query) to dsh; keep the path clean.
    proxyReq.path = `/?token=${launchToken}${originalQuery ? `&${originalQuery}` : ''}`;
    req.__dshInjected = { path, query: originalQuery };
  }
});

// Rewrite dsh's 303 Location from `/` to `/<original>?<BOOTSTRAP>` so the follow-up is
// served normally (cookie now valid) instead of re-entering the exchange.
proxy.on('proxyRes', (proxyRes, req) => {
  const injected = req.__dshInjected;
  if (injected && proxyRes.statusCode === 303) {
    const qs = injected.query ? `${injected.query}&${BOOTSTRAP}=1` : `${BOOTSTRAP}=1`;
    proxyRes.headers.location = `${injected.path}?${qs}`;
  }
  // dsh issues its session cookie as SameSite=Strict, assuming a loopback UI. Behind
  // Render's public host that breaks the exchange: the browser will not replay the just-
  // minted cookie on the 303 follow-up navigation (nor reliably across a cold start), so
  // /api comes back 401 and Settings shows "settings are unavailable in this browser".
  // Lax keeps it on top-level navigations and same-site /api calls without opening the
  // cookie to cross-site subresource requests, which is exactly what this deployment needs.
  const cookies = proxyRes.headers['set-cookie'];
  if (cookies) {
    proxyRes.headers['set-cookie'] = (Array.isArray(cookies) ? cookies : [cookies])
      .map((c) => c.replace(/;\s*SameSite=Strict/i, '; SameSite=Lax'));
  }
});

proxy.on('error', (_err, req, res) => {
  if (!res || typeof res.writeHead !== 'function') return;
  // A navigation that hit upstream while dsh is momentarily down: show the auto-retry page.
  if (isIndexNav(req)) return bootPage(res, 'เซิร์ฟเวอร์กำลังรีสตาร์ต…');
  res.writeHead(502, { 'content-type': 'text/plain', 'retry-after': '2' });
  res.end('DeepSeek Harness is starting up...');
});

// Cold-start experience. On Render's free tier the container sleeps and dsh takes ~15s to
// boot + print its token on every wake. If we answered that window with a plain 5xx text
// page, a visitor who opens the URL cold lands on a dead-end that LOOKS broken ("เข้าไม่ได้").
// Instead the index is held on a self-refreshing status page until the launch token is
// captured, so the first successful navigation always finds auth ready.
function bootPage(res, msg) {
  const html = `<!doctype html><html lang="th"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="3"><title>DeepSeek Harness — กำลังเริ่มทำงาน</title>
<style>body{font:16px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif;background:#0b0d12;color:#e6e8ee;
display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{text-align:center;max-width:420px;padding:32px}.spin{width:34px;height:34px;margin:0 auto 18px;
border:3px solid #2a2f3a;border-top-color:#7aa2ff;border-radius:50%;animation:s 1s linear infinite}
@keyframes s{to{transform:rotate(360deg)}}p{margin:.3em 0;color:#9aa3b2}code{color:#7aa2ff}</style></head>
<body><div class="card"><div class="spin"></div><strong>DeepSeek Harness</strong>
<p>${msg}</p><p>หน้านี้จะโหลดใหม่อัตโนมัติ…</p></div>
<script>setTimeout(function(){location.reload()},3000)</script></body></html>`;
  res.writeHead(200, {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store',
    'retry-after': '3',
  });
  res.end(html);
}

const server = http.createServer((req, res) => {
  // Edge gate: without the dshgate cookie (issued at /-gate after the passphrase
  // login) NOTHING reaches dsh — not the token bootstrap, not /api, not assets.
  gate(req, res, () => {
    // Hold the first meaningful navigation until dsh is up and we have a token to inject.
    if (!launchToken && isIndexNav(req)) return bootPage(res, 'กำลังเริ่มเซิร์ฟเวอร์ (bootstrapping auth)…');
    proxy.web(req, res);
  });
});
server.on('upgrade', (req, socket, head) => {
  if (!gate.isVerified(req)) {
    socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    return socket.destroy();
  }
  proxy.ws(req, socket, head);
});

// Bind immediately so Render sees the port open even while dsh is still booting.
server.listen(PORT, '0.0.0.0', () => {
  console.log(`[proxy] 0.0.0.0:${PORT} -> ${UPSTREAM.host}:${UPSTREAM.port} (dsh web, auto-auth proxy, gate ${gate.enabled ? 'ON' : 'OFF'})`);
});

function shutdown(sig) {
  console.log(`[proxy] ${sig} - shutting down`);
  try { child.kill('SIGTERM'); } catch { /* already gone */ }
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 5000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
