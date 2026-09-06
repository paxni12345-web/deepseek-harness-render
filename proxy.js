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
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import HttpProxy from 'http-proxy';

const PORT = Number(process.env.PORT || 8080); // Render injects PORT (binds 0.0.0.0 here)
const UPSTREAM = { host: '127.0.0.1', port: 3080 }; // dsh web only ever binds loopback
const PATCH = process.env.DSH_CONFIG_PATCH || './dsh.config.json';

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
});

proxy.on('error', (_err, _req, res) => {
  if (res && typeof res.writeHead === 'function') {
    const notReady = !launchToken;
    res.writeHead(notReady ? 503 : 502, {
      'content-type': 'text/plain',
      'retry-after': notReady ? '5' : '2',
    });
    res.end(notReady
      ? 'DeepSeek Harness is starting up (bootstrapping auth)...'
      : 'DeepSeek Harness is starting up...');
  }
});

const server = http.createServer((req, res) => proxy.web(req, res));
server.on('upgrade', (req, socket, head) => proxy.ws(req, socket, head));

// Bind immediately so Render sees the port open even while dsh is still booting.
server.listen(PORT, '0.0.0.0', () => {
  console.log(`[proxy] 0.0.0.0:${PORT} -> ${UPSTREAM.host}:${UPSTREAM.port} (dsh web, auto-auth proxy)`);
});

function shutdown(sig) {
  console.log(`[proxy] ${sig} - shutting down`);
  try { child.kill('SIGTERM'); } catch { /* already gone */ }
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 5000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
