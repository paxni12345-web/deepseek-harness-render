// Render-ready reverse proxy around `dsh web`.
//
// WHY a proxy is mandatory (verified against dsh 0.1.2-rc.1):
//   dsh REJECTS `--host 0.0.0.0` on purpose ("expose remote code execution to the
//   network; use 127.0.0.1 instead"). Render needs a listener on 0.0.0.0:$PORT, so
//   dsh cannot serve Render traffic by itself -> this proxy is the bridge.
// Note: dsh web is AUTH-GATED (returns 401 until credentials/config are supplied).
// On startup dsh prints a one-time login URL (http://127.0.0.1:3080/?token=...).
// This proxy captures it, rewrites the host to Render's public hostname, and logs a
// clickable "LOGIN URL" line so a single user can auth on the cloud service.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import HttpProxy from 'http-proxy';

const PORT = Number(process.env.PORT || 8080); // Render injects PORT (binds 0.0.0.0 here)
const UPSTREAM = { host: '127.0.0.1', port: 3080 }; // dsh web only ever binds loopback
const PATCH = process.env.DSH_CONFIG_PATCH || './dsh.config.json';
const PUBLIC_HOST = process.env.RENDER_EXTERNAL_HOSTNAME; // e.g. deepseek-harness-puul.onrender.com

// dsh defaults to 127.0.0.1:3080; --no-open keeps it headless; never pass --host 0.0.0.0.
const args = ['--no-install', 'dsh', 'web', '--no-open'];
if (fs.existsSync(PATCH)) args.push('--patch', PATCH); // non-interactive config (avoids first-run prompt)
// The /api "browser-trust fence" rejects unknown Host headers (e.g. *.onrender.com).
// Tell dsh to trust Render's public hostname so proxied API calls aren't blocked.
const TRUSTED = PUBLIC_HOST;
if (TRUSTED) args.push('--trusted-host', TRUSTED);

const child = spawn('npx', args, {
  stdio: ['ignore', 'pipe', 'pipe'],
  env: { ...process.env, CI: 'true', NO_COLOR: '1', BROWSER: 'none' }, // never prompt
});

// Surface dsh's loopback login URL as a clickable public https URL in the logs.
function surface(chunk, sink) {
  const text = chunk.toString();
  process[sink].write(text);
  if (!PUBLIC_HOST) return;
  for (const m of text.matchAll(/http:\/\/127\.0\.0\.1:3080\b[^\s"']*/g)) {
    const pub = m[0].replace('http://127.0.0.1:3080', `https://${PUBLIC_HOST}`);
    console.log(`\n🔑 LOGIN URL (เปิดในเบราว์เซอร์): ${pub}\n`);
  }
}
child.stdout.on('data', (d) => surface(d, 'stdout'));
child.stderr.on('data', (d) => surface(d, 'stderr'));

child.on('exit', (code, sig) => {
  console.error(`[proxy] dsh exited code=${code} sig=${sig}`);
  process.exit(code ?? 1);
});

const proxy = HttpProxy.createProxyServer({
  ws: true,
  target: `http://${UPSTREAM.host}:${UPSTREAM.port}`,
});
proxy.on('error', (_err, _req, res) => {
  if (res && typeof res.writeHead === 'function') {
    res.writeHead(502, { 'content-type': 'text/plain' });
    res.end('DeepSeek Harness is starting up…\n');
  }
});

const server = http.createServer((req, res) => proxy.web(req, res));
server.on('upgrade', (req, socket, head) => proxy.ws(req, socket, head));

// Bind immediately so Render sees the port open even while dsh is still booting.
server.listen(PORT, '0.0.0.0', () => {
  console.log(`[proxy] 0.0.0.0:${PORT} -> ${UPSTREAM.host}:${UPSTREAM.port} (dsh web)`);
});

function shutdown(sig) {
  console.log(`[proxy] ${sig} — shutting down`);
  try { child.kill('SIGTERM'); } catch { /* already gone */ }
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 5000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
