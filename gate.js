// Passphrase gate for the dsh proxy.
//
// WHY this exists: dsh's own launch-token flow can't be completed by a remote browser
// (headless server, token printed only to logs), so proxy.js performs the exchange
// automatically. That convenience means ANY anonymous visitor who finds the URL ends up
// holding a valid dsh session cookie — and dsh exposes bash/agent tools, i.e. an
// unauthenticated remote-code-execution surface on the public internet. This gate puts
// one shared passphrase at the edge: only visitors who pass it get the `dshgate` cookie
// that proxy.js requires before it will run the token exchange (or proxy /api and
// WebSocket traffic) on their behalf.
//
// It deliberately lives in THE PROXY, not in dsh's middleware: dsh's auth is
// unforgeable-by-design (random per-boot token, authority-bound signed cookie) and
// patching its source to disable it would ship an openly exploitable fork.
//
// Config: env DSH_PASS — set as a Render SECRET (never commit it).
//   * Unset/empty -> gate disabled, with a loud boot warning. Production MUST set it.
//   * Log in at:  GET /-gate (form) / POST /-gate {pass=...} -> sets 30-day HttpOnly
//     cookie, then redirects to / where the normal token bootstrap completes the session.
import { createHmac, timingSafeEqual } from 'node:crypto';

export const GATE_COOKIE = 'dshgate';
export const GATE_MAX_AGE = 30 * 24 * 3600; // seconds; matches dsh's own 30-day cookie

// Stable, unforgeable-without-the-passphrase cookie value. (A random per-boot value
// would log every browser out on each redeploy — Render regenerates the whole process.)
export function gateValue(pass) {
  return createHmac('sha256', String(pass)).update('dsh-gate-v1').digest('hex');
}

export function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of String(header).split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    try {
      out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
    } catch { /* malformed percent-encoding: ignore this pair */ }
  }
  return out;
}

function safeEq(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function sendHtml(req, res, status, html) {
  res.writeHead(status, {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store',
  });
  res.end(html);
}

function readBody(req, limit = 8192) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { reject(new Error('body too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

// Cookie is Secure only when the edge really is HTTPS: Render terminates TLS and sets
// x-forwarded-proto; a plain local http:// test server must NOT get a Secure cookie or
// the browser would never send it back.
function gateCookie(req, value) {
  const secure = req.socket.encrypted || String(req.headers['x-forwarded-proto'] || '').includes('https');
  let c = `${GATE_COOKIE}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${GATE_MAX_AGE}`;
  if (secure) c += '; Secure';
  return c;
}

const loginPage = (err) => `<!doctype html><html lang="th"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DeepSeek Harness — รหัสผ่าน</title>
<style>body{font:16px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif;background:#0b0d12;color:#e6e8ee;
display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{width:min(340px,92vw);padding:32px;border:1px solid #222833;border-radius:14px;background:#11141b}
h1{font-size:18px;margin:0 0 4px}p{margin:.2em 0;color:#9aa3b2;font-size:14px}
input{width:100%;box-sizing:border-box;margin:14px 0 0;padding:10px 12px;font-size:16px;color:#e6e8ee;
background:#0b0d12;border:1px solid #2a2f3a;border-radius:8px;outline:none}
input:focus{border-color:#7aa2ff}button{width:100%;margin-top:12px;padding:10px;font-size:15px;font-weight:600;
color:#fff;background:#3563e9;border:0;border-radius:8px;cursor:pointer}
.err{color:#ff7b7b;font-size:14px;min-height:1.2em;margin-top:10px}</style></head>
<body><form class="card" method="POST" action="/-gate">
<h1>DeepSeek Harness</h1><p>ใส่รหัสผ่านเพื่อเข้าถึง (จำไว้ 30 วันต่อบราวเซอร์)</p>
<input type="password" name="pass" autocomplete="current-password" autofocus placeholder="passphrase">
<button type="submit">เข้าใช้งาน</button>
<div class="err">${err ? 'รหัสผ่านไม่ถูกต้อง — ลองอีกครั้ง' : ''}</div>
</form></body></html>`;

/**
 * Build the gate middleware.
 * @param {string|undefined} pass  DSH_PASS value; empty/undefined disables the gate.
 * @returns middleware `(req, res, next)` with `.enabled` and `.isVerified(req)` helpers
 *          (isVerified is used by proxy.js for WebSocket `upgrade` requests).
 */
export function createGate(pass) {
  const secret = pass && String(pass).length > 0 ? String(pass) : null;
  const expected = secret ? gateValue(secret) : null;

  function isVerified(req) {
    if (!expected) return true;
    const cookies = parseCookies(req.headers.cookie);
    return safeEq(cookies[GATE_COOKIE] || '', expected);
  }

  async function gate(req, res, next) {
    if (!expected) return next(); // gate disabled (DSH_PASS unset) — proxy.js warns at boot

    const path = (req.url || '/').split('?')[0];

    if (path === '/-gate') {
      if (req.method === 'GET') return sendHtml(req, res, 200, loginPage(false));
      if (req.method !== 'POST') {
        res.writeHead(405, { allow: 'GET, POST', 'content-type': 'text/plain' });
        return res.end('method not allowed');
      }
      let given = '';
      try {
        given = new URLSearchParams(await readBody(req)).get('pass') || '';
      } catch { /* oversize/malformed body -> treated as wrong below */ }
      if (given && safeEq(gateValue(given), expected)) {
        res.writeHead(303, { location: '/', 'set-cookie': gateCookie(req, expected), 'cache-control': 'no-store' });
        return res.end();
      }
      await sleep(400); // blunt online guessing a little
      return sendHtml(req, res, 401, loginPage(true));
    }

    if (isVerified(req)) return next();

    const accept = req.headers.accept || '';
    if (req.method === 'GET' && (accept.includes('text/html') || accept === '')) {
      return sendHtml(req, res, 401, loginPage(false));
    }
    res.writeHead(401, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    res.end(JSON.stringify({ error: 'unauthorized', login: '/-gate' }));
  }

  gate.enabled = !!expected;
  gate.isVerified = isVerified;
  return gate;
}
