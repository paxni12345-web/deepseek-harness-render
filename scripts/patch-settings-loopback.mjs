// Build-time patch: enable the in-browser Settings pages on non-loopback authorities.
//
// Context: dsh 0.1.2-rc.1 hard-gates its client UI — `@deepseek-ai/dsh-client-ui-settings`
// picks `persistence = ctx.remote.$host.isLoopback ? "host" : "memory"`, and in "memory"
// mode the settings describe-mirror NEVER reads from the wire, so any non-localhost page
// (e.g. *.onrender.com) shows "Loading the provider directory failed: settings are
// unavailable in this browser" even with a fully authenticated session.
//
// This is a FEATURE gate, not authentication: token, authority-bound cookie, trusted-host
// fence, and the proxy's DSH_PASS passphrase gate all stay fully enforced. This deployment
// is a single-owner private instance; the operator's browser IS the operator's machine,
// just reached via proxy. Only the persistence choice is flipped.
//
// Version-guarded: if dsh's source changes shape, this script FAILS LOUDLY at build
// instead of silently shipping a broken/unpatched bundle. package.json pins the dsh version.
import fs from 'node:fs';

const FILE = new URL('../node_modules/@deepseek-ai/dsh-client-ui-settings/lib/client.js', import.meta.url);
const NEEDLE = 'const persistence = ctx.remote.$host.isLoopback ? "host" : "memory";';
const FIXED = 'const persistence = "host"; /* dsh-render: single-owner proxied deployment; see scripts/patch-settings-loopback.mjs */';

let src;
try {
  src = fs.readFileSync(FILE, 'utf8');
} catch {
  // Package missing (e.g. partial install): don't hard-fail an unrelated build.
  console.error('[patch-settings] dsh-client-ui-settings not found; skipping');
  process.exit(0);
}

if (src.includes('dsh-render: single-owner proxied deployment')) {
  console.log('[patch-settings] already applied');
} else if (!src.includes(NEEDLE)) {
  console.error('[patch-settings] FATAL: persistence gate not found verbatim in');
  console.error(`[patch-settings]   ${FILE.pathname}`);
  console.error('[patch-settings] dsh internals changed — review by hand before deploying.');
  process.exit(1);
} else {
  fs.writeFileSync(FILE, src.replace(NEEDLE, FIXED));
  console.log('[patch-settings] applied: settings pages unlocked for proxied non-loopback hosts');
}
