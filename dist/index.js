// VibeLocked LeakCheck Scan: free, read-only secret scan for GitHub Actions.
// No dependencies. No token. Nothing is uploaded: files are read on the runner, and the optional
// URL check makes read-only GET requests to the app you name. Secret values are always masked.
// https://vibelocked.com/leakcheck/?ref=github-action  License: MIT
'use strict';
const fs = require('node:fs');
const path = require('node:path');

const SB_PUBLIC_NOTE = 'Public Supabase key. Expected in the browser and not a leak by itself, but only safe if Row Level Security is on for every exposed table.';
const rules = [
  { name: 'OpenAI API key', re: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b|\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}/g, level: 'high', fix: 'Revoke it at platform.openai.com/api-keys and call OpenAI only from a server.' },
  { name: 'Anthropic API key', re: /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}/g, level: 'high', fix: 'Revoke it in the Anthropic Console and move calls server side.' },
  { name: 'Stripe or Clerk secret key', re: /\bsk_(?:live|test)_[A-Za-z0-9]{20,}/g, level: 'high', fix: 'Roll it in the Stripe Dashboard (Developers, API keys) or create a new Clerk Secret Key and delete the old one.' },
  { name: 'Stripe restricted key', re: /\brk_(?:live|test)_[A-Za-z0-9]{20,}/g, level: 'high', fix: 'Roll the restricted key in the Stripe Dashboard.' },
  { name: 'Stripe or Clerk webhook secret', re: /\bwhsec_[A-Za-z0-9]{20,}/g, level: 'high', fix: 'Rotate the endpoint signing secret and keep it server side only.' },
  { name: 'Supabase secret key', re: /\bsb_secret_[A-Za-z0-9_-]{20,}/g, level: 'high', fix: 'Delete and recreate it under Project Settings, API Keys. Never ship it to the browser.' },
  { name: 'AWS access key ID', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, level: 'high', fix: 'Deactivate and delete the key in IAM, then check CloudTrail for use.' },
  { name: 'AWS secret access key', re: /aws_?secret_?access_?key["'\s:=]+[A-Za-z0-9/+]{40}/gi, level: 'high', fix: 'Deactivate the matching access key in IAM.' },
  { name: 'GitHub token', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{60,}/g, level: 'high', fix: 'Revoke it under GitHub Settings, Developer settings.' },
  { name: 'GitLab token', re: /\bglpat-[A-Za-z0-9_-]{20,}/g, level: 'high', fix: 'Revoke it in GitLab access tokens.' },
  { name: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g, level: 'warn', fix: 'Fine in a Firebase web config if restricted. If it is a Gemini or Maps key without restrictions, restrict or rotate it in Google Cloud.' },
  { name: 'Slack token', re: /\bxox[abposr]-[A-Za-z0-9-]{10,}/g, level: 'high', fix: 'Revoke the token in your Slack app settings.' },
  { name: 'Slack webhook URL', re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/_-]+/g, level: 'high', fix: 'Regenerate the incoming webhook.' },
  { name: 'Discord webhook URL', re: /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/g, level: 'high', fix: 'Delete the webhook in the channel settings and create a new one.' },
  { name: 'Twilio API key', re: /\bSK[0-9a-fA-F]{32}\b/g, level: 'warn', fix: 'If this is a Twilio key, delete it in the Twilio Console.' },
  { name: 'SendGrid API key', re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g, level: 'high', fix: 'Delete it in SendGrid API Keys.' },
  { name: 'Resend API key', re: /\bre_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}/g, level: 'high', fix: 'Revoke it in the Resend dashboard.' },
  { name: 'Hugging Face token', re: /\bhf_[A-Za-z0-9]{34,}\b/g, level: 'high', fix: 'Invalidate it in Hugging Face access tokens.' },
  { name: 'Groq API key', re: /\bgsk_[A-Za-z0-9]{40,}\b/g, level: 'high', fix: 'Revoke it in the Groq console.' },
  { name: 'xAI API key', re: /\bxai-[A-Za-z0-9]{60,}\b/g, level: 'high', fix: 'Revoke it in the xAI console.' },
  { name: 'Replicate token', re: /\br8_[A-Za-z0-9]{36,}\b/g, level: 'high', fix: 'Revoke it in Replicate account settings.' },
  { name: 'Private key block', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----/g, level: 'high', fix: 'Treat the key pair as compromised and replace it.' },
  { name: 'Database URL with password', re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss):\/\/[^\s:@/'"]+:[^\s@/'"]{3,}@[^\s'"]+/g, level: 'high', fix: 'Change the database password and keep the URL in server env vars only.' },
  { name: 'Stripe or Clerk publishable key', re: /\bpk_(?:live|test)_[A-Za-z0-9]{20,}/g, level: 'info', fix: 'Publishable keys are meant for the browser.' },
  { name: 'Supabase publishable key', re: /\bsb_publishable_[A-Za-z0-9_-]{20,}/g, level: 'info', fix: SB_PUBLIC_NOTE },
];
const jwtRe = /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;
const genericRe = /\b([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY)[A-Z0-9_]*)\s*[:=]\s*["']?([^\s"'`,;]{16,})/g;
const PLACEHOLDER = /^(?:process\.env|import\.meta\.env|\$\{|\$\(|<|your|xxx|changeme|example|placeholder|dummy|test-?key|\*{3,})/i;

function jwtRole(t) {
  try {
    const p = t.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    const j = JSON.parse(Buffer.from(p, 'base64').toString('utf8'));
    return typeof j.role === 'string' ? j.role : '';
  } catch { return ''; }
}
function mask(v) { return v.length <= 12 ? v.slice(0, 3) + '...' : v.slice(0, 8) + '...' + v.slice(-4); }
function lineOf(text, i) { let n = 1; for (let k = 0; k < i; k++) if (text.charCodeAt(k) === 10) n++; return n; }

function scanText(text) {
  const found = []; const seen = new Set();
  const add = (f) => { const k = f.name + f.value; if (!seen.has(k)) { seen.add(k); found.push(f); } };
  for (const r of rules) for (const m of text.matchAll(r.re)) add({ name: r.name, level: r.level, value: m[0], index: m.index, fix: r.fix });
  for (const m of text.matchAll(jwtRe)) {
    const role = jwtRole(m[0]);
    if (role === 'service_role') add({ name: 'Supabase service role key', level: 'high', value: m[0], index: m.index, fix: 'It bypasses Row Level Security. Rotate it in Supabase (new API keys or JWT secret) and use it only on a server.' });
    else if (role === 'anon') add({ name: 'Supabase anon key', level: 'info', value: m[0], index: m.index, fix: SB_PUBLIC_NOTE });
  }
  const covered = found.map((f) => f.value);
  for (const m of text.matchAll(genericRe)) {
    const v = m[2];
    if (covered.some((c) => c.includes(v) || v.includes(c))) continue;
    if (PLACEHOLDER.test(v)) continue;
    if (/^[{[(!]/.test(v) || v.includes('=>') || /^(?:async)?function/.test(v)) continue;
    if (/_INTERNALS_DO_NOT_USE_|^(?:NEXT_|__NEXT|VITE_|ASTRO_)/.test(m[1])) continue;
    add({ name: 'Possible secret in ' + m[1], level: 'warn', value: v, index: m.index, fix: 'If this is a real value, move it to server env vars or a CI secret and rotate it.' });
  }
  for (const f of found) f.line = lineOf(text, f.index);
  return found.filter((f) => f.level !== 'info');
}

// ---------- inputs / outputs ----------
const input = (n, d) => { const v = process.env['INPUT_' + n.replace(/ /g, '_').toUpperCase()]; return v === undefined || v === '' ? d : v.trim(); };
const esc = (s) => String(s).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
const escProp = (s) => esc(s).replace(/:/g, '%3A').replace(/,/g, '%2C');
function setOutput(k, v) { if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, `${k}=${v}\n`); }

const SKIP_DIRS = new Set(['.git', 'node_modules', '.pnpm-store', '.yarn', 'bower_components', '.venv', 'venv', '__pycache__', '.cache', '.turbo', '.vercel', '.netlify']);
const SKIP_FILES = /(?:^|\/)(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb|composer\.lock|Cargo\.lock|poetry\.lock|go\.sum)$/;
const SKIP_EXT = /\.(?:png|jpe?g|gif|webp|avif|ico|bmp|tiff?|mp[34]|mov|webm|wav|ogg|flac|woff2?|ttf|otf|eot|pdf|zip|gz|tgz|bz2|xz|7z|rar|jar|wasm|so|dylib|dll|exe|bin|class|pyc|psd|sketch|fig)$/i;
const ENV_FILE = /^\.env(?:\.[A-Za-z0-9_-]+)*$/;
const ENV_OK = /\.(?:example|sample|template|dist|defaults?|schema|test\.example)$/i;
const MAX_BYTES = 2 * 1024 * 1024;

function walk(root, maxFiles) {
  const out = []; const stack = [root];
  while (stack.length && out.length < maxFiles) {
    const dir = stack.pop();
    let entries; try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) stack.push(full); }
      else if (e.isFile()) out.push(full);
      if (out.length >= maxFiles) break;
    }
  }
  return out;
}

function scanFolder(root, maxFiles) {
  const results = []; let read = 0; let capped = false;
  const files = walk(root, maxFiles);
  if (files.length >= maxFiles) capped = true;
  for (const file of files) {
    const rel = path.relative(process.env.GITHUB_WORKSPACE || process.cwd(), file).split(path.sep).join('/');
    const base = path.basename(file);
    if (ENV_FILE.test(base) && !ENV_OK.test(base)) {
      results.push({ name: 'Environment file in the repo or build', level: 'high', value: '', where: rel, line: 1, fix: 'Delete it from git (git rm --cached), add .env* to .gitignore with !.env.example, and rotate every key that was in it. Keep real values in your host or CI secrets.' });
    }
    if (SKIP_FILES.test(rel) || SKIP_EXT.test(base)) continue;
    let buf; try { const st = fs.statSync(file); if (st.size > MAX_BYTES || st.size === 0) continue; buf = fs.readFileSync(file); } catch { continue; }
    if (buf.subarray(0, 8000).includes(0)) continue;
    read++;
    for (const f of scanText(buf.toString('utf8'))) results.push({ ...f, where: rel });
  }
  return { results, read, capped };
}

async function get(url, limit = 1.5 * 1024 * 1024) {
  const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), 15000);
  try {
    const r = await fetch(url, { method: 'GET', redirect: 'follow', signal: ctl.signal, headers: { 'User-Agent': 'VibeLocked-LeakCheck-Action/1 (+https://vibelocked.com/leakcheck/)', Accept: '*/*' } });
    const reader = r.body ? r.body.getReader() : null; const chunks = []; let size = 0;
    if (reader) for (;;) { const { done, value } = await reader.read(); if (done) break; size += value.length; if (size > limit) { ctl.abort(); break; } chunks.push(value); }
    return { status: r.status, url: r.url, type: r.headers.get('content-type') || '', text: Buffer.concat(chunks.map((c) => Buffer.from(c))).toString('utf8') };
  } catch (e) { return { status: 0, url, type: '', text: '', error: String(e && e.name === 'AbortError' ? 'timeout or size cap' : e) }; }
  finally { clearTimeout(t); }
}

async function scanUrl(target) {
  const results = []; const notes = [];
  let base; try { base = new URL(target); } catch { notes.push(`Not a valid URL: ${target}`); return { results, notes, scripts: 0 }; }
  if (!/^https?:$/.test(base.protocol)) { notes.push('Only http and https URLs are checked.'); return { results, notes, scripts: 0 }; }
  const page = await get(base.href);
  if (page.status !== 200) { notes.push(`GET ${base.href} returned ${page.status || page.error}.`); return { results, notes, scripts: 0 }; }
  const origin = new URL(page.url || base.href).origin;
  for (const f of scanText(page.text)) results.push({ ...f, where: `GET ${base.pathname || '/'} (HTML)` });
  const srcs = new Set();
  const addSrc = (s) => { try { const u = new URL(s, page.url || base.href); if (u.origin === origin) srcs.add(u.href); } catch {} };
  for (const m of page.text.matchAll(/<script\b[^>]*\bsrc=["']([^"']+)["']/gi)) addSrc(m[1]);
  for (const m of page.text.matchAll(/<link\b[^>]*\brel=["']modulepreload["'][^>]*\bhref=["']([^"']+)["']/gi)) addSrc(m[1]);
  const list = [...srcs].slice(0, 20);
  if (srcs.size > 20) notes.push(`Checked the first 20 of ${srcs.size} same-origin scripts.`);
  let mapsChecked = 0;
  for (const s of list) {
    const r = await get(s);
    if (r.status !== 200) continue;
    const p = new URL(s).pathname;
    for (const f of scanText(r.text)) results.push({ ...f, where: `GET ${p}` });
    const ref = r.text.match(/\/\/[#@] sourceMappingURL=([^\s'"]+\.map)\s*$/m);
    if (ref && mapsChecked < 5) {
      mapsChecked++;
      let mu; try { mu = new URL(ref[1], s); } catch {}
      if (mu && mu.origin === origin) {
        const m = await get(mu.href, 256 * 1024);
        if ((m.status === 200 || (m.status === 0 && m.error === 'timeout or size cap')) && /"(?:version|sources|mappings)"/.test(m.text)) {
          results.push({ name: 'Production source map is public', level: 'warn', value: '', where: `GET ${mu.pathname}`, line: 1, fix: 'Anyone can read your original source. Turn off production source maps (for example build.sourcemap: false in Vite) or upload them privately to your error tracker.' });
        }
      }
    }
  }
  const env = await get(origin + '/.env', 64 * 1024);
  if (env.status === 200 && !/<html|<!doctype/i.test(env.text) && /^[A-Z_][A-Z0-9_]*\s*=/m.test(env.text)) {
    results.push({ name: '.env file served publicly', level: 'high', value: '', where: 'GET /.env', line: 1, fix: 'Block the file on your host now, then rotate every key in it.' });
  }
  const git = await get(origin + '/.git/config', 64 * 1024);
  if (git.status === 200 && /\[core\]/.test(git.text)) {
    results.push({ name: '.git folder served publicly', level: 'high', value: '', where: 'GET /.git/config', line: 1, fix: 'Block /.git on your host. Anyone can download your source and history; rotate any key ever committed.' });
  }
  return { results, notes, scripts: list.length };
}

async function main() {
  const ws = process.env.GITHUB_WORKSPACE || process.cwd();
  const scanPath = input('path', '.');
  const url = input('url', '');
  const failOn = input('fail-on', 'high').toLowerCase();
  const maxFiles = Math.max(1, parseInt(input('max-files', '5000'), 10) || 5000);
  if (!['high', 'warn', 'none'].includes(failOn)) { console.log(`::error::fail-on must be high, warn or none (got ${esc(failOn)})`); process.exit(1); }

  const all = []; const notes = []; let read = 0; let scripts = 0;
  const root = path.resolve(ws, scanPath);
  if (!root.startsWith(path.resolve(ws))) { console.log('::error::path must stay inside the workspace'); process.exit(1); }
  if (fs.existsSync(root)) {
    const r = scanFolder(root, maxFiles); all.push(...r.results); read = r.read;
    if (r.capped) notes.push(`Stopped at max-files (${maxFiles}).`);
  } else notes.push(`Path not found: ${scanPath}`);
  if (url) { const u = await scanUrl(url); all.push(...u.results); notes.push(...u.notes); scripts = u.scripts; }

  const high = all.filter((f) => f.level === 'high');
  const warn = all.filter((f) => f.level === 'warn');
  for (const f of [...high, ...warn]) {
    const cmd = f.level === 'high' ? 'error' : 'warning';
    const ev = f.value ? ` (${mask(f.value)})` : '';
    const loc = f.where && !f.where.startsWith('GET ') ? ` file=${escProp(f.where)},line=${f.line || 1},` : ' ';
    console.log(`::${cmd}${loc}title=${escProp('LeakCheck: ' + f.name)}::${esc(`${f.name}${ev} in ${f.where}. ${f.fix}`)}`);
  }

  const verdict = high.length ? `${high.length} likely secret${high.length === 1 ? '' : 's'} found` : warn.length ? `No likely secrets. ${warn.length} item${warn.length === 1 ? '' : 's'} to review` : 'No secrets found';
  console.log(`LeakCheck: ${verdict}. Files read: ${read}${url ? `, URL checked: ${url} (${scripts} scripts)` : ''}.`);
  for (const n of notes) console.log('Note: ' + n);

  if (process.env.GITHUB_STEP_SUMMARY) {
    const rows = [...high, ...warn].slice(0, 100).map((f) => `| ${f.level === 'high' ? 'High' : 'Review'} | ${f.name.replace(/\|/g, '\\|')} | \`${(f.where + (f.where.startsWith('GET ') ? '' : ':' + (f.line || 1))).replace(/\|/g, '\\|')}\` | ${f.value ? '`' + mask(f.value) + '`' : ''} | ${f.fix.replace(/\|/g, '\\|')} |`);
    let md = `## VibeLocked LeakCheck: ${verdict}\n\nFiles read: ${read} in \`${scanPath}\`${url ? `. Live URL: ${url} (${scripts} same-origin scripts)` : ''}. Values are masked.\n\n`;
    if (rows.length) md += `| Severity | What | Where | Value | Fix |\n|---|---|---|---|---|\n${rows.join('\n')}\n\n`;
    if (all.length > 100) md += `Showing 100 of ${all.length}.\n\n`;
    for (const n of notes) md += `- ${n}\n`;
    md += `\nIf a real key leaked, rotate it at the provider first; deleting the commit is not enough. A clean result is not a guarantee: this is a pattern scan, not a full audit.\n\nThis action does not check your database. [VibeLocked LeakCheck](https://vibelocked.com/leakcheck/?ref=github-action) also checks a live app for Supabase tables the public key can read and open Firebase data, free.\n`;
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, md);
  }
  setOutput('high', high.length); setOutput('warn', warn.length); setOutput('total', high.length + warn.length);
  if ((failOn === 'high' && high.length) || (failOn === 'warn' && (high.length || warn.length))) process.exit(1);
}

module.exports = { scanText, mask, scanFolder, scanUrl };
if (require.main === module) main().catch((e) => { console.log(`::error::LeakCheck crashed: ${esc(e && e.stack || e)}`); process.exit(1); });
