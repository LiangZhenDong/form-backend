// Pure helpers (no Cloudflare APIs) so they can be tested with plain Node.

export const LIMITS = { maxFields: 50, maxFieldBytes: 10 * 1024, maxBodyBytes: 100 * 1024 };

export class InputError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.status = status;
  }
}

const enc = new TextEncoder();

// Returns { data, gotcha, turnstileToken }. `data` excludes meta fields (names starting with "_" and the Turnstile token).
export async function parseSubmission(contentType = '', body) {
  if (body.byteLength > LIMITS.maxBodyBytes) throw new InputError('Body too large', 413);
  const type = contentType.split(';')[0].trim().toLowerCase();
  const entries = [];

  if (type === 'application/json') {
    let obj;
    try {
      obj = JSON.parse(new TextDecoder().decode(body));
    } catch {
      throw new InputError('Invalid JSON');
    }
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) throw new InputError('JSON body must be an object');
    for (const [k, v] of Object.entries(obj)) entries.push([k, typeof v === 'string' ? v : JSON.stringify(v)]);
  } else if (type === 'application/x-www-form-urlencoded') {
    for (const e of new URLSearchParams(new TextDecoder().decode(body))) entries.push(e);
  } else if (type === 'multipart/form-data') {
    let fd;
    try {
      fd = await new Response(body, { headers: { 'content-type': contentType } }).formData();
    } catch {
      throw new InputError('Invalid multipart body');
    }
    // ponytail: file parts are dropped; storing them in R2 is the upgrade path.
    for (const [k, v] of fd) if (typeof v === 'string') entries.push([k, v]);
  } else {
    throw new InputError('Unsupported content type', 415);
  }

  const fields = {};
  for (const [k, v] of entries) {
    if (enc.encode(k).length > 200) throw new InputError('Field name too long');
    // Repeated names (checkbox groups) are joined.
    fields[k] = k in fields ? `${fields[k]}, ${v}` : v;
    if (enc.encode(fields[k]).length > LIMITS.maxFieldBytes) throw new InputError(`Field "${k}" too large`, 413);
  }

  const gotcha = fields._gotcha || '';
  const turnstileToken = fields['cf-turnstile-response'] || '';
  const data = {};
  for (const [k, v] of Object.entries(fields)) if (!k.startsWith('_') && k !== 'cf-turnstile-response') data[k] = v;
  if (Object.keys(data).length > LIMITS.maxFields) throw new InputError('Too many fields', 413);
  if (Object.keys(data).length === 0) throw new InputError('Empty submission');
  return { data, gotcha, turnstileToken };
}

// Accepts comma/whitespace separated origins; returns normalized space-separated string.
export function normalizeOrigins(text = '') {
  return text
    .split(/[\s,]+/)
    .filter(Boolean)
    .map((o) => {
      let u;
      try {
        u = new URL(o);
      } catch {
        throw new InputError(`Invalid origin: ${o}`);
      }
      if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new InputError(`Invalid origin: ${o}`);
      return u.origin;
    })
    .join(' ');
}

// Empty allow-list means any origin (including none, e.g. curl).
export function originAllowed(allowed, origin) {
  const list = (allowed || '').split(/[\s,]+/).filter(Boolean);
  if (list.length === 0) return true;
  return !!origin && list.includes(origin.toLowerCase().replace(/\/$/, ''));
}

export function requestOrigin(headers) {
  const origin = headers.get('Origin');
  if (origin && origin !== 'null') return origin;
  try {
    return new URL(headers.get('Referer')).origin;
  } catch {
    return '';
  }
}

export function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

export function csvCell(v) {
  let s = String(v ?? '');
  // Neutralize spreadsheet formula injection.
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export const toCsv = (rows) => rows.map((r) => r.map(csvCell).join(',')).join('\r\n') + '\r\n';

export function safeEqual(a, b) {
  const x = enc.encode(a);
  const y = enc.encode(b);
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) diff |= (x[i] | 0) ^ (y[i] | 0);
  return diff === 0;
}

const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');

export async function sha256Hex(s) {
  return hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));
}

export const hashIp = (ip, salt) => sha256Hex(`${salt}:${ip}`);

async function hmac(value, secret) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', key, enc.encode(value)));
}

// Session value = "<expiresMs>.<hmac>"; nothing else to store server-side.
export async function signSession(secret, ttlMs, now = Date.now()) {
  const exp = String(now + ttlMs);
  return `${exp}.${await hmac(exp, secret)}`;
}

export async function verifySession(value, secret, now = Date.now()) {
  const [exp, sig] = String(value || '').split('.');
  if (!exp || !sig || !(Number(exp) > now)) return false;
  return safeEqual(sig, await hmac(exp, secret));
}

export function getCookie(header, name) {
  for (const part of (header || '').split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return v.join('=');
  }
  return '';
}

function b64(s) {
  let bin = '';
  for (const b of enc.encode(s)) bin += String.fromCharCode(b);
  return btoa(bin);
}

// Minimal RFC 5322 message for the send_email binding. Body is base64 so any UTF-8 is safe.
export function buildMime({ from, to, subject, text, messageId, date = new Date() }) {
  const body = b64(text).replace(/.{76}/g, '$&\r\n');
  return [
    `From: ${from}`,
    `To: ${to}`,
    `Subject: =?UTF-8?B?${b64(subject)}?=`,
    `Message-ID: ${messageId}`,
    `Date: ${date.toUTCString()}`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: base64',
    '',
    body,
  ].join('\r\n');
}

export function formatSubmission(formName, data) {
  return `New submission: ${formName}\n\n` + Object.entries(data).map(([k, v]) => `${k}: ${v}`).join('\n');
}
