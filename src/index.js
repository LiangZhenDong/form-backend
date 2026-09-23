import { EmailMessage } from 'cloudflare:email';
import {
  InputError,
  LIMITS,
  parseSubmission,
  normalizeOrigins,
  originAllowed,
  requestOrigin,
  escapeHtml as e,
  toCsv,
  safeEqual,
  hashIp,
  signSession,
  verifySession,
  getCookie,
  buildMime,
  formatSubmission,
} from './logic.js';

const SESSION_COOKIE = 'fb_session';
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const PAGE_SIZE = 50;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const parts = url.pathname.split('/').filter(Boolean);
    try {
      if (parts[0] === 'f' && parts.length === 2) return await submit(request, env, ctx, parts[1]);
      if (parts[0] === 'admin') return await admin(request, env, url, parts.slice(1));
      if (url.pathname === '/thanks') return page('Thanks', '<h1>Thanks!</h1><p>Your submission was received.</p>');
      if (url.pathname === '/') return page('Form backend', '<h1>Form backend</h1><p>This server accepts form submissions at <code>/f/&lt;form-id&gt;</code>. <a href="/admin">Admin</a></p>');
      return new Response('Not found', { status: 404 });
    } catch (err) {
      if (err instanceof InputError) return new Response(err.message, { status: err.status });
      console.error(err);
      return new Response('Internal error', { status: 500 });
    }
  },
};

// ---------- Public submission endpoint ----------

async function submit(request, env, ctx, formId) {
  const form = await env.DB.prepare('SELECT * FROM forms WHERE id = ?').bind(formId).first();
  const origin = requestOrigin(request.headers);
  const cors = form && origin && originAllowed(form.allowed_origins, origin) ? { 'Access-Control-Allow-Origin': origin, Vary: 'Origin' } : {};
  const json = /json/i.test(request.headers.get('Content-Type') || '') || /application\/json/i.test(request.headers.get('Accept') || '');
  const fail = (status, error) =>
    json ? Response.json({ ok: false, error }, { status, headers: cors }) : page('Error', `<h1>Submission failed</h1><p>${e(error)}</p>`, status, cors);

  if (!form) return fail(404, 'Form not found');
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: cors['Access-Control-Allow-Origin'] ? 204 : 403,
      headers: { ...cors, 'Access-Control-Allow-Methods': 'POST', 'Access-Control-Allow-Headers': 'Content-Type, Accept', 'Access-Control-Max-Age': '86400' },
    });
  }
  if (request.method !== 'POST') return fail(405, 'Method not allowed');
  if (!originAllowed(form.allowed_origins, origin)) return fail(403, 'Origin not allowed');
  if (Number(request.headers.get('Content-Length')) > LIMITS.maxBodyBytes) return fail(413, 'Body too large');

  let parsed;
  try {
    parsed = await parseSubmission(request.headers.get('Content-Type') || '', await request.arrayBuffer());
  } catch (err) {
    if (err instanceof InputError) return fail(err.status, err.message);
    throw err;
  }

  const ok = () => (json ? Response.json({ ok: true }, { headers: cors }) : Response.redirect(form.redirect_url || new URL('/thanks', request.url).href, 303));
  // Bots get a normal-looking success so they don't adapt.
  if (parsed.gotcha) return ok();

  if (!env.IP_SALT) throw new Error('IP_SALT secret is not set');
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const ipHash = await hashIp(ip, env.IP_SALT);

  // ponytail: rate limit = COUNT over recent rows in D1. Not atomic (a parallel burst can slip a few over) and only per form+IP.
  // Upgrade path: Workers Rate Limiting binding or a Durable Object counter.
  const limit = Number(env.RATE_LIMIT_PER_MINUTE) || 10;
  const since = new Date(Date.now() - 60_000).toISOString();
  const { n } = await env.DB.prepare('SELECT COUNT(*) AS n FROM submissions WHERE form_id = ? AND ip_hash = ? AND created_at > ?')
    .bind(form.id, ipHash, since)
    .first();
  if (n >= limit) return fail(429, 'Too many submissions, please try again in a minute');

  if (form.turnstile && !(await verifyTurnstile(env.TURNSTILE_SECRET, parsed.turnstileToken, ip))) return fail(403, 'Captcha verification failed');

  await env.DB.prepare('INSERT INTO submissions (form_id, data, ip_hash, user_agent, origin, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .bind(form.id, JSON.stringify(parsed.data), ipHash, (request.headers.get('User-Agent') || '').slice(0, 500), origin.slice(0, 200), new Date().toISOString())
    .run();

  // Stored first; notifications run after the response and can fail without losing data.
  ctx.waitUntil(notify(env, form, parsed.data));
  return ok();
}

async function verifyTurnstile(secret, token, ip) {
  if (!secret || !token) return false;
  const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    body: new URLSearchParams({ secret, response: token, remoteip: ip }),
  });
  return res.ok && (await res.json()).success === true;
}

async function notify(env, form, data) {
  const text = formatSubmission(form.name, data);
  const jobs = [];
  if (env.TELEGRAM_BOT_TOKEN && form.notify_telegram_chat_id) {
    jobs.push(
      fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: form.notify_telegram_chat_id, text: text.slice(0, 4000) }),
      }).then((r) => {
        if (!r.ok) throw new Error(`Telegram HTTP ${r.status}`);
      }),
    );
  }
  if (env.EMAIL && env.MAIL_FROM && form.notify_email) {
    const raw = buildMime({
      from: env.MAIL_FROM,
      to: form.notify_email,
      subject: `New submission: ${form.name}`,
      text,
      messageId: `<${crypto.randomUUID()}@${env.MAIL_FROM.split('@')[1]}>`,
    });
    jobs.push(env.EMAIL.send(new EmailMessage(env.MAIL_FROM, form.notify_email, raw)));
  }
  for (const r of await Promise.allSettled(jobs)) if (r.status === 'rejected') console.error('notify failed:', r.reason);
}

// ---------- Admin ----------

async function admin(request, env, url, parts) {
  if (!env.ADMIN_TOKEN || env.ADMIN_TOKEN.length < 16) return new Response('Admin disabled: set an ADMIN_TOKEN secret (16+ characters).', { status: 503 });
  // Rotating ADMIN_TOKEN invalidates all sessions.
  const secret = `session:${env.ADMIN_TOKEN}`;

  if (parts[0] === 'login') {
    if (request.method !== 'POST') return loginPage();
    const token = String((await request.formData()).get('token') || '');
    if (!safeEqual(token, env.ADMIN_TOKEN)) return loginPage('Wrong token', 401);
    const cookie = `${SESSION_COOKIE}=${await signSession(secret, SESSION_TTL_MS)}; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL_MS / 1000}`;
    return new Response(null, { status: 303, headers: { Location: '/admin', 'Set-Cookie': cookie } });
  }

  if (!(await isAdmin(request, env.ADMIN_TOKEN, secret))) {
    return request.method === 'GET' ? Response.redirect(new URL('/admin/login', url).href, 303) : new Response('Unauthorized', { status: 401 });
  }

  const post = request.method === 'POST';
  const [section, id, sub, sid, action] = parts;
  if (!section) return listForms(env);
  if (section === 'logout' && post) {
    return new Response(null, { status: 303, headers: { Location: '/admin/login', 'Set-Cookie': `${SESSION_COOKIE}=; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=0` } });
  }
  if (section === 'forms' && id === 'new' && !sub) return post ? saveForm(request, env, null) : adminPage('New form', `<h1>New form</h1>${formEditor()}`);
  if (section === 'forms' && id && !sub) return post ? saveForm(request, env, id) : formDetail(env, url, id);
  if (section === 'forms' && sub === 'export.csv' && !post) return exportCsv(env, id);
  if (section === 'forms' && sub === 'submissions' && action === 'delete' && post) {
    await env.DB.prepare('DELETE FROM submissions WHERE id = ? AND form_id = ?').bind(Number(sid), id).run();
    return new Response(null, { status: 303, headers: { Location: `/admin/forms/${encodeURIComponent(id)}` } });
  }
  return new Response('Not found', { status: 404 });
}

async function isAdmin(request, token, secret) {
  const auth = request.headers.get('Authorization') || '';
  if (auth.startsWith('Bearer ')) return safeEqual(auth.slice(7), token);
  return verifySession(getCookie(request.headers.get('Cookie'), SESSION_COOKIE), secret);
}

async function listForms(env) {
  const { results } = await env.DB.prepare(
    'SELECT f.id, f.name, f.created_at, COUNT(s.id) AS n FROM forms f LEFT JOIN submissions s ON s.form_id = f.id GROUP BY f.id ORDER BY f.created_at DESC',
  ).all();
  const rows = results.map((f) => `<tr><td><a href="/admin/forms/${e(f.id)}">${e(f.name)}</a></td><td><code>${e(f.id)}</code></td><td>${f.n}</td><td>${e(f.created_at)}</td></tr>`);
  return adminPage(
    'Forms',
    `<h1>Forms <a class="btn" href="/admin/forms/new">New form</a></h1>` +
      (rows.length ? `<table><tr><th>Name</th><th>ID</th><th>Submissions</th><th>Created</th></tr>${rows.join('')}</table>` : '<p>No forms yet.</p>'),
  );
}

async function saveForm(request, env, id) {
  const f = await request.formData();
  const get = (k, max) => {
    const v = String(f.get(k) || '').trim();
    if (v.length > max) throw new InputError(`${k} is too long`);
    return v;
  };
  const name = get('name', 200);
  const allowed = normalizeOrigins(get('allowed_origins', 2000));
  const redirect = get('redirect_url', 2000);
  const email = get('notify_email', 254);
  const chat = get('notify_telegram_chat_id', 64);
  if (!name) throw new InputError('Name is required');
  if (redirect && !/^https?:$/.test(URL.canParse(redirect) && new URL(redirect).protocol)) throw new InputError('Redirect URL must be an http(s) URL');
  if (email && !/^[^\s@<>,;]+@[^\s@<>,;]+$/.test(email)) throw new InputError('Invalid email');
  if (chat && !/^(-?\d+|@\w+)$/.test(chat)) throw new InputError('Telegram chat id must be a number or @channel');
  const values = [name, allowed, redirect, email, chat, f.get('turnstile') ? 1 : 0];

  if (id) {
    const r = await env.DB.prepare(
      'UPDATE forms SET name = ?, allowed_origins = ?, redirect_url = ?, notify_email = ?, notify_telegram_chat_id = ?, turnstile = ? WHERE id = ?',
    )
      .bind(...values, id)
      .run();
    if (!r.meta.changes) return new Response('Not found', { status: 404 });
  } else {
    id = crypto.randomUUID().replace(/-/g, '').slice(0, 12);
    await env.DB.prepare(
      'INSERT INTO forms (name, allowed_origins, redirect_url, notify_email, notify_telegram_chat_id, turnstile, id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    )
      .bind(...values, id, new Date().toISOString())
      .run();
  }
  return new Response(null, { status: 303, headers: { Location: `/admin/forms/${id}` } });
}

async function formDetail(env, url, id) {
  const form = await env.DB.prepare('SELECT * FROM forms WHERE id = ?').bind(id).first();
  if (!form) return new Response('Not found', { status: 404 });
  const pageNo = Math.max(1, parseInt(url.searchParams.get('page'), 10) || 1);
  // ponytail: OFFSET paging scans skipped rows; fine for thousands of submissions. Upgrade: keyset paging on id.
  const { results } = await env.DB.prepare('SELECT * FROM submissions WHERE form_id = ? ORDER BY id DESC LIMIT ? OFFSET ?')
    .bind(id, PAGE_SIZE + 1, (pageNo - 1) * PAGE_SIZE)
    .all();
  const rows = results.slice(0, PAGE_SIZE).map((r) => ({ ...r, data: JSON.parse(r.data) }));
  const keys = [...new Set(rows.flatMap((r) => Object.keys(r.data)))];
  const base = `/admin/forms/${e(id)}`;

  const table = rows.length
    ? `<table><tr><th>Date</th>${keys.map((k) => `<th>${e(k)}</th>`).join('')}<th>Origin</th><th></th></tr>` +
      rows
        .map(
          (r) =>
            `<tr><td>${e(r.created_at)}</td>${keys.map((k) => `<td>${e(r.data[k])}</td>`).join('')}<td>${e(r.origin)}</td>` +
            `<td><form method="POST" action="${base}/submissions/${r.id}/delete"><button class="danger">Delete</button></form></td></tr>`,
        )
        .join('') +
      '</table>'
    : '<p>No submissions yet.</p>';
  const pager =
    (pageNo > 1 ? `<a href="${base}?page=${pageNo - 1}">&larr; Newer</a> ` : '') + (results.length > PAGE_SIZE ? `<a href="${base}?page=${pageNo + 1}">Older &rarr;</a>` : '');

  const snippet = `<form action="${url.origin}/f/${form.id}" method="POST">
  <input name="email" type="email" required>
  <textarea name="message" required></textarea>
  <input type="text" name="_gotcha" style="display:none" tabindex="-1" autocomplete="off">
  <button type="submit">Send</button>
</form>`;

  return adminPage(
    form.name,
    `<h1>${e(form.name)}</h1><p>Endpoint: <code>${e(url.origin)}/f/${e(form.id)}</code></p><pre>${e(snippet)}</pre>` +
      `<h2>Settings</h2>${formEditor(form)}` +
      `<h2>Submissions <a class="btn" href="${base}/export.csv">Export CSV</a></h2>${table}<p>${pager}</p>`,
  );
}

async function exportCsv(env, id) {
  // ponytail: builds the whole CSV in memory; fine up to tens of thousands of rows. Upgrade: page through rows into a ReadableStream.
  const { results } = await env.DB.prepare('SELECT id, created_at, origin, user_agent, data FROM submissions WHERE form_id = ? ORDER BY id').bind(id).all();
  const rows = results.map((r) => ({ ...r, data: JSON.parse(r.data) }));
  const keys = [...new Set(rows.flatMap((r) => Object.keys(r.data)))];
  const csv = toCsv([['id', 'created_at', 'origin', 'user_agent', ...keys], ...rows.map((r) => [r.id, r.created_at, r.origin, r.user_agent, ...keys.map((k) => r.data[k])])]);
  return new Response(csv, {
    headers: { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': `attachment; filename="form-${id.replace(/[^\w-]/g, '')}.csv"` },
  });
}

function formEditor(f = {}) {
  return `<form method="POST" class="card">
<label>Name<input name="name" required maxlength="200" value="${e(f.name)}"></label>
<label>Allowed origins <small>space or comma separated, e.g. https://example.com &mdash; empty allows any origin</small><textarea name="allowed_origins" rows="2">${e(f.allowed_origins)}</textarea></label>
<label>Redirect URL <small>after a normal HTML form post; empty shows a built-in thanks page</small><input name="redirect_url" type="url" value="${e(f.redirect_url)}"></label>
<label>Notify email <small>must be a verified Email Routing destination address</small><input name="notify_email" type="email" value="${e(f.notify_email)}"></label>
<label>Telegram chat id <small>requires the TELEGRAM_BOT_TOKEN secret</small><input name="notify_telegram_chat_id" value="${e(f.notify_telegram_chat_id)}"></label>
<label class="check"><input type="checkbox" name="turnstile"${f.turnstile ? ' checked' : ''}> Require Cloudflare Turnstile (needs the TURNSTILE_SECRET secret)</label>
<button>Save</button>
</form>`;
}

function loginPage(error = '', status = 200) {
  return page(
    'Admin login',
    `<h1>Admin login</h1>${error ? `<p class="error">${e(error)}</p>` : ''}<form method="POST" action="/admin/login" class="card"><label>Admin token<input name="token" type="password" required autofocus></label><button>Log in</button></form>`,
    status,
  );
}

function adminPage(title, body) {
  const nav = '<nav><a href="/admin">Forms</a><form method="POST" action="/admin/logout"><button class="link">Log out</button></form></nav>';
  return page(title, nav + body, 200, { 'Cache-Control': 'no-store' });
}

const CSS = `body{font:15px/1.5 system-ui,sans-serif;margin:0;color:#1f2328;background:#f6f8fa}main{max-width:1100px;margin:0 auto;padding:24px}
nav{display:flex;gap:16px;align-items:center;margin-bottom:16px}nav form{margin:0}
table{border-collapse:collapse;width:100%;background:#fff}th,td{border:1px solid #d0d7de;padding:6px 8px;text-align:left;vertical-align:top;max-width:28em;overflow-wrap:anywhere}th{background:#eef1f4}
td form{margin:0}.card{background:#fff;border:1px solid #d0d7de;border-radius:8px;padding:16px;max-width:560px}
label{display:block;margin-bottom:12px;font-weight:600}label small{font-weight:400;color:#57606a}input,textarea{display:block;width:100%;box-sizing:border-box;padding:6px 8px;margin-top:4px;font:inherit;border:1px solid #d0d7de;border-radius:6px}
.check{font-weight:400}.check input{display:inline;width:auto}
button,.btn{font:inherit;font-size:14px;padding:5px 12px;border-radius:6px;border:1px solid #1f883d;background:#1f883d;color:#fff;cursor:pointer;text-decoration:none}
.btn{margin-left:8px;vertical-align:middle}.danger{background:#fff;color:#cf222e;border-color:#cf222e}.link{background:none;border:0;color:#0969da;padding:0}
pre{background:#fff;border:1px solid #d0d7de;padding:12px;overflow:auto}.error{color:#cf222e}a{color:#0969da}`;

function page(title, body, status = 200, headers = {}) {
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${e(title)}</title><style>${CSS}</style></head><body><main>${body}</main></body></html>`;
  return new Response(html, {
    status,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
      'Referrer-Policy': 'no-referrer',
      ...headers,
    },
  });
}
