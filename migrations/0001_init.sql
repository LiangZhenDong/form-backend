CREATE TABLE forms (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  allowed_origins TEXT NOT NULL DEFAULT '',          -- space separated origins; empty = any
  redirect_url TEXT NOT NULL DEFAULT '',
  notify_email TEXT NOT NULL DEFAULT '',
  notify_telegram_chat_id TEXT NOT NULL DEFAULT '',
  turnstile INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL                           -- ISO 8601 UTC
);

CREATE TABLE submissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  form_id TEXT NOT NULL REFERENCES forms(id) ON DELETE CASCADE,
  data TEXT NOT NULL,                                -- JSON object of field name -> string
  ip_hash TEXT NOT NULL,                             -- SHA-256(IP_SALT + IP), never the raw IP
  user_agent TEXT NOT NULL DEFAULT '',
  origin TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);

CREATE INDEX submissions_form ON submissions (form_id, id);
CREATE INDEX submissions_rate ON submissions (form_id, ip_hash, created_at);
