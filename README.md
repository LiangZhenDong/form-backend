# Form Backend

**A form backend for static websites that runs on your own Cloudflare account. It's free forever when self-hosted, with one-click deploy.**

Point any HTML `<form>` at your Worker and the submissions land in your own D1 database. You can get notified by Telegram or email, browse submissions in a small admin page, and export them to CSV. There's no SaaS in the middle and nothing to maintain beyond a single Worker.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/LiangZhenDong/form-backend)

## Features

- **Works with any static site.** Plain HTML forms, `fetch()`/JSON, `urlencoded` and `multipart` bodies.
- **Your data, your account.** Submissions are stored in Cloudflare D1. IPs are stored only as salted SHA-256 hashes.
- **Spam protection.** Honeypot field, optional [Cloudflare Turnstile](https://developers.cloudflare.com/turnstile/) per form, and a per-IP rate limit.
- **Origin lock.** Each form only accepts submissions from the origins you allow, with proper CORS.
- **Notifications.** Telegram bot and/or email through Cloudflare Email Routing. Notifications are sent after the submission is saved, so a failed notification never loses data.
- **Admin UI.** Create and edit forms, browse submissions with pagination, delete them, and export CSV. Protected by a token.
- **Tiny.** One Worker, zero runtime dependencies, under 500 lines of plain JavaScript.
- **Free.** Fits comfortably in the Workers + D1 free tiers for typical sites.

## 30-second quick start

1. Click **Deploy to Cloudflare** above, or follow [Manual setup](#manual-setup).
2. Open `https://<your-worker>/admin`, log in with your `ADMIN_TOKEN`, and create a form.
3. Paste the snippet into your site:

```html
<form action="https://<your-worker>/f/<form-id>" method="POST">
  <input name="email" type="email" required>
  <textarea name="message" required></textarea>
  <!-- honeypot: keep hidden; bots fill it, humans don't -->
  <input type="text" name="_gotcha" style="display:none" tabindex="-1" autocomplete="off">
  <button type="submit">Send</button>
</form>
```

After an HTML post, the visitor gets a 303 redirect to the form's redirect URL, or to a built-in "Thanks" page.

Submitting with JavaScript works too:

```js
await fetch('https://<your-worker>/f/<form-id>', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email: 'me@example.com', message: 'Hi!' }),
}); // -> {"ok":true}
```

Errors come back as `{"ok":false,"error":"..."}` with an HTTP status: `400`, `403` (wrong origin or failed captcha), `404`, `413`, `415`, or `429`.

## Manual setup

Requirements: Node 18+ and a Cloudflare account.

```sh
git clone https://github.com/LiangZhenDong/form-backend && cd form-backend
npm install
npx wrangler login

# 1. Create the database and paste the printed database_id into wrangler.toml
npx wrangler d1 create form-backend

# 2. Create the tables
npx wrangler d1 migrations apply DB --remote

# 3. Secrets (you'll be prompted for each value)
npx wrangler secret put ADMIN_TOKEN     # 16+ random characters
npx wrangler secret put IP_SALT         # any random string
npx wrangler secret put TELEGRAM_BOT_TOKEN   # optional
npx wrangler secret put TURNSTILE_SECRET     # optional

# 4. Deploy
npx wrangler deploy
```

To generate a random token, run `node -e "console.log(crypto.randomUUID()+crypto.randomUUID())"`.

**Custom domain:** in `wrangler.toml`, uncomment `routes = [{ pattern = "form.example.com", custom_domain = true }]`. The domain's zone must be on your Cloudflare account. Then run `npx wrangler deploy` again.

**Local development:** `cp .dev.vars.example .dev.vars`, then `npm run dev`. This applies migrations to a local D1 and starts `wrangler dev`. Run `npm test` to run the logic tests.

## Configuration

| Name | Kind | Required | Description |
|---|---|---|---|
| `DB` | D1 binding | yes | Database holding forms and submissions. |
| `ADMIN_TOKEN` | secret | yes | Admin login token, 16+ chars. You can also send it as `Authorization: Bearer <token>`. Changing it logs out all sessions. |
| `IP_SALT` | secret | yes | Salt for hashing submitter IPs. Raw IPs are never stored. |
| `TELEGRAM_BOT_TOKEN` | secret | no | Bot token from [@BotFather](https://t.me/BotFather). Set a chat id on each form. |
| `TURNSTILE_SECRET` | secret | no | Turnstile secret key. Enable Turnstile per form in the admin. |
| `RATE_LIMIT_PER_MINUTE` | var | no | Max submissions per form per IP per minute (default `10`). |
| `MAIL_FROM` | var | no | Sender address for email notifications, on a zone with Email Routing enabled. |
| `EMAIL` | `send_email` binding | no | Enables email notifications. Uncomment `[[send_email]]` in `wrangler.toml`. |

Per-form settings are managed in `/admin`: name, allowed origins, redirect URL, notify email, Telegram chat id, and the Turnstile toggle.

### Email notifications

Email uses Cloudflare Email Routing's [`send_email` binding](https://developers.cloudflare.com/email-routing/email-workers/send-email-workers/). It can **only send to addresses that are verified destination addresses** in Email Routing on your zone. It isn't a general-purpose mailer. To set it up:

1. Enable Email Routing on your domain.
2. Add and verify the address you want to notify.
3. Set `MAIL_FROM` to an address on that domain.
4. Uncomment `[[send_email]]` in `wrangler.toml`.

### Telegram notifications

1. Create a bot with @BotFather and set `TELEGRAM_BOT_TOKEN`.
2. Send your bot a message.
3. Get your chat id from `https://api.telegram.org/bot<token>/getUpdates`.
4. Paste the chat id into the form settings.

### Turnstile

Add the widget to your form, e.g. `<div class="cf-turnstile" data-sitekey="..."></div>` plus Cloudflare's script. Set `TURNSTILE_SECRET`, then tick "Require Cloudflare Turnstile" on the form. If the toggle is on but the secret is missing, submissions are rejected.

## Limits

- Max request body: 100 KB. Max 50 fields, 10 KB per field value, 200 bytes per field name.
- File uploads are ignored; only text fields are stored.
- Field names starting with `_` (e.g. `_gotcha`) and `cf-turnstile-response` are not stored.
- The rate limit is a best-effort count in D1. A parallel burst can slip a few extra submissions through.
- CSV export builds the file in memory, which is fine for tens of thousands of rows.
- If a form has allowed origins set, requests without an `Origin` or `Referer` header (e.g. curl) are rejected.

## FAQ

**Is it really free?** Yes. It runs on your own Cloudflare account, and the Workers and D1 free tiers cover most personal and small-business sites. It's MIT licensed.

**Where is my data?** In a D1 database on your Cloudflare account. Nobody else has access to it.

**Can I use it with Hugo / Jekyll / Astro / plain HTML / GitHub Pages / Netlify?** Yes. It only needs a `<form action>` or a `fetch()` call.

**How do I delete all data?** Delete the D1 database, or delete individual submissions in the admin.

**Is there a hosted version?** A hosted version is planned at `form.zdtoolx.com` for people who don't want to run their own. Self-hosting will stay free.

**Support?** Open a GitHub issue, or email support@zdtoolx.com.

## License

[MIT](LICENSE) © ZDToolx
