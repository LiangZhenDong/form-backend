import assert from 'node:assert/strict';
import * as L from '../src/logic.js';

const buf = (s) => new TextEncoder().encode(s);

// Body parsing
let r = await L.parseSubmission('application/x-www-form-urlencoded', buf('name=Ann&tag=a&tag=b&_gotcha=&cf-turnstile-response=tok'));
assert.deepEqual(r, { data: { name: 'Ann', tag: 'a, b' }, gotcha: '', turnstileToken: 'tok' });

r = await L.parseSubmission('application/json; charset=utf-8', buf('{"email":"a@b.c","n":3,"_gotcha":"bot"}'));
assert.deepEqual(r.data, { email: 'a@b.c', n: '3' });
assert.equal(r.gotcha, 'bot');

const fd = new FormData();
fd.append('msg', 'hi');
fd.append('file', new Blob(['x']), 'x.txt');
const mp = new Request('http://x', { method: 'POST', body: fd });
r = await L.parseSubmission(mp.headers.get('content-type'), await mp.arrayBuffer());
assert.deepEqual(r.data, { msg: 'hi' });

const rejects = (ct, body, status) => assert.rejects(L.parseSubmission(ct, buf(body)), (e) => e instanceof L.InputError && e.status === status);
await rejects('application/json', '[1]', 400);
await rejects('application/json', '{bad', 400);
await rejects('text/plain', 'a', 415);
await rejects('application/x-www-form-urlencoded', '_gotcha=', 400);
await rejects('application/x-www-form-urlencoded', 'a=' + 'x'.repeat(10 * 1024 + 1), 413);
await rejects('application/x-www-form-urlencoded', 'a=' + 'x'.repeat(100 * 1024), 413);
await rejects('application/x-www-form-urlencoded', Array.from({ length: 51 }, (_, i) => `f${i}=1`).join('&'), 413);

// Origins
assert.equal(L.normalizeOrigins('https://A.com/path, http://b.com:8080\nhttps://c.com/'), 'https://a.com http://b.com:8080 https://c.com');
assert.throws(() => L.normalizeOrigins('javascript:alert(1)'), L.InputError);
assert.equal(L.originAllowed('', ''), true);
assert.equal(L.originAllowed('https://a.com https://b.com', 'https://b.com'), true);
assert.equal(L.originAllowed('https://a.com', 'https://evil.com'), false);
assert.equal(L.originAllowed('https://a.com', ''), false);
assert.equal(L.requestOrigin(new Headers({ Referer: 'https://a.com/contact?x=1' })), 'https://a.com');
assert.equal(L.requestOrigin(new Headers({ Origin: 'null' })), '');

// Escaping
assert.equal(L.escapeHtml(`<img src=x onerror="a('b')">&`), '&lt;img src=x onerror=&quot;a(&#39;b&#39;)&quot;&gt;&amp;');
assert.equal(L.escapeHtml(undefined), '');
assert.equal(L.toCsv([['a', 'b'], ['x,y', 'say "hi"'], ['=SUM(A1)', 'line\nbreak']]), 'a,b\r\n"x,y","say ""hi"""\r\n\'=SUM(A1),"line\nbreak"\r\n');

// Constant-time compare + session cookie
assert.equal(L.safeEqual('secret-token', 'secret-token'), true);
assert.equal(L.safeEqual('secret-token', 'secret-tokeX'), false);
assert.equal(L.safeEqual('secret', 'secret-token'), false);
const s = await L.signSession('k', 1000, 5000);
assert.equal(await L.verifySession(s, 'k', 5500), true);
assert.equal(await L.verifySession(s, 'k', 6001), false); // expired
assert.equal(await L.verifySession(s, 'other', 5500), false);
assert.equal(await L.verifySession(s.replace(/^\d+/, '99999999'), 'k', 5500), false); // extended expiry, stale sig
assert.equal(L.getCookie('a=1; fb_session=x.y=z', 'fb_session'), 'x.y=z');

// IP hash
assert.match(await L.hashIp('1.2.3.4', 'salt'), /^[0-9a-f]{64}$/);
assert.notEqual(await L.hashIp('1.2.3.4', 'salt'), await L.hashIp('1.2.3.4', 'pepper'));

// MIME
const mime = L.buildMime({ from: 'f@x.com', to: 't@y.com', subject: 'Hé', text: 'héllo', messageId: '<1@x.com>' });
assert.match(mime, /^From: f@x\.com\r\nTo: t@y\.com\r\nSubject: =\?UTF-8\?B\?SMOp\?=\r\n/);
assert.equal(Buffer.from(mime.split('\r\n\r\n')[1], 'base64').toString(), 'héllo');

console.log('logic tests passed');
