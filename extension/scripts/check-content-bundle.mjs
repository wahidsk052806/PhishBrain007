#!/usr/bin/env node
/**
 * Smoke-check the **built** content script (`dist/content.js`).
 *
 *   npm run build && npm run check:content
 *
 * Why it exists: a library build leaves `process.env.NODE_ENV` in the bundle,
 * and a content script runs in the page where `process` does not exist — React's
 * module header evaluated it immediately, so the shipped script died with
 * "process is not defined" *before* it registered its listener. Nothing on Gmail
 * was parsed or scanned, and the popup answered "No scan result yet for this
 * tab" with no explanation. Nothing in the source, the type check or the unit
 * tests can catch that: only evaluating the real bundle can.
 *
 * It also covers the "is a message actually open?" rule — Gmail's inbox list
 * carries sender avatars but no body, and treating that as an email produced a
 * verdict for a message nobody had opened.
 */
import { readFileSync, existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { JSDOM } from "jsdom";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const BUNDLE = resolve(ROOT, "dist/content.js");

if (!existsSync(BUNDLE)) {
  console.error("dist/content.js is missing — run `npm run build` first.");
  process.exit(1);
}

const bundle = readFileSync(BUNDLE, "utf8");
const GMAIL = "https://mail.google.com/mail/u/0/#inbox/thread-1";

const MESSAGE = `<html><body>
  <div role="main">
    <h3 class="iw"><span class="gD" email="billing@secure-paypa1.top" name="PayPal">PayPal</span></h3>
    <h2 class="hP">Your account is limited</h2>
    <div class="a3s">Confirm now: <a href="https://secure-paypa1.top/verify">paypal.com</a></div>
  </div>
</body></html>`;

// What Gmail's inbox really looks like: sender avatars in the list, no body.
const INBOX = `<html><body>
  <div role="main">
    <table><tr class="zA">
      <td><span data-hovercard-id="someone@example.com" class="zF" email="someone@example.com">S</span></td>
      <td><span class="y2">Your account is limited — act now</span></td>
    </tr></table>
  </div>
</body></html>`;

/** Evaluate the shipped bundle in a page that only provides `chrome`. */
function mount(html) {
  const dom = new JSDOM(html, { url: GMAIL, runScripts: "outside-only", pretendToBeVisual: true });
  const { window } = dom;
  const listeners = [];
  const sent = [];
  const store = {};

  window.chrome = {
    runtime: {
      onMessage: { addListener: (cb) => listeners.push(cb) },
      sendMessage: (message, cb) => {
        sent.push(message);
        cb?.(undefined);
      },
      getURL: (path) => `chrome-extension://test/${path}`,
      lastError: undefined,
    },
    storage: {
      local: {
        get: (keys, cb) => {
          const out = Array.isArray(keys)
            ? Object.fromEntries(keys.filter((k) => k in store).map((k) => [k, store[k]]))
            : { ...store };
          cb(out);
        },
        set: (items, cb) => {
          Object.assign(store, items);
          cb?.();
        },
        remove: (_keys, cb) => cb?.(),
      },
      onChanged: { addListener() {} },
    },
    tabs: { sendMessage: (_id, _message, cb) => cb?.(undefined) },
  };

  window.eval(bundle);
  return { window, listeners, sent };
}

function ask(listeners, message) {
  return new Promise((resolve) => {
    const listener = listeners.at(-1);
    const answered = listener(message, {}, resolve);
    if (answered !== true) resolve(undefined);
  });
}

const results = [];
function check(name, ok, extra = "") {
  results.push({ name, ok, extra });
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${extra ? ` — ${extra}` : ""}`);
}

// 1. A Gmail message is open.
{
  const { window, listeners, sent } = mount(MESSAGE);
  await new Promise((r) => setTimeout(r, 50));

  const pong = await ask(listeners, { type: "PING" });
  check("answers PING", pong?.ok === true, JSON.stringify(pong));

  const before = sent.filter((m) => m.type === "EMAIL_SUMMARY").length;
  const reply = await ask(listeners, { type: "REPARSE_EMAIL" });
  await new Promise((r) => setTimeout(r, 100));
  const reports = sent.filter((m) => m.type === "EMAIL_SUMMARY");

  check("REPARSE_EMAIL reports ok", reply?.ok === true, JSON.stringify(reply));
  check("REPARSE_EMAIL re-reports the message", reports.length > before, `${reports.length} report(s)`);

  const email = reports.at(-1)?.email ?? {};
  check("report carries the sender", email.sender === "billing@secure-paypa1.top", email.sender);
  check(
    "report carries the unwrapped link",
    (email.links ?? []).some((link) => link.includes("secure-paypa1.top")),
    JSON.stringify(email.links),
  );

  // 1b. "Keep scanning": the mailbox is polled, so the next message is read
  // without a page reload and without the user pressing Rescan.
  const pane = window.document.querySelector('[role="main"]');
  pane?.querySelector("span.gD")?.setAttribute("email", "second@phish.example");
  if (pane?.querySelector("div.a3s")) pane.querySelector("div.a3s").textContent = "A second message arrived.";
  await new Promise((r) => setTimeout(r, 3000));

  const latest = sent.filter((m) => m.type === "EMAIL_SUMMARY").at(-1);
  check(
    "polls the mailbox and reports the next message",
    latest?.email?.sender === "second@phish.example",
    latest?.email?.sender,
  );
}

// 2. The inbox list is showing, so no message is open.
{
  const { listeners, sent } = mount(INBOX);
  await new Promise((r) => setTimeout(r, 50));
  const reply = await ask(listeners, { type: "REPARSE_EMAIL" });
  check("answers ok:false with no message open", reply?.ok === false, JSON.stringify(reply));
  check(
    "does not report the inbox as an email",
    sent.every((m) => m.type !== "EMAIL_SUMMARY"),
    `${sent.filter((m) => m.type === "EMAIL_SUMMARY").length} report(s)`,
  );
}

const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
process.exit(failed.length ? 1 : 0);
