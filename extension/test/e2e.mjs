// End-to-end test of the extension in a real Chromium, against a running `pop demo`.
//   POP_PAIRING_TOKEN=0123456789abcdef0123 ./target/release/pop demo &
//   POP_PAIRING_TOKEN=0123456789abcdef0123 node extension/test/e2e.mjs [screenshot-dir]
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import path from "node:path";
import os from "node:os";
import fs from "node:fs";
import assert from "node:assert/strict";

// require() also finds a globally installed Playwright through NODE_PATH
const { chromium } = createRequire(import.meta.url)("playwright");

const ext = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const shots = process.argv[2];
const token = process.env.POP_PAIRING_TOKEN;
assert.ok(token, "set POP_PAIRING_TOKEN to the demo's pairing token");
const FEED = "http://127.0.0.1:4000";

const profile = fs.mkdtempSync(path.join(os.tmpdir(), "pop-ext-"));
const ctx = await chromium.launchPersistentContext(profile, {
  channel: "chromium",
  headless: true,
  args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`],
  viewport: { width: 900, height: 1100 },
  deviceScaleFactor: shots ? 2 : 1,
});
try {
  const sw = ctx.serviceWorkers()[0] ?? (await ctx.waitForEvent("serviceworker"));
  // directory requests go through the demo's relay (ohttp.js)
  await sw.evaluate((t) => chrome.storage.local.set({ token: t, reportLikes: true, relayUrl: "http://127.0.0.1:4004/directory" }), token);

  const page = await ctx.newPage();
  const badgeAfter = (handle) => page.locator(`[data-pop-account][data-pop-handle="${handle}"] + .pop-badge`);
  const count = (post) => page.locator(`[data-pop-post="${post}"] .pop-count`);

  await page.goto(FEED);
  await count("p3").waitFor();
  // Alice and Bob bound their accounts and the directory saw their codes: badges
  assert.ok((await badgeAfter("alice").count()) >= 1, "alice has a badge");
  assert.ok((await badgeAfter("bob").count()) >= 1, "bob has a badge");
  // Carol enrolled but bound nothing; dailytruth copied Alice's code; the bots are bots: no badge
  for (const h of ["carol", "dailytruth", "patriot01"]) assert.equal(await badgeAfter(h).count(), 0, `${h} has no badge`);
  // 40 farm likes on p2 but one verified person; p3 has three
  assert.equal(await count("p2").textContent(), "1 verified");
  assert.equal(await count("p3").textContent(), "3 verified");
  assert.equal(await count("p1").textContent(), "0 verified");
  if (shots) await page.screenshot({ path: path.join(shots, "feed.png") });

  // The impostor's profile shows Alice's code in its bio and still gets no badge
  await page.goto(`${FEED}/u/dailytruth`);
  await count("p2").waitFor();
  assert.match(await page.locator("[data-pop-bio]").textContent(), /pop1-/);
  assert.equal(await page.locator(".pop-badge").count(), 0);

  // Liking as Alice reports a one-per-person tag through her holder app
  await page.goto(FEED);
  await page.selectOption("#who", "alice");
  await count("p1").waitFor();
  await page.locator('[data-pop-like="p1"]').click();
  await page.waitForFunction(() => document.querySelector('[data-pop-post="p1"] .pop-count')?.textContent === "1 verified", null, { timeout: 60_000 });
  // unlike and like again: still one person
  await page.locator('[data-pop-like="p1"]').click();
  await page.locator('[data-pop-like="p1"]').click();
  await page.waitForTimeout(8000);
  await page.reload();
  await count("p1").waitFor();
  assert.equal(await count("p1").textContent(), "1 verified");
  assert.ok(await count("p1").evaluate((e) => e.classList.contains("pop-mine")), "own like is marked");

  // With reporting switched off, a like is not reported
  await sw.evaluate(() => chrome.storage.local.set({ reportLikes: false }));
  await page.reload();
  await count("p4").waitFor();
  await page.locator('[data-pop-like="p4"]').click();
  await page.waitForTimeout(6000);
  await page.reload();
  await count("p4").waitFor();
  assert.equal(await count("p4").textContent(), "0 verified");

  // every directory request above went through the relay
  assert.ok((await sw.evaluate(() => PopOhttp.sent)) > 0, "directory requests went through the relay");

  // A web page cannot use the holder app: no token, and no CORS for web origins
  const r = await page.evaluate(async () => {
    try {
      const x = await fetch("http://127.0.0.1:4010/v1/like", { method: "POST", headers: { "content-type": "application/json" }, body: '{"platform":"mockfeed","post":"p2"}' });
      return x.status;
    } catch (e) {
      return "blocked";
    }
  });
  assert.ok(r === "blocked" || r === 401, `page-origin call to the holder app must fail, got ${r}`);
  if (shots) await page.screenshot({ path: path.join(shots, "feed-after-like.png") });
  console.log("extension e2e: all checks passed");
} finally {
  await ctx.close();
  fs.rmSync(profile, { recursive: true, force: true });
}
