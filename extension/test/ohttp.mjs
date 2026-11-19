// The extension's Oblivious HTTP client against the Rust gateway and relay of a running `pop demo`
// (or `pop devnet`): the same answers as straight from the directory.
//   node extension/test/ohttp.mjs
import { fileURLToPath } from "node:url";
import path from "node:path";
import fs from "node:fs";
import vm from "node:vm";
import assert from "node:assert/strict";

const src = fs.readFileSync(path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../src/ohttp.js"), "utf8");
vm.runInThisContext(src);
const { request } = globalThis.PopOhttp;
const DIR = "http://127.0.0.1:4003", RELAY = "http://127.0.0.1:4004/directory";

const url = `${DIR}/v1/bindings?platform=mockfeed`;
const direct = await (await fetch(url)).json();
const r = await request(RELAY, "GET", url);
assert.equal(r.status, 200);
assert.equal(r.headers["content-type"], "application/json");
assert.deepEqual(JSON.parse(new TextDecoder().decode(r.body)), direct);

// a POST with a body, and an error answer, come back as the directory gave them
const bad = await request(RELAY, "POST", `${DIR}/v1/likes/counts`, JSON.stringify({ platform: "nope", posts: [] }));
const badDirect = await fetch(`${DIR}/v1/likes/counts`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ platform: "nope", posts: [] }) });
assert.equal(bad.status, badDirect.status);
assert.deepEqual(JSON.parse(new TextDecoder().decode(bad.body)), await badDirect.json());

// the gateway's own routes cannot be reached from inside
assert.equal((await request(RELAY, "GET", `${DIR}/ohttp/keys`)).status, 400);
console.log("ohttp client: ok");
