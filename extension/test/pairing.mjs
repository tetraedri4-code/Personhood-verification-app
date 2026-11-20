// The extension's pairing format against fixed vectors (the same as the Rust test `known_answer` in
// crates/pop-protocol/src/mailbox.rs, also computed with Python's hashlib and hmac).
//   node extension/test/pairing.mjs
import { createRequire } from "node:module";
import assert from "node:assert/strict";
const require = createRequire(import.meta.url);
const { POP_WORDS } = require("../src/words.js");
const { PopPairing } = require("../src/pairing.js");

assert.equal(POP_WORDS.length, 1024);
const k = await PopPairing.derive("able acid acorn actor adapt admit adult advice aerial", 1000);
assert.equal(k.mailbox, "4784938d8f14ee5b1471c245314ccd36d99b7afd135acf635dcd9ea3e4069b5d");
assert.equal(await PopPairing.endTag(k, 1_700_000_000_000), "aff17ae9d7f65f8495c3bd427d48b6bc8385ae04ec4de1489f2c81e835e2b909");
const w = PopPairing.generate().split(" ");
assert.equal(w.length, 9);
assert.ok(w.every((x) => POP_WORDS.includes(x)));
const s = await PopPairing.seal(k, "mockfeed", "p1", 5);
assert.equal(s.item.length, 2 * (12 + 512 + 16));
assert.match(s.dh, /^[0-9a-f]{64}$/);
// print one sealed item for the Rust side to open (crates/pop-protocol test `opens_an_item_sealed_by_the_extension`)
if (process.argv[2] === "--print") console.log(JSON.stringify(s));
console.log("pairing format: all checks passed");
