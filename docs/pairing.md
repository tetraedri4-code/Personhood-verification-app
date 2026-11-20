# Liking from a computer without the app (pairing)

The holder app keeps the secret, and only it can prove a like. On a computer the person does not own,
say a library computer, there is no app. Pairing lets such a computer pass likes to the person's app
for a period the person chooses. The app proves and sends them as usual.

Not to be confused with the **pairing token** (`pop holder serve`), which connects the extension to the
app on the person's *own* computer.

## How it goes

1. In the extension's options on the borrowed computer: "Pair for" 30 minutes to 30 days, then **Pair**.
   The extension shows nine words in a 3 × 3 grid.
2. The person gives the words to their app: types them in (`pop holder pair`, or `POST /v1/pairings` on
   the local API), lets a phone camera read them, or writes them down and types them in later, also after
   the end. Only the first four letters of each word matter.
3. Likes made on the borrowed computer go, encrypted, to a mailbox beside the directory.
4. The app collects the mailbox every 3 to 4 minutes while it runs (or at once: `pop holder pairings`,
   `POST /v1/pairings/collect`). Collected likes are deleted from the mailbox.
5. By default each like **waits for the person's approval** (`pop holder approve <numbers|all>` or
   `reject`; `POST /v1/inbox/approve` / `reject`). A pairing made with `--auto` (`"auto": true`) queues
   its likes at once instead. Approved likes go out at a random moment of the next like window, like any
   other like.
6. The pairing ends at its end time, or earlier when either side unpairs (**Unpair now** in the options,
   `pop holder unpair <name>`). Closing the browser forgets the words on the borrowed computer.

## The format (`pop_protocol::mailbox`, `extension/src/pairing.js`)

| Step | What |
|---|---|
| Words | 9 words from a list of 1024 (`crates/pop-protocol/src/pairing-words.txt`; the extension carries the same list in `words.js`, and a test checks they match). Every word has its own first four letters; three-letter words are matched whole. 9 × 10 = 90 bits |
| Stretching | PBKDF2-HMAC-SHA256, 600 000 iterations, salt `pop-pairing-v1`, password = the words as the list spells them, joined by single spaces. 600 000 is the OWASP Password Storage Cheat Sheet's figure for PBKDF2-HMAC-SHA256 [1]. About a second in a browser |
| Keys | HKDF-SHA256 (empty salt) of the result, with info `pop-pairing-v1 mailbox`, `… enc`, `… auth`: the mailbox id, an AES-256-GCM key, an HMAC key |
| End | The computer opens the mailbox with `end_ms` and `tag = HMAC(auth, "end|" + end_ms)`. The server cannot show a later end without the words; the app checks the tag |
| Like | JSON `{platform, post, at, d}` padded with spaces to 512 bytes, AES-256-GCM with a random 12-byte nonce, additional data `pop-pairing-v1 item|<mailbox id>`. `d` is a random 32-byte deletion code; the server keeps only `SHA-256(d)` |

Fixed test vectors are in `crates/pop-protocol/src/mailbox.rs` (`known_answer`, also computed with
Python's `hashlib` and `hmac`) and `extension/test/pairing.mjs`; the Rust test
`opens_an_item_sealed_by_the_extension` opens an item the extension sealed.

## The mailbox server (`pop-mailbox`)

All requests are POSTs with JSON bodies, so the mailbox id, a bearer secret, never appears in a URL. The
server stores the id only as its SHA-256. In the demo and `pop directory` the mailbox runs in the
directory's process, behind the same Oblivious HTTP gateway, so the extension and the app reach it
through the relay when one is set.

| Path | Body | Rule |
|---|---|---|
| `/v1/mailbox/open` | `mailbox, end_ms, tag` | once; the end in the future and at most 30 days away; the same request again is a no-op, a different end is refused (409) |
| `/v1/mailbox/deposit` | `mailbox, item, dh` | refused after the end or a close (410), beyond 256 items (429), or with an item of the wrong length |
| `/v1/mailbox/list` | `mailbox, after` | items numbered after `after`, with the time each arrived |
| `/v1/mailbox/delete` | `mailbox, codes` | deletes the items whose `SHA-256(code)` matches: only whoever decrypted them can |
| `/v1/mailbox/close` | `mailbox` | ends the period now |

Everything is deleted 30 days after the end. At most 100 000 mailboxes are open at once.

## What each party learns

* **The mailbox server**: that some mailbox exists, its end, when likes were left and collected, and
  how many. Not the likes (padded to one length and encrypted), not who the person is. Through a relay,
  not the addresses either.
* **The directory** (often the same operator): as for any like, a proof for a post with no account
  or pseudonym. A like goes out after the person approves it and then at a random moment of the next
  window, so the time of a deposit and the time of the like are far apart. With `auto`, the gap is the
  collection round (3 to 4 minutes) plus the window; an operator that runs both and sees little traffic
  could match a deposit to a like by time. Approval by default makes that harder.
* **The borrowed computer**: the posts liked on it, while paired. Its extension keeps the words and the
  list of posts liked during the pairing in session storage, which content scripts cannot read and the
  browser drops when it closes. Malware on that computer sees the words, and can leave likes until the
  end: the person sees them in the inbox before anything is sent.
* **Whoever finds the paper**: until the end, the same as the computer. On a pairing made with `auto`
  their likes are sent without asking, so use `auto` only for one's own devices. After the end, nothing: deposits
  are refused, and the app ignores anything the server says arrived after the end.

## Limits of the prototype

* No phone app yet, so no camera reading; the words are typed into `pop holder pair` or the local API.
* The mailbox keeps its state through `pop_storage::Store`; the JSON-file store rewrites a table on each
  write, enough for a pilot only.
* The 30-day limit, 256 items and 100 000 mailboxes are constants in `pop-protocol` and `pop-mailbox`.

[1] OWASP Cheat Sheet Series, Password Storage Cheat Sheet, section "PBKDF2": "PBKDF2-HMAC-SHA256:
600,000 iterations".
https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html (read 20 November 2026)
