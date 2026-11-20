const KEYS = { directoryUrl: "http://127.0.0.1:4003", relayUrl: "", holderUrl: "http://127.0.0.1:4010", token: "", reportLikes: false };
const $ = (id) => document.getElementById(id);
const out = (t) => ($("out").textContent = t);

chrome.storage.local.get(Object.keys(KEYS)).then((s) => {
  for (const [k, d] of Object.entries(KEYS)) {
    if (typeof d === "boolean") $(k).checked = s[k] ?? d;
    else $(k).value = s[k] ?? d;
  }
});

$("save").onclick = async () => {
  const s = {};
  for (const [k, d] of Object.entries(KEYS)) s[k] = typeof d === "boolean" ? $(k).checked : $(k).value.trim();
  await chrome.storage.local.set(s);
  out("Saved.");
};

// The holder app serves the instructions for securing an eID at this path (docs/reset-eid/, one page per EU state and language).
const RESET_EID_PATH = "/help/reset-eid";

function helpLink() {
  let base;
  try {
    base = new URL($("holderUrl").value.trim());
  } catch {
    return null;
  }
  if (base.protocol !== "http:" && base.protocol !== "https:") return null;
  const a = document.createElement("a");
  a.href = new URL(RESET_EID_PATH, base).href;
  a.target = "_blank";
  a.rel = "noopener noreferrer";
  a.textContent = "How to secure your eID";
  return a;
}

$("test").onclick = () =>
  chrome.runtime.sendMessage({ type: "holder-status" }, (r) => {
    if (!r || r.error) return out("Holder app not reachable: " + ((r && r.error) || "no answer"));
    out(r.enrolled ? `Connected. Enrolled, ${r.bindings.length} bound account(s).` : "Connected, but not enrolled yet.");
    if (r.suspended) {
      $("out").textContent +=
        "\n\nYour secret is suspended: someone logged in with your eID and reported this enrolment as not theirs. " +
        "Someone else can log in as you, so secure your eID first, then lift the suspension with a re-check " +
        "in the app (pop holder veto). ";
      const a = helpLink();
      if (a) $("out").append(a);
    }
  });

// ---- pairing this computer (background.js, pairing.js)
const send = (msg) => new Promise((ok) => chrome.runtime.sendMessage(msg, (r) => ok(chrome.runtime.lastError ? { error: chrome.runtime.lastError.message } : r)));
const pairOut = (t) => ($("pairOut").textContent = t);

function showPairing(r) {
  const box = $("words");
  box.replaceChildren();
  $("unpair").disabled = !r.paired;
  $("pair").disabled = !!r.paired;
  if (!r.paired) return;
  r.words.split(" ").forEach((w, i) => {
    const el = document.createElement("span");
    const n = document.createElement("small");
    n.textContent = String(i + 1);
    el.append(n, w);
    box.append(el);
  });
  const end = new Date(r.end_ms);
  pairOut(
    `Paired until ${end.toLocaleString()}.\n\n` +
      "Type these nine words into the app on your phone, or let its camera read them, or write them down and type them in later. " +
      "Only the first four letters of each word matter. Until the end, whoever has the words can leave likes for you to approve, " +
      "so take the paper with you."
  );
}

send({ type: "pair-status" }).then((r) => (r && !r.error ? showPairing(r) : null));

$("pair").onclick = async () => {
  $("pair").disabled = true;
  pairOut("Making the words (a second or so)...");
  const r = await send({ type: "pair-start", minutes: Number($("pairFor").value) });
  if (!r || r.error) {
    $("pair").disabled = false;
    return pairOut("Not paired: " + ((r && r.error) || "no answer"));
  }
  showPairing({ paired: true, ...r });
};

$("unpair").onclick = async () => {
  const r = await send({ type: "pair-end" });
  showPairing({ paired: false });
  pairOut(r && r.closed ? "Unpaired. The words are forgotten here and the mailbox takes no more likes." : "Unpaired here. " + ((r && r.error) || ""));
};
