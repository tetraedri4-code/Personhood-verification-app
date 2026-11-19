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
