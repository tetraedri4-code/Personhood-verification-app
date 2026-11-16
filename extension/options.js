const KEYS = { directoryUrl: "http://127.0.0.1:4003", holderUrl: "http://127.0.0.1:4010", token: "", reportLikes: false };
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

$("test").onclick = () =>
  chrome.runtime.sendMessage({ type: "holder-status" }, (r) => {
    if (!r || r.error) out("Holder app not reachable: " + ((r && r.error) || "no answer"));
    else out(r.enrolled ? `Connected. Enrolled, ${r.bindings.length} bound account(s).` : "Connected, but not enrolled yet.");
  });
