//! The instructions for securing an eID (docs/reset-eid/), built into the app so that they work without
//! the network, and served on the app's local address at [`crate::holder::RESET_EID_PATH`].
//!
//! - `/help/reset-eid?lang=xx` explains why the eID comes first and lets the person pick their country
//!   from a searchable list (an `<input list>`, which browsers filter as one types, with no script).
//! - `/help/reset-eid?country=Finland` (what the list submits) redirects to the country's page.
//! - `/help/reset-eid/fi?lang=sv` is the country's page, in English or one of the country's official
//!   languages; the default is the country's most widely used language.
//!
//! Everything shown is fixed text compiled into the app. Nothing from the request is echoed back: the
//! language and the country are only used to pick among known values.
use axum::{
    extract::{Path, Query},
    http::{header, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use serde::Deserialize;

#[path = "help_pages.rs"]
mod pages;

pub struct Country {
    pub code: &'static str,
    pub name: &'static str,
    /// names in the country's own languages, for the search list
    pub native: &'static [&'static str],
    /// official languages at national level, the default (most widely used) first
    pub langs: &'static [&'static str],
}

/// Language codes and their names in the language itself.
pub const LANGS: &[(&str, &str)] = &[
    ("bg", "Български"),
    ("cs", "Čeština"),
    ("da", "Dansk"),
    ("de", "Deutsch"),
    ("el", "Ελληνικά"),
    ("en", "English"),
    ("es", "Español"),
    ("et", "Eesti"),
    ("fi", "Suomi"),
    ("fr", "Français"),
    ("ga", "Gaeilge"),
    ("hr", "Hrvatski"),
    ("hu", "Magyar"),
    ("it", "Italiano"),
    ("lb", "Lëtzebuergesch"),
    ("lt", "Lietuvių"),
    ("lv", "Latviešu"),
    ("mt", "Malti"),
    ("nl", "Nederlands"),
    ("pl", "Polski"),
    ("pt", "Português"),
    ("ro", "Română"),
    ("sk", "Slovenčina"),
    ("sl", "Slovenščina"),
    ("sv", "Svenska"),
    ("tr", "Türkçe"),
];

macro_rules! c {
    ($code:literal, $name:literal, [$($n:literal),*], [$($l:literal),+]) => {
        Country { code: $code, name: $name, native: &[$($n),*], langs: &[$($l),+] }
    };
}

/// The 27 member states. Languages are the official languages at national level (regional co-official
/// languages are not included).
pub const COUNTRIES: &[Country] = &[
    c!("at", "Austria", ["Österreich"], ["de"]),
    c!("be", "Belgium", ["België", "Belgique", "Belgien"], ["nl", "fr", "de"]),
    c!("bg", "Bulgaria", ["България"], ["bg"]),
    c!("hr", "Croatia", ["Hrvatska"], ["hr"]),
    c!("cy", "Cyprus", ["Κύπρος", "Kıbrıs"], ["el", "tr"]),
    c!("cz", "Czechia", ["Česko"], ["cs"]),
    c!("dk", "Denmark", ["Danmark"], ["da"]),
    c!("ee", "Estonia", ["Eesti"], ["et"]),
    c!("fi", "Finland", ["Suomi"], ["fi", "sv"]),
    c!("fr", "France", [], ["fr"]),
    c!("de", "Germany", ["Deutschland"], ["de"]),
    c!("gr", "Greece", ["Ελλάδα"], ["el"]),
    c!("hu", "Hungary", ["Magyarország"], ["hu"]),
    c!("ie", "Ireland", ["Éire"], ["en", "ga"]),
    c!("it", "Italy", ["Italia"], ["it"]),
    c!("lv", "Latvia", ["Latvija"], ["lv"]),
    c!("lt", "Lithuania", ["Lietuva"], ["lt"]),
    c!("lu", "Luxembourg", ["Lëtzebuerg", "Luxemburg"], ["fr", "de", "lb"]),
    c!("mt", "Malta", [], ["mt", "en"]),
    c!("nl", "Netherlands", ["Nederland"], ["nl"]),
    c!("pl", "Poland", ["Polska"], ["pl"]),
    c!("pt", "Portugal", [], ["pt"]),
    c!("ro", "Romania", ["România"], ["ro"]),
    c!("sk", "Slovakia", ["Slovensko"], ["sk"]),
    c!("si", "Slovenia", ["Slovenija"], ["sl"]),
    c!("es", "Spain", ["España"], ["es"]),
    c!("se", "Sweden", ["Sverige"], ["sv"]),
];

/// The texts of one language: interface strings, then (after a line `---`) the "why" section.
struct Ui {
    strings: Vec<(&'static str, &'static str)>,
    why: &'static str,
}

impl Ui {
    fn get(&self, key: &str) -> &'static str {
        self.strings.iter().find(|(k, _)| *k == key).map(|(_, v)| *v).unwrap_or("")
    }
}

fn parse_ui(src: &'static str) -> Ui {
    let (head, why) = src.split_once("\n---\n").unwrap_or(("", src));
    let strings = head.lines().filter_map(|l| l.split_once(": ")).map(|(k, v)| (k.trim(), v.trim())).collect();
    Ui { strings, why }
}

fn ui(lang: &str) -> Ui {
    let src = pages::UI.iter().find(|(l, _)| *l == lang).or_else(|| pages::UI.iter().find(|(l, _)| *l == "en")).map(|(_, s)| *s).unwrap_or("");
    let mut u = parse_ui(src);
    if lang != "en" {
        // a string missing in a translation falls back to English
        let en = parse_ui(pages::UI.iter().find(|(l, _)| *l == "en").map(|(_, s)| *s).unwrap_or(""));
        for (k, v) in en.strings {
            if !u.strings.iter().any(|(kk, _)| *kk == k) {
                u.strings.push((k, v));
            }
        }
    }
    u
}

fn lang_name(code: &str) -> &'static str {
    LANGS.iter().find(|(c, _)| *c == code).map(|(_, n)| *n).unwrap_or("")
}

/// A known language code equal to `want`, if there is one.
fn known_lang(want: Option<&str>, allowed: &[&'static str]) -> Option<&'static str> {
    let want = want?;
    allowed.iter().copied().find(|l| *l == want)
}

fn country(code: &str) -> Option<&'static Country> {
    COUNTRIES.iter().find(|c| c.code == code)
}

fn label(c: &Country) -> String {
    if c.native.is_empty() {
        c.name.to_string()
    } else {
        format!("{} ({})", c.name, c.native.join(" / "))
    }
}

/// Find the country the person typed or picked: its code, English or native name, or list label.
pub fn find_country(input: &str) -> Option<&'static Country> {
    // the longest label is under 100 bytes; refuse anything longer before copying it
    let s = input.trim();
    if s.is_empty() || s.len() > 100 {
        return None;
    }
    let s = s.to_lowercase();
    COUNTRIES.iter().find(|c| {
        c.code == s || c.name.to_lowercase() == s || label(c).to_lowercase() == s || c.native.iter().any(|n| n.to_lowercase() == s)
    })
}

/// Markdown to HTML. Raw HTML in the source is shown as text, not passed through: the pages are our
/// own files, but translations are many and contributed, so a stray tag must not become markup.
fn md(src: &str) -> String {
    use pulldown_cmark::{Event, Options, Parser};
    let events = Parser::new_ext(src, Options::ENABLE_TABLES).map(|e| match e {
        Event::Html(t) | Event::InlineHtml(t) => Event::Text(t),
        e => e,
    });
    let mut out = String::new();
    pulldown_cmark::html::push_html(&mut out, events);
    out
}

/// sources.md lines are "- Label: https://..."; show each label as a link to its address.
fn source_links(src: &str) -> String {
    src.lines()
        .map(|l| match l.strip_prefix("- ").and_then(|r| r.rsplit_once(": https://")) {
            Some((label, rest)) if !rest.contains(char::is_whitespace) => format!("- [{label}](https://{rest})"),
            _ => l.to_string(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

const STYLE: &str = "body{font:16px/1.5 system-ui,sans-serif;max-width:46rem;margin:1rem auto;padding:0 1rem}\
nav.langs{font-size:.9em;margin-bottom:1rem;display:flex;flex-wrap:wrap;gap:.2rem .7rem}nav.langs a,nav.langs strong{white-space:nowrap}\
table{border-collapse:collapse;display:block;overflow-x:auto}td,th{border:1px solid #999;padding:.3rem .5rem;vertical-align:top}\
input[list]{font:inherit;padding:.4rem;width:100%;max-width:24rem;box-sizing:border-box}button{font:inherit;padding:.4rem 1rem}\
.note{color:#555;font-size:.9em}@media (prefers-color-scheme:dark){body{background:#111;color:#eee}a{color:#8bf}.note{color:#aaa}}";

fn page(lang: &str, title: &str, body: &str) -> Response {
    let html = format!(
        "<!doctype html><html lang={lang}><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\">\
         <title>{}</title><style>{STYLE}</style><body>{body}</body></html>",
        esc(title)
    );
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            // fixed pages from this program: no scripts, no framing, forms only to this app
            (header::CONTENT_SECURITY_POLICY, "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::X_FRAME_OPTIONS, "DENY"),
            (header::REFERRER_POLICY, "no-referrer"),
        ],
        html,
    )
        .into_response()
}

fn lang_nav(current: &str, choices: &[&str], href: impl Fn(&str) -> String) -> String {
    let mut s = String::from("<nav class=langs>");
    for l in choices {
        if *l == current {
            s += &format!("<strong>{}</strong>", lang_name(l));
        } else {
            s += &format!("<a href=\"{}\" hreflang={l} lang={l}>{}</a>", href(l), lang_name(l));
        }
    }
    s + "</nav>"
}

#[derive(Deserialize)]
pub struct IndexQuery {
    lang: Option<String>,
    country: Option<String>,
}

/// Languages that have interface texts, English first.
fn ui_langs() -> Vec<&'static str> {
    let mut v: Vec<&'static str> = vec!["en"];
    v.extend(LANGS.iter().map(|(c, _)| *c).filter(|c| *c != "en" && pages::UI.iter().any(|(l, _)| l == c)));
    v
}

pub async fn index(Query(q): Query<IndexQuery>) -> Response {
    let langs = ui_langs();
    let lang = known_lang(q.lang.as_deref(), &langs).unwrap_or("en");
    let mut not_found = false;
    if let Some(input) = q.country.as_deref() {
        match find_country(input) {
            Some(c) => {
                // keep the language the person chose, if the country's page has it; else the country's default
                let base = format!("{}/{}", crate::holder::RESET_EID_PATH, c.code);
                let keep = q.lang.is_some() && (lang == "en" || c.langs.contains(&lang));
                let target = if keep { format!("{base}?lang={lang}") } else { base };
                return Redirect::to(&target).into_response();
            }
            None => not_found = true,
        }
    }
    let u = ui(lang);
    let mut body = lang_nav(lang, &langs, |l| format!("{}?lang={l}", crate::holder::RESET_EID_PATH));
    if lang != "en" {
        body += &format!("<p class=note>{}</p>", esc(u.get("translated")));
    }
    body += &md(u.why);
    body += &format!(
        "<h2 id=country>{}</h2><form method=get action=\"{}\"><input type=hidden name=lang value={lang}>\
         <input list=countries name=country id=country-input aria-labelledby=country placeholder=\"{}\" autocomplete=off required> \
         <button type=submit>{}</button><datalist id=countries>",
        esc(u.get("choose")),
        crate::holder::RESET_EID_PATH,
        esc(u.get("placeholder")),
        esc(u.get("go"))
    );
    for c in COUNTRIES {
        body += &format!("<option value=\"{}\">", esc(&label(c)));
    }
    body += "</datalist></form>";
    if not_found {
        body += &format!("<p role=alert>{}</p>", esc(u.get("not_found")));
    }
    // the same list as plain links, for browsers that do not offer the search list
    body += &format!("<details><summary>{}</summary><ul>", esc(u.get("all")));
    for c in COUNTRIES {
        body += &format!("<li><a href=\"{}/{}\">{}</a></li>", crate::holder::RESET_EID_PATH, c.code, esc(&label(c)));
    }
    body += "</ul></details>";
    page(lang, u.get("title"), &body)
}

#[derive(Deserialize)]
pub struct CountryQuery {
    lang: Option<String>,
}

pub async fn country_page(Path(code): Path<String>, Query(q): Query<CountryQuery>) -> Response {
    let Some(c) = country(&code) else {
        return (StatusCode::NOT_FOUND, "no such country page").into_response();
    };
    // the country's languages and English, as far as the page exists
    let mut choices: Vec<&'static str> = c.langs.to_vec();
    if !choices.contains(&"en") {
        choices.push("en");
    }
    choices.retain(|l| pages::PAGES.iter().any(|(cc, pl, _)| *cc == c.code && pl == l));
    let Some(default) = choices.first().copied() else {
        return (StatusCode::NOT_FOUND, "no page for this country yet").into_response();
    };
    let lang = known_lang(q.lang.as_deref(), &choices).unwrap_or(default);
    let text = pages::PAGES.iter().find(|(cc, pl, _)| *cc == c.code && *pl == lang).map(|(_, _, t)| *t).unwrap_or("");
    let u = ui(lang);
    let mut body = lang_nav(lang, &choices, |l| format!("{}/{}?lang={l}", crate::holder::RESET_EID_PATH, c.code));
    body += &format!("<p><a href=\"{}?lang={lang}\">{}</a></p>", crate::holder::RESET_EID_PATH, esc(u.get("back")));
    if lang != "en" {
        body += &format!("<p class=note>{}</p>", esc(u.get("translated")));
    }
    body += &md(text);
    if let Some((_, src)) = pages::SOURCES.iter().find(|(cc, _)| *cc == c.code) {
        body += &format!("<h2>{}</h2>", esc(u.get("sources")));
        body += &md(&source_links(src));
    }
    page(lang, &format!("{}: {}", u.get("title"), c.name), &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The list of compiled-in pages must match the files in docs/reset-eid/. With POP_REGEN=1 the
    /// test writes the list instead.
    #[test]
    fn page_list_matches_the_files() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/reset-eid");
        let mut ui = vec![];
        let mut pages = vec![];
        let mut sources = vec![];
        let mut langs: Vec<_> = std::fs::read_dir(root.join("lang")).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        langs.sort();
        for f in langs {
            let l = f.strip_suffix(".md").unwrap().to_string();
            ui.push(format!("    (\"{l}\", include_str!(\"../../../docs/reset-eid/lang/{f}\")),"));
        }
        for c in COUNTRIES {
            let dir = root.join(c.code);
            if !dir.exists() {
                continue;
            }
            let mut files: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
            files.sort();
            for f in files {
                let stem = f.strip_suffix(".md").unwrap();
                if stem == "sources" {
                    sources.push(format!("    (\"{}\", include_str!(\"../../../docs/reset-eid/{}/sources.md\")),", c.code, c.code));
                } else {
                    assert!(stem == "en" || c.langs.contains(&stem), "{}/{f}: not a language of {}", c.code, c.name);
                    pages.push(format!("    (\"{}\", \"{stem}\", include_str!(\"../../../docs/reset-eid/{}/{f}\")),", c.code, c.code));
                }
            }
        }
        let want = format!(
            "// Generated by the test `page_list_matches_the_files` (POP_REGEN=1 cargo test -p pop-holder help). Do not edit.\n\
             pub(super) const UI: &[(&str, &str)] = &[\n{}\n];\n\
             pub(super) const PAGES: &[(&str, &str, &str)] = &[\n{}\n];\n\
             pub(super) const SOURCES: &[(&str, &str)] = &[\n{}\n];\n",
            ui.join("\n"),
            pages.join("\n"),
            sources.join("\n")
        );
        let file = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/help_pages.rs");
        if std::env::var("POP_REGEN").is_ok() {
            std::fs::write(&file, &want).unwrap();
        }
        assert_eq!(std::fs::read_to_string(&file).unwrap(), want, "run POP_REGEN=1 cargo test -p pop-holder help");
    }

    #[test]
    fn every_country_has_english_and_all_its_languages() {
        for c in COUNTRIES {
            for l in c.langs.iter().chain(["en"].iter()) {
                assert!(pages::PAGES.iter().any(|(cc, pl, _)| *cc == c.code && pl == l), "missing docs/reset-eid/{}/{l}.md", c.code);
                assert!(pages::UI.iter().any(|(ul, _)| ul == l), "missing docs/reset-eid/lang/{l}.md");
            }
            assert!(pages::SOURCES.iter().any(|(cc, _)| *cc == c.code), "missing docs/reset-eid/{}/sources.md", c.code);
        }
    }

    #[test]
    fn every_language_has_every_string() {
        let en = parse_ui(pages::UI.iter().find(|(l, _)| *l == "en").unwrap().1);
        for (l, src) in pages::UI {
            let u = parse_ui(src);
            assert!(!u.why.trim().is_empty(), "{l}: no why section");
            for (k, _) in &en.strings {
                assert!(u.strings.iter().any(|(kk, v)| kk == k && !v.is_empty()), "{l}: missing {k}");
            }
        }
    }

    #[test]
    fn countries_are_found_by_any_name() {
        assert_eq!(find_country("Finland").unwrap().code, "fi");
        assert_eq!(find_country(" suomi ").unwrap().code, "fi");
        assert_eq!(find_country("fi").unwrap().code, "fi");
        assert_eq!(find_country(&label(country("be").unwrap())).unwrap().code, "be");
        assert_eq!(find_country("Ελλάδα").unwrap().code, "gr");
        assert!(find_country("Atlantis").is_none());
        assert!(find_country("").is_none());
        assert!(find_country(&"a".repeat(10_000)).is_none());
    }

    #[test]
    fn every_source_is_a_link() {
        for (cc, src) in pages::SOURCES {
            for l in src.lines().filter(|l| !l.trim().is_empty()) {
                assert!(source_links(l).starts_with("- ["), "{cc}/sources.md: {l}");
            }
        }
    }

    #[test]
    fn raw_html_in_a_page_is_shown_as_text() {
        let h = md("Hello <script>alert(1)</script> and <b>bold</b>\n\n<iframe src=x></iframe>");
        assert!(!h.contains("<script") && !h.contains("<b>") && !h.contains("<iframe"), "{h}");
        assert!(h.contains("&lt;script&gt;"));
    }

    #[test]
    fn links_in_pages_are_web_links() {
        for &(cc, l, t) in pages::PAGES.iter().chain(pages::SOURCES.iter().map(|&(cc, t)| (cc, "sources", t)).collect::<Vec<_>>().iter()) {
            for href in md(&source_links(t)).split("href=\"").skip(1) {
                assert!(href.starts_with("https://"), "{cc}/{l}: link {}", &href[..href.len().min(60)]);
            }
        }
    }
}
