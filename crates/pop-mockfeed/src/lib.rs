//! # pop-mockfeed
//!
//! A small social network that runs locally, so the whole flow can be tried without any real platform:
//! profiles with bios, posts, likes, and a like farm of 40 bot accounts that pile likes onto one post.
//! It knows nothing about personhood; the extension and the `pop-platform-mockfeed` adapter treat it
//! like any other platform.
//!
//! Pages carry `data-pop-*` attributes so the extension's adapter has stable selectors.
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

#[derive(Clone, Serialize)]
pub struct User {
    pub id: String,
    pub handle: String,
    pub name: String,
    pub bio: String,
    pub bot: bool,
}

#[derive(Clone, Serialize)]
pub struct Post {
    pub id: String,
    pub author_id: String,
    pub text: String,
    pub likes: BTreeSet<String>,
    pub seq: u64,
}

#[derive(Default)]
struct Db {
    users: BTreeMap<String, User>,
    tokens: BTreeMap<String, String>,
    posts: BTreeMap<String, Post>,
    seq: u64,
}

type St = Arc<Mutex<Db>>;

impl Db {
    fn add_user(&mut self, handle: &str, name: &str, bio: &str, bot: bool) -> String {
        let id = format!("u{}", self.users.len() + 1);
        self.users.insert(id.clone(), User { id: id.clone(), handle: handle.into(), name: name.into(), bio: bio.into(), bot });
        id
    }
    fn add_post(&mut self, author: &str, text: &str) -> String {
        self.seq += 1;
        let id = format!("p{}", self.seq);
        self.posts.insert(id.clone(), Post { id: id.clone(), author_id: author.into(), text: text.into(), likes: BTreeSet::new(), seq: self.seq });
        id
    }
    fn by_handle(&self, h: &str) -> Option<&User> {
        let h = h.trim_start_matches('@').to_lowercase();
        self.users.values().find(|u| u.handle == h)
    }
}

fn seed() -> Db {
    let mut db = Db::default();
    let alice = db.add_user("alice", "Alice Aaltonen", "Birdwatcher in Oulu.", false);
    let bob = db.add_user("bob", "Bob Berg", "Teacher. Opinions my own.", false);
    let carol = db.add_user("carol", "Carol Corhonen", "Local politics, bus timetables.", false);
    let news = db.add_user("dailytruth", "Daily Truth 24/7", "The news THEY won't tell you!!", false);
    let bots: Vec<String> = (1..=40).map(|i| db.add_user(&format!("patriot{i:02}"), &format!("Real Patriot {i}"), "", true)).collect();
    let p1 = db.add_post(&alice, "First waxwings of the winter at the harbour this morning.");
    let p2 = db.add_post(&news, "BREAKING: Candidate X secretly plans to ban saunas. Share before it's deleted!");
    let p3 = db.add_post(&bob, "Reminder: the municipal election is on Sunday. Polling stations open at 9.");
    let p4 = db.add_post(&carol, "Bus line 7 gets a Sunday timetable from next month.");
    for b in &bots {
        db.posts.get_mut(&p2).unwrap().likes.insert(b.clone());
    }
    for b in bots.iter().take(5) {
        db.posts.get_mut(&p3).unwrap().likes.insert(b.clone());
    }
    for u in [&bob, &carol] {
        db.posts.get_mut(&p1).unwrap().likes.insert(u.clone());
    }
    db.posts.get_mut(&p3).unwrap().likes.insert(alice.clone());
    db.posts.get_mut(&p4).unwrap().likes.insert(alice.clone());
    db
}

pub fn router() -> Router {
    let st: St = Arc::new(Mutex::new(seed()));
    Router::new()
        .route("/", get(feed_page))
        .route("/u/:handle", get(profile_page))
        .route("/api/login", post(login))
        .route("/api/users/:handle", get(get_user))
        .route("/api/users/:handle/posts", get(user_posts))
        .route("/api/me/bio", put(set_bio))
        .route("/api/posts", get(all_posts).post(new_post))
        .route("/api/posts/:id/like", post(like).delete(unlike))
        .route("/api/posts/:id/liked", get(liked))
        .with_state(st)
}

struct ApiErr(StatusCode, &'static str);
impl IntoResponse for ApiErr {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error": self.1}))).into_response()
    }
}

fn me(db: &Db, h: &HeaderMap) -> Result<String, ApiErr> {
    let t = h.get("authorization").and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")).ok_or(ApiErr(StatusCode::UNAUTHORIZED, "login required"))?;
    db.tokens.get(t).cloned().ok_or(ApiErr(StatusCode::UNAUTHORIZED, "bad token"))
}

#[derive(Deserialize)]
struct LoginReq {
    handle: String,
}

/// Mock login: no password. Do not expose this server beyond localhost.
async fn login(State(s): State<St>, Json(r): Json<LoginReq>) -> Result<Json<serde_json::Value>, ApiErr> {
    let mut db = s.lock().unwrap();
    let u = db.by_handle(&r.handle).cloned().ok_or(ApiErr(StatusCode::NOT_FOUND, "no such user"))?;
    let token = hex::encode(rand::random::<[u8; 16]>());
    db.tokens.insert(token.clone(), u.id.clone());
    Ok(Json(json!({"token": token, "user": u})))
}

async fn get_user(State(s): State<St>, Path(h): Path<String>) -> Result<Json<User>, ApiErr> {
    let db = s.lock().unwrap();
    db.by_handle(&h).cloned().map(Json).ok_or(ApiErr(StatusCode::NOT_FOUND, "no such user"))
}

fn post_json(db: &Db, p: &Post) -> serde_json::Value {
    let a = &db.users[&p.author_id];
    json!({"id": p.id, "author_id": a.id, "author_handle": a.handle, "text": p.text, "likes": p.likes.len()})
}

async fn user_posts(State(s): State<St>, Path(h): Path<String>) -> Result<Json<Vec<serde_json::Value>>, ApiErr> {
    let db = s.lock().unwrap();
    let u = db.by_handle(&h).ok_or(ApiErr(StatusCode::NOT_FOUND, "no such user"))?;
    let mut v: Vec<&Post> = db.posts.values().filter(|p| p.author_id == u.id).collect();
    v.sort_by_key(|p| std::cmp::Reverse(p.seq));
    Ok(Json(v.into_iter().take(20).map(|p| post_json(&db, p)).collect()))
}

async fn all_posts(State(s): State<St>) -> Json<Vec<serde_json::Value>> {
    let db = s.lock().unwrap();
    let mut v: Vec<&Post> = db.posts.values().collect();
    v.sort_by_key(|p| std::cmp::Reverse(p.seq));
    Json(v.into_iter().map(|p| post_json(&db, p)).collect())
}

#[derive(Deserialize)]
struct BioReq {
    bio: String,
}

async fn set_bio(State(s): State<St>, h: HeaderMap, Json(r): Json<BioReq>) -> Result<Json<User>, ApiErr> {
    let mut db = s.lock().unwrap();
    let id = me(&db, &h)?;
    if r.bio.chars().count() > 256 {
        return Err(ApiErr(StatusCode::BAD_REQUEST, "bio longer than 256 characters"));
    }
    let u = db.users.get_mut(&id).unwrap();
    u.bio = r.bio;
    Ok(Json(u.clone()))
}

#[derive(Deserialize)]
struct PostReq {
    text: String,
}

async fn new_post(State(s): State<St>, h: HeaderMap, Json(r): Json<PostReq>) -> Result<Json<serde_json::Value>, ApiErr> {
    let mut db = s.lock().unwrap();
    let id = me(&db, &h)?;
    let pid = db.add_post(&id, &r.text);
    let p = db.posts[&pid].clone();
    Ok(Json(post_json(&db, &p)))
}

async fn like(State(s): State<St>, h: HeaderMap, Path(pid): Path<String>) -> Result<Json<serde_json::Value>, ApiErr> {
    let mut db = s.lock().unwrap();
    let id = me(&db, &h)?;
    let p = db.posts.get_mut(&pid).ok_or(ApiErr(StatusCode::NOT_FOUND, "no such post"))?;
    p.likes.insert(id);
    Ok(Json(json!({"likes": p.likes.len()})))
}

async fn liked(State(s): State<St>, h: HeaderMap, Path(pid): Path<String>) -> Result<Json<serde_json::Value>, ApiErr> {
    let db = s.lock().unwrap();
    let id = me(&db, &h)?;
    let p = db.posts.get(&pid).ok_or(ApiErr(StatusCode::NOT_FOUND, "no such post"))?;
    Ok(Json(json!({"liked": p.likes.contains(&id)})))
}

async fn unlike(State(s): State<St>, h: HeaderMap, Path(pid): Path<String>) -> Result<Json<serde_json::Value>, ApiErr> {
    let mut db = s.lock().unwrap();
    let id = me(&db, &h)?;
    let p = db.posts.get_mut(&pid).ok_or(ApiErr(StatusCode::NOT_FOUND, "no such post"))?;
    p.likes.remove(&id);
    Ok(Json(json!({"likes": p.likes.len()})))
}

// ------------------------------------------------------------------ pages

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

const STYLE: &str = r#"
:root{--bg:#f6f7f9;--card:#fff;--fg:#16181c;--muted:#5b6470;--line:#e3e6ea;--accent:#2f6fde}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#171a20;--fg:#e8eaed;--muted:#9aa3ad;--line:#2a2f37;--accent:#7aa7ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.45 system-ui,sans-serif}
header{position:sticky;top:0;background:var(--card);border-bottom:1px solid var(--line);padding:.6rem 1rem;display:flex;gap:1rem;align-items:center;justify-content:space-between}
header a{color:var(--fg);text-decoration:none;font-weight:700}main{max-width:40rem;margin:0 auto;padding:1rem}
.post,.profile{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:.9rem 1rem;margin:0 0 .8rem}
.author{font-weight:600;color:var(--fg);text-decoration:none}.handle{color:var(--muted);font-size:.9rem}
.text{margin:.4rem 0 .6rem;white-space:pre-wrap}.bio{color:var(--muted);white-space:pre-wrap}
button{font:inherit;border:1px solid var(--line);background:var(--bg);color:var(--fg);border-radius:999px;padding:.25rem .8rem;cursor:pointer}
button.liked{border-color:#d33;color:#d33}select,textarea{font:inherit;background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:.3rem}
textarea{width:100%}.row{display:flex;gap:.5rem;align-items:center;flex-wrap:wrap}.note{color:var(--muted);font-size:.85rem}
"#;

const SCRIPT: &str = r#"
const tok=()=>localStorage.getItem('mf_token');const meH=()=>localStorage.getItem('mf_handle');
async function api(m,u,b){const r=await fetch(u,{method:m,headers:{'content-type':'application/json',...(tok()?{authorization:'Bearer '+tok()}:{})},body:b?JSON.stringify(b):undefined});if(!r.ok)throw new Error((await r.json()).error);return r.json();}
async function loginAs(h){if(!h){localStorage.removeItem('mf_token');localStorage.removeItem('mf_handle');location.reload();return;}const r=await api('POST','/api/login',{handle:h});localStorage.setItem('mf_token',r.token);localStorage.setItem('mf_handle',h);location.reload();}
document.addEventListener('DOMContentLoaded',()=>{const sel=document.getElementById('who');if(sel){sel.value=meH()||'';sel.onchange=()=>loginAs(sel.value);}
document.querySelectorAll('[data-pop-like]').forEach(b=>{if(tok())api('GET','/api/posts/'+b.dataset.popLike+'/liked').then(r=>b.classList.toggle('liked',r.liked)).catch(()=>{});b.onclick=async()=>{if(!tok()){document.getElementById('who').focus();b.title='Choose who you are in the top bar first.';return;}const liked=b.classList.contains('liked');const r=await api(liked?'DELETE':'POST','/api/posts/'+b.dataset.popLike+'/like');b.classList.toggle('liked',!liked);b.querySelector('.n').textContent=r.likes;};});
const pf=document.getElementById('postform');if(pf){pf.onsubmit=async e=>{e.preventDefault();await api('POST','/api/posts',{text:pf.text.value});location.reload();};}
const bf=document.getElementById('bioform');if(bf){bf.onsubmit=async e=>{e.preventDefault();await api('PUT','/api/me/bio',{bio:bf.bio.value});location.reload();};}});
"#;

fn page(db: &Db, title: &str, body: &str) -> Html<String> {
    let opts: String = db
        .users
        .values()
        .filter(|u| !u.bot)
        .map(|u| format!(r#"<option value="{h}">@{h}</option>"#, h = esc(&u.handle)))
        .collect();
    Html(format!(
        r#"<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{t}</title><style>{STYLE}</style>
<header><a href="/">MockFeed</a><label class="row">You are <select id="who"><option value="">(logged out)</option>{opts}</select></label></header>
<main data-pop-platform="mockfeed">{body}</main><script>{SCRIPT}</script></html>"#,
        t = esc(title)
    ))
}

fn render_post(db: &Db, p: &Post) -> String {
    let a = &db.users[&p.author_id];
    format!(
        r#"<article class="post" data-pop-post="{id}" data-pop-author-id="{aid}" data-pop-author-handle="{h}">
<div><a class="author" data-pop-account="{aid}" data-pop-handle="{h}" href="/u/{h}">{name}</a> <span class="handle">@{h}</span></div>
<p class="text">{text}</p><div class="row"><button data-pop-like="{id}">♥ <span class="n">{n}</span></button></div></article>"#,
        id = p.id,
        aid = a.id,
        h = esc(&a.handle),
        name = esc(&a.name),
        text = esc(&p.text),
        n = p.likes.len()
    )
}

async fn feed_page(State(s): State<St>) -> Html<String> {
    let db = s.lock().unwrap();
    let mut v: Vec<&Post> = db.posts.values().collect();
    v.sort_by_key(|p| std::cmp::Reverse(p.seq));
    let posts: String = v.iter().map(|p| render_post(&db, p)).collect();
    let body = format!(
        r#"<form id="postform" class="post"><textarea name="text" rows="2" placeholder="What's happening?"></textarea><div class="row"><button>Post</button><span class="note">Choose who you are in the top bar first.</span></div></form>{posts}"#
    );
    page(&db, "MockFeed", &body)
}

async fn profile_page(State(s): State<St>, Path(h): Path<String>) -> Response {
    let db = s.lock().unwrap();
    let Some(u) = db.by_handle(&h).cloned() else {
        return (StatusCode::NOT_FOUND, "no such user").into_response();
    };
    let mut v: Vec<&Post> = db.posts.values().filter(|p| p.author_id == u.id).collect();
    v.sort_by_key(|p| std::cmp::Reverse(p.seq));
    let posts: String = v.iter().map(|p| render_post(&db, p)).collect();
    let body = format!(
        r#"<section class="profile" data-pop-profile="{id}" data-pop-handle="{h}"><h1 style="margin:.2rem 0"><span data-pop-account="{id}" data-pop-handle="{h}">{name}</span></h1><div class="handle">@{h}</div><p class="bio" data-pop-bio>{bio}</p>
<form id="bioform" class="row"><textarea name="bio" rows="2" placeholder="Edit your bio (only if this is you)">{bio}</textarea><button>Save bio</button></form></section>{posts}"#,
        id = u.id,
        h = esc(&u.handle),
        name = esc(&u.name),
        bio = esc(&u.bio)
    );
    page(&db, &format!("@{}", u.handle), &body).into_response()
}
