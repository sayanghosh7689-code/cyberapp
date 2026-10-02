"""
cyber_app.py - AI Cybersecurity Copilot (Streamlit frontend)
Theme: fire animation + glass icons + water droplets.

Run:  streamlit run cyber_app.py
"""

import html
import random

import requests
import streamlit as st

st.set_page_config(page_title="AI Cybersecurity Copilot", page_icon="🔥", layout="centered")

# ============================================================
# BACKEND SETTINGS  (change when your FastAPI part is ready)
# ============================================================
try:
    BACKEND_URL = st.secrets["BACKEND_URL"]
except Exception:
    BACKEND_URL = "http://127.0.0.1:8000"

# Backend is expected to answer POST {BACKEND_URL}/analyze with JSON:
# { "risk_level": "high|medium|low", "summary": "...",
#   "stats": {"requests": 0, "failed_logins": 0, "suspicious_ips": 0},
#   "findings": [{"severity": "high", "title": "...", "detail": "..."}],
#   "recommendations": ["...", "..."] }

DEMO = {
    "risk_level": "high",
    "summary": "One IP made 212 failed login attempts in 6 minutes against /api/login, "
               "a pattern typical of a brute-force attack. A second IP is scanning "
               "for admin pages that do not exist.",
    "stats": {"requests": 18452, "failed_logins": 341, "suspicious_ips": 4},
    "findings": [
        {"severity": "high", "title": "Brute-force login attempts",
         "detail": "203.0.113.24 failed 212 logins in 6 minutes."},
        {"severity": "medium", "title": "Path scanning",
         "detail": "198.51.100.7 requested /admin, /.env and /wp-login.php (404s)."},
        {"severity": "low", "title": "Unusual user agent",
         "detail": "A few requests came from an outdated command-line client."},
    ],
    "recommendations": [
        "Block or rate-limit the offending IPs.",
        "Add lockout or CAPTCHA after 5 failed logins.",
        "Turn on multi-factor authentication for admin accounts.",
    ],
}

# ============================================================
# THEME: fire + glass + droplets
# ============================================================
CSS = """
<style>
.stApp { background: radial-gradient(ellipse at 50% 100%, #3a0d05 0%, #150605 55%, #080303 100%);
         background-attachment: fixed; }
[data-testid="stHeader"] { background: transparent; }
[data-testid="stMain"], [data-testid="stSidebar"] { position: relative; z-index: 1; }
.stApp, .stApp p, .stApp label, .stApp span, .stApp li,
.stApp h1, .stApp h2, .stApp h3 { color: #fff1e6; }

/* ---------- fire ---------- */
.fire { position: fixed; left: 0; right: 0; bottom: 0; height: 45vh;
        pointer-events: none; z-index: -1; overflow: hidden;
        background: linear-gradient(to top, rgba(255,90,0,0.35), transparent 85%); }
.flame { position: absolute; bottom: -70px; border-radius: 50% 50% 50% 50% / 62% 62% 38% 38%;
         background: radial-gradient(ellipse at 50% 85%, #fff3b0 0%, #ffb300 24%, #ff5a00 52%, rgba(255,0,0,0) 76%);
         filter: blur(14px); mix-blend-mode: screen; transform-origin: 50% 100%;
         animation: flicker ease-in-out infinite alternate; }
@keyframes flicker {
  0%   { transform: scale(1, 1)     translateY(0)     rotate(-3deg); opacity: .9; }
  50%  { transform: scale(.9, 1.25) translateY(-22px) rotate(3deg);  opacity: 1; }
  100% { transform: scale(1.1, .9)  translateY(6px)   rotate(-1deg); opacity: .85; }
}
.ember { position: absolute; bottom: 0; border-radius: 50%; background: #ffb347;
         box-shadow: 0 0 8px 2px rgba(255,140,0,.9); animation: rise linear infinite; }
@keyframes rise {
  0%   { transform: translate(0, 0); opacity: 0; }
  10%  { opacity: 1; }
  100% { transform: translate(var(--dx), -85vh); opacity: 0; }
}

/* ---------- water droplets ---------- */
.drops { position: fixed; inset: 0; overflow: hidden; pointer-events: none; z-index: 5; }
.drop { position: absolute; opacity: 0; border-radius: 50% 50% 50% 50% / 60% 60% 40% 40%;
        background: radial-gradient(circle at 30% 28%, rgba(255,255,255,.95) 0%,
                    rgba(255,255,255,.25) 35%, rgba(255,255,255,.06) 70%);
        border: 1px solid rgba(255,255,255,.35);
        box-shadow: inset -2px -3px 6px rgba(0,0,0,.25), 0 3px 6px rgba(0,0,0,.3);
        animation: drip ease-in infinite; }
@keyframes drip {
  0%   { opacity: 0; transform: translateY(0) scale(.3); }
  12%  { opacity: 1; transform: translateY(0) scale(1); }
  55%  { opacity: 1; transform: translateY(0) scale(1.05); }
  100% { opacity: 0; transform: translateY(38vh) scale(.8, 1.5); }
}
@media (prefers-reduced-motion: reduce) { .flame, .ember, .drop { animation: none; } }

/* ---------- glass ---------- */
.glass { background: rgba(255,255,255,.07); backdrop-filter: blur(16px) saturate(150%);
         -webkit-backdrop-filter: blur(16px) saturate(150%);
         border: 1px solid rgba(255,190,140,.28); border-radius: 22px;
         box-shadow: 0 8px 32px rgba(0,0,0,.4), inset 0 1px 0 rgba(255,220,190,.35);
         padding: 18px 22px; margin: 12px 0; }
.glass-icon { width: 56px; height: 56px; flex: 0 0 56px; display: grid; place-items: center;
              font-size: 28px; border-radius: 18px;
              background: linear-gradient(145deg, rgba(255,200,150,.35), rgba(255,255,255,.06));
              backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px);
              border: 1px solid rgba(255,210,170,.5);
              box-shadow: 0 6px 18px rgba(0,0,0,.4), inset 0 2px 0 rgba(255,235,215,.6); }
.hero, .row { display: flex; align-items: center; gap: 15px; }
.hero h1 { margin: 0; font-size: 1.7rem; line-height: 1.2; }
.hero p { margin: 4px 0 0; opacity: .85; font-size: .95rem; }
.label { font-size: .75rem; opacity: .75; text-transform: uppercase; letter-spacing: .06em; }
.value { font-size: 1.1rem; font-weight: 700; }
.detail { font-size: .92rem; opacity: .9; font-weight: 400; }
.stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
.stats .glass { text-align: center; padding: 16px 8px; }
.stats .glass-icon { margin: 0 auto 8px; }
@media (max-width: 700px) { .stats { grid-template-columns: repeat(2, 1fr); } }
.sev-high   { border-color: rgba(255,80,60,.75);  box-shadow: 0 0 22px rgba(255,60,40,.35); }
.sev-medium { border-color: rgba(255,170,40,.75); }
.sev-low    { border-color: rgba(90,220,140,.65); }

/* ---------- widgets ---------- */
[data-testid="stSidebar"] { background: rgba(255,255,255,.05); backdrop-filter: blur(14px);
                            border-right: 1px solid rgba(255,190,140,.2); }
.stTextArea textarea, .stTextInput input { background: rgba(255,255,255,.08) !important;
    border: 1px solid rgba(255,190,140,.3) !important; border-radius: 14px !important; color: #fff !important; }
[data-testid="stFileUploader"] section { background: rgba(255,255,255,.06);
    border: 1px dashed rgba(255,190,140,.45); border-radius: 18px; }
.stButton > button { background: linear-gradient(135deg, rgba(255,120,30,.55), rgba(255,60,20,.45));
    color: #fff; border: 1px solid rgba(255,200,150,.55); border-radius: 14px; font-weight: 600; }
.stButton > button:hover { border-color: #fff; filter: brightness(1.15); }
</style>
"""

rnd = random.Random(11)


def make_fire():
    flames = "".join(
        f'<span class="flame" style="left:{-6 + i * 9}%;width:{rnd.randint(150, 260)}px;'
        f'height:{rnd.randint(230, 400)}px;animation-duration:{rnd.uniform(1.1, 2.4):.2f}s;'
        f'animation-delay:-{rnd.uniform(0, 2):.2f}s"></span>'
        for i in range(13)
    )
    embers = "".join(
        f'<span class="ember" style="left:{rnd.randint(0, 98)}%;width:{(s := rnd.randint(3, 6))}px;'
        f'height:{s}px;--dx:{rnd.randint(-60, 60)}px;animation-duration:{rnd.randint(5, 11)}s;'
        f'animation-delay:-{rnd.randint(0, 10)}s"></span>'
        for _ in range(30)
    )
    return f'<div class="fire">{flames}{embers}</div>'


def make_drops():
    out = []
    for _ in range(20):
        w = rnd.randint(8, 20)
        out.append(
            f'<span class="drop" style="left:{rnd.randint(2, 96)}%;top:{rnd.randint(2, 70)}%;'
            f'width:{w}px;height:{int(w * 1.3)}px;animation-duration:{rnd.randint(7, 13)}s;'
            f'animation-delay:-{rnd.randint(0, 12)}s"></span>'
        )
    return f'<div class="drops">{"".join(out)}</div>'


st.markdown(CSS + make_fire() + make_drops(), unsafe_allow_html=True)

# ============================================================
# HELPERS
# ============================================================
SEV_ICON = {"high": "🔴", "medium": "🟠", "low": "🟢"}


def e(x):
    return html.escape(str(x))


def stat_card(icon, label, value, sev=""):
    return (f'<div class="glass {sev}"><div class="glass-icon">{icon}</div>'
            f'<div class="value">{e(value)}</div><div class="label">{e(label)}</div></div>')


def finding_card(f):
    sev = str(f.get("severity", "low")).lower()
    return (f'<div class="glass row sev-{sev}"><div class="glass-icon">{SEV_ICON.get(sev, "🟢")}</div>'
            f'<div><div class="value">{e(f.get("title", "Finding"))}</div>'
            f'<div class="detail">{e(f.get("detail", ""))}</div></div></div>')


# ============================================================
# HEADER + SIDEBAR
# ============================================================
st.markdown(
    '<div class="glass hero"><div class="glass-icon">🛡️</div><div>'
    '<h1>AI Cybersecurity Copilot</h1>'
    '<p>Upload server or API logs and get plain-English explanations of '
    'suspicious activity.</p></div></div>',
    unsafe_allow_html=True,
)

with st.sidebar:
    st.header("⚙️ Settings")
    demo = st.toggle("Demo mode (no backend needed)", value=True)
    st.write(f"**Backend:** `{BACKEND_URL}`")
    if st.button("🔌 Check Backend"):
        try:
            r = requests.get(f"{BACKEND_URL}/health", timeout=5)
            st.success("✅ Backend is running") if r.status_code == 200 else st.error(f"Status {r.status_code}")
        except requests.exceptions.RequestException as ex:
            st.error(f"❌ Not reachable: {ex}")

# ============================================================
# INPUT
# ============================================================
st.subheader("📂 Add your logs")
uploaded = st.file_uploader("Upload a log file", type=["log", "txt", "csv", "json"])
pasted = st.text_area("…or paste log lines here", height=130,
                      placeholder="203.0.113.24 - POST /api/login 401 ...")

if st.button("🔥 Analyze logs"):
    log_bytes = uploaded.getvalue() if uploaded else pasted.encode("utf-8")

    if demo:
        st.session_state["result"] = DEMO
    elif not log_bytes.strip():
        st.warning("Please upload a file or paste some log lines first.")
    else:
        with st.spinner("🔍 Analyzing…"):
            try:
                resp = requests.post(f"{BACKEND_URL}/analyze",
                                     files={"file": ("logs.txt", log_bytes)}, timeout=300)
                resp.raise_for_status()
                st.session_state["result"] = resp.json()
            except requests.exceptions.RequestException as ex:
                st.error(f"❌ Could not analyze: {ex}")

# ============================================================
# RESULTS
# ============================================================
res = st.session_state.get("result")

if res:
    risk = str(res.get("risk_level", "low")).lower()
    stats = res.get("stats", {})

    st.markdown(
        '<div class="stats">'
        + stat_card("📨", "Requests", stats.get("requests", "-"))
        + stat_card("🔑", "Failed logins", stats.get("failed_logins", "-"))
        + stat_card("🕵️", "Suspicious IPs", stats.get("suspicious_ips", "-"))
        + stat_card("🔥", "Risk level", risk.upper(), f"sev-{risk}")
        + "</div>",
        unsafe_allow_html=True,
    )

    st.markdown(
        '<div class="glass row"><div class="glass-icon">🧠</div><div>'
        '<div class="label">AI explanation</div>'
        f'<div class="detail">{e(res.get("summary", ""))}</div></div></div>',
        unsafe_allow_html=True,
    )

    st.subheader("🚨 Findings")
    st.markdown("".join(finding_card(f) for f in res.get("findings", [])), unsafe_allow_html=True)

    recs = res.get("recommendations", [])
    if recs:
        items = "".join(f"<li>{e(r)}</li>" for r in recs)
        st.markdown(
            '<div class="glass row"><div class="glass-icon">✅</div><div>'
            f'<div class="label">Recommended actions</div><ul class="detail">{items}</ul></div></div>',
            unsafe_allow_html=True,
        )
else:
    st.markdown(
        '<div class="glass row"><div class="glass-icon">📡</div><div>'
        '<div class="label">Waiting</div><div class="value">Add logs and press Analyze</div></div></div>',
        unsafe_allow_html=True,
    )
