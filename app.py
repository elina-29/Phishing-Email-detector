import streamlit as st
import time
import tempfile
import json
import datetime
import plotly.graph_objects as go
from core.email_parser import extract_email_content, extract_attachments
from core.analyzer import analyze_email_input

# ---------------------------------------------------
# PAGE CONFIG
# ---------------------------------------------------
st.set_page_config(
    page_title="Phishing Email Detector — Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ---------------------------------------------------
# FONTS + GLOBAL CSS
# ---------------------------------------------------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Mono:ital,wght@0,400;0,700;1,400&family=Syne:wght@400;600;700;800&family=DM+Mono:wght@300;400;500&display=swap');

:root {
  --bg:         #020711;
  --surface:    #080e1c;
  --surface2:   #0c1525;
  --border:     rgba(0, 230, 180, 0.10);
  --border2:    rgba(255,255,255,0.05);
  --accent:     #00e6b4;
  --accent2:    #0077ff;
  --accent3:    #7c3aff;
  --danger:     #ff4466;
  --warn:       #ffaa00;
  --safe:       #00d68f;
  --text:       #b8c8dc;
  --text-dim:   #3d5470;
  --text-mid:   #6b85a0;
  --font-mono:  'Space Mono', monospace;
  --font-ui:    'Syne', sans-serif;
  --font-data:  'DM Mono', monospace;
}

*, *::before, *::after { box-sizing: border-box; }
#MainMenu, footer, header { visibility: hidden; }

.stApp {
  background: var(--bg);
  color: var(--text);
  font-family: var(--font-ui);
}
.block-container { padding: 1.5rem 2.5rem 4rem; max-width: 1440px; }

.stApp::before {
  content: "";
  position: fixed; inset: 0;
  background:
    radial-gradient(ellipse 80% 50% at 20% -10%, rgba(0,230,180,0.06) 0%, transparent 60%),
    radial-gradient(ellipse 60% 40% at 80% 110%, rgba(0,119,255,0.05) 0%, transparent 60%),
    radial-gradient(ellipse 40% 30% at 50% 50%, rgba(124,58,255,0.03) 0%, transparent 70%);
  pointer-events: none; z-index: 0;
}
.stApp::after {
  content: "";
  position: fixed; inset: 0;
  background-image:
    linear-gradient(rgba(0,230,180,0.025) 1px, transparent 1px),
    linear-gradient(90deg, rgba(0,230,180,0.025) 1px, transparent 1px);
  background-size: 48px 48px;
  pointer-events: none; z-index: 0;
}

/* ── SCROLLBAR ── */
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: var(--bg); }
::-webkit-scrollbar-thumb { background: var(--surface2); border-radius: 10px; }

/* ── SIDEBAR ── */
[data-testid="stSidebar"] { background: var(--surface) !important; border-right: 1px solid var(--border) !important; }
[data-testid="stSidebar"] .block-container { padding: 1.5rem 1.2rem; }

/* ── MASTHEAD ── */
.masthead {
  display: flex; align-items: center; gap: 16px;
  padding: 22px 0 28px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 36px;
  position: relative;
}
.masthead::after {
  content: ""; position: absolute; bottom: -1px; left: 0;
  width: 200px; height: 1px;
  background: linear-gradient(90deg, var(--accent), transparent);
}
.logo-mark {
  width: 44px; height: 44px;
  background: linear-gradient(135deg, var(--accent), var(--accent2));
  border-radius: 10px;
  display: flex; align-items: center; justify-content: center;
  font-size: 22px; flex-shrink: 0;
  box-shadow: 0 0 24px rgba(0,230,180,0.25), 0 0 60px rgba(0,230,180,0.08);
  position: relative;
}
.logo-mark::after {
  content: ""; position: absolute; inset: -3px;
  border-radius: 13px; border: 1px solid rgba(0,230,180,0.2);
  animation: pulse-ring 3s ease-in-out infinite;
}
@keyframes pulse-ring {
  0%,100% { opacity: 0.5; transform: scale(1); }
  50%      { opacity: 0;   transform: scale(1.25); }
}
.brand-name {
  font-family: var(--font-mono); font-size: 1.1rem; font-weight: 700;
  color: #fff; letter-spacing: 4px; text-transform: uppercase; margin: 0;
}
.brand-sub {
  font-family: var(--font-data); font-size: 0.62rem;
  color: var(--text-dim); letter-spacing: 2.5px; text-transform: uppercase; margin-top: 2px;
}
.status-cluster { margin-left: auto; display: flex; align-items: center; gap: 10px; }
.status-dot {
  width: 7px; height: 7px; border-radius: 50%;
  background: var(--accent); box-shadow: 0 0 8px var(--accent);
  animation: blink 2s ease-in-out infinite;
}
@keyframes blink { 0%,100% { opacity:1; } 50% { opacity:0.3; } }
.status-text { font-family: var(--font-mono); font-size: 0.6rem; letter-spacing: 2.5px; text-transform: uppercase; color: var(--accent); }
.uptime-badge { font-family: var(--font-mono); font-size: 0.58rem; color: var(--text-dim); border: 1px solid var(--border); padding: 4px 10px; border-radius: 4px; letter-spacing: 1.5px; }

/* ── GLITCH ── */
@keyframes glitch {
  0%   { clip-path: inset(40% 0 60% 0); transform: translate(-4px,0); }
  20%  { clip-path: inset(70% 0 10% 0); transform: translate(4px,0); }
  40%  { clip-path: inset(10% 0 85% 0); transform: translate(-2px,0); }
  60%  { clip-path: inset(55% 0 30% 0); transform: translate(3px,0); }
  80%  { clip-path: inset(25% 0 65% 0); transform: translate(-3px,0); }
  100% { clip-path: inset(40% 0 60% 0); transform: translate(2px,0); }
}
.glitch-wrap { position: relative; display: inline-block; }
.glitch-wrap::before, .glitch-wrap::after { content: attr(data-text); position: absolute; inset: 0; font: inherit; }
.glitch-wrap::before { color: var(--danger); animation: glitch 2.5s infinite linear; opacity: 0.6; }
.glitch-wrap::after  { color: var(--accent2); animation: glitch 2.5s infinite linear reverse; opacity: 0.4; }

/* ── INPUT PANEL ── */
/* input-panel and corner-deco removed — div wrappers not compatible with Streamlit native widgets */

/* ── WIDGET OVERRIDES ── */
.stTextInput > div > div > input,
.stTextArea > div > div > textarea {
  background: rgba(2,7,17,0.8) !important; border: 1px solid rgba(0,230,180,0.10) !important;
  border-radius: 8px !important; color: var(--text) !important;
  font-family: var(--font-data) !important; font-size: 0.83rem !important;
  padding: 11px 15px !important; transition: border-color 0.2s, box-shadow 0.2s !important;
  caret-color: var(--accent) !important;
}
.stTextInput > div > div > input:focus,
.stTextArea > div > div > textarea:focus {
  border-color: rgba(0,230,180,0.4) !important;
  box-shadow: 0 0 0 3px rgba(0,230,180,0.06) !important; outline: none !important;
}
.stTextInput label, .stTextArea label {
  font-family: var(--font-mono) !important; font-size: 0.6rem !important;
  letter-spacing: 2.5px !important; text-transform: uppercase !important; color: var(--text-dim) !important;
}
.stRadio > label { font-family: var(--font-mono) !important; font-size: 0.6rem !important; letter-spacing: 2px !important; text-transform: uppercase !important; color: var(--text-dim) !important; }
.stFileUploader section { background: rgba(2,7,17,0.6) !important; border: 1px dashed rgba(0,230,180,0.15) !important; border-radius: 10px !important; transition: border-color 0.2s !important; }
.stFileUploader section:hover { border-color: rgba(0,230,180,0.4) !important; }

/* ── BUTTONS ── */
.stButton > button {
  background: linear-gradient(135deg, var(--accent) 0%, var(--accent2) 100%) !important;
  color: #020711 !important; border: none !important; border-radius: 8px !important;
  font-family: var(--font-mono) !important; font-size: 0.68rem !important; font-weight: 700 !important;
  letter-spacing: 3px !important; text-transform: uppercase !important; padding: 14px 28px !important;
  transition: all 0.25s ease !important; box-shadow: 0 0 28px rgba(0,230,180,0.18) !important;
}
.stButton > button:hover { transform: translateY(-2px) !important; box-shadow: 0 6px 40px rgba(0,230,180,0.35) !important; filter: brightness(1.08) !important; }
.stButton > button:active { transform: translateY(0) !important; }

/* ── DOWNLOAD BUTTON ── */
.stDownloadButton > button {
  background: transparent !important;
  border: 1px solid var(--border) !important;
  color: var(--text-mid) !important;
  font-family: var(--font-mono) !important; font-size: 0.62rem !important;
  letter-spacing: 2px !important; text-transform: uppercase !important;
  box-shadow: none !important;
  margin-bottom: 6px !important;
}
.stDownloadButton > button:hover { border-color: var(--accent) !important; color: var(--accent) !important; transform: translateY(-1px) !important; box-shadow: none !important; }

/* ── VERDICT BANNER ── */
.verdict-wrap {
  border-radius: 16px; padding: 30px 40px; margin-bottom: 32px;
  display: flex; align-items: center; gap: 28px;
  position: relative; overflow: hidden;
}
.v-critical { background: linear-gradient(135deg, rgba(255,68,102,0.07), rgba(127,10,30,0.12)); border: 1px solid rgba(255,68,102,0.3); }
.v-warning  { background: linear-gradient(135deg, rgba(255,170,0,0.07),  rgba(127,60,0,0.12));  border: 1px solid rgba(255,170,0,0.3); }
.v-safe     { background: linear-gradient(135deg, rgba(0,214,143,0.07),  rgba(0,80,50,0.12));   border: 1px solid rgba(0,214,143,0.3); }
.verdict-icon-wrap { width: 64px; height: 64px; border-radius: 16px; display: flex; align-items: center; justify-content: center; font-size: 30px; flex-shrink: 0; }
.v-critical .verdict-icon-wrap { background: rgba(255,68,102,0.12); border: 1px solid rgba(255,68,102,0.25); }
.v-warning  .verdict-icon-wrap { background: rgba(255,170,0,0.12);  border: 1px solid rgba(255,170,0,0.25); }
.v-safe     .verdict-icon-wrap { background: rgba(0,214,143,0.12);  border: 1px solid rgba(0,214,143,0.25); }
.verdict-eyebrow { font-family: var(--font-mono); font-size: 0.58rem; letter-spacing: 4px; text-transform: uppercase; color: var(--text-dim); margin-bottom: 5px; }
.verdict-heading { font-family: var(--font-ui); font-size: 2rem; font-weight: 800; margin: 0; line-height: 1.1; }
.v-critical .verdict-heading { color: #ff6688; }
.v-warning  .verdict-heading { color: #ffbb33; }
.v-safe     .verdict-heading { color: #00d68f; }
.verdict-body { font-size: 0.8rem; color: var(--text-mid); margin-top: 6px; font-family: var(--font-data); letter-spacing: 0.3px; }
.verdict-score-badge { margin-left: auto; text-align: center; flex-shrink: 0; }
.verdict-score-num { font-family: var(--font-mono); font-size: 3.2rem; font-weight: 700; line-height: 1; }
.v-critical .verdict-score-num { color: var(--danger); }
.v-warning  .verdict-score-num { color: var(--warn); }
.v-safe     .verdict-score-num { color: var(--safe); }
.verdict-score-label { font-family: var(--font-mono); font-size: 0.55rem; letter-spacing: 2px; text-transform: uppercase; color: var(--text-dim); margin-top: 2px; }

/* ── METRIC STRIP ── */
.metric-strip { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 28px; }
.metric-tile {
  background: var(--surface); border: 1px solid var(--border2); border-radius: 12px;
  padding: 18px 20px; position: relative; overflow: hidden;
  transition: border-color 0.2s, transform 0.2s;
}
.metric-tile:hover { border-color: var(--border); transform: translateY(-2px); }
.metric-tile::before { content: ""; position: absolute; bottom:0; left:12px; right:12px; height:1px; background: linear-gradient(90deg, transparent, rgba(0,230,180,0.2), transparent); }
.metric-tile-icon { font-size: 1.1rem; margin-bottom: 8px; opacity: 0.7; }
.metric-tile-val { font-family: var(--font-mono); font-size: 1.6rem; font-weight: 700; color: #fff; line-height: 1; }
.metric-tile-label { font-family: var(--font-mono); font-size: 0.58rem; letter-spacing: 2px; text-transform: uppercase; color: var(--text-dim); margin-top: 5px; }
.metric-tile-delta { position: absolute; top: 14px; right: 14px; font-family: var(--font-mono); font-size: 0.55rem; letter-spacing: 1px; padding: 2px 7px; border-radius: 10px; }
.delta-bad  { background: rgba(255,68,102,0.12); color: var(--danger); }
.delta-warn { background: rgba(255,170,0,0.12);  color: var(--warn); }
.delta-ok   { background: rgba(0,214,143,0.12);  color: var(--safe); }

/* ── TIMELINE ── */
.timeline-wrap { display: flex; flex-direction: column; gap: 0; margin: 32px 0; }
.timeline-step { display: flex; align-items: flex-start; gap: 18px; padding: 16px 0; opacity: 0.3; transition: opacity 0.4s ease; }
.timeline-step.active { opacity: 1; }
.timeline-step.done   { opacity: 0.6; }
.timeline-connector { display: flex; flex-direction: column; align-items: center; flex-shrink: 0; }
.t-node { width: 28px; height: 28px; border-radius: 50%; border: 2px solid var(--text-dim); display: flex; align-items: center; justify-content: center; font-family: var(--font-mono); font-size: 0.65rem; color: var(--text-dim); background: var(--bg); transition: all 0.4s ease; }
.timeline-step.active .t-node { border-color: var(--accent); color: var(--accent); box-shadow: 0 0 12px rgba(0,230,180,0.4); animation: node-pulse 1.2s ease-in-out infinite; }
.timeline-step.done   .t-node { border-color: var(--accent); background: rgba(0,230,180,0.15); color: var(--accent); }
@keyframes node-pulse { 0%,100% { box-shadow: 0 0 12px rgba(0,230,180,0.4); } 50% { box-shadow: 0 0 24px rgba(0,230,180,0.7); } }
.t-line { width: 1px; flex: 1; min-height: 24px; background: linear-gradient(to bottom, var(--text-dim), transparent); }
.timeline-step.done .t-line { background: linear-gradient(to bottom, var(--accent), rgba(0,230,180,0.1)); }
.t-title { font-family: var(--font-mono); font-size: 0.75rem; letter-spacing: 2px; text-transform: uppercase; color: var(--text); }
.timeline-step.active .t-title { color: var(--accent); }
.t-desc { font-family: var(--font-data); font-size: 0.7rem; color: var(--text-dim); margin-top: 3px; }

/* ── SCAN CENTRE ── */
.scan-centre { text-align: center; padding: 60px 0 20px; }
.scan-rings { position: relative; width: 110px; height: 110px; margin: 0 auto 32px; }
.ring { position: absolute; inset: 0; border-radius: 50%; border: 1px solid transparent; }
.ring-1 { border-top-color: var(--accent);  animation: spin 1.2s linear infinite; }
.ring-2 { inset: 10px; border-right-color: var(--accent2); animation: spin 1.8s linear infinite reverse; }
.ring-3 { inset: 22px; border-bottom-color: var(--accent3); animation: spin 2.4s linear infinite; }
.ring-core { position: absolute; inset: 34px; border-radius: 50%; background: radial-gradient(circle, rgba(0,230,180,0.2), rgba(0,230,180,0.02)); animation: core-pulse 2s ease-in-out infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
@keyframes core-pulse { 0%,100% { opacity:0.6; transform:scale(0.9); } 50% { opacity:1; transform:scale(1.1); } }
.scan-title-text { font-family: var(--font-mono); font-size: 0.8rem; letter-spacing: 5px; color: var(--accent); text-transform: uppercase; margin-bottom: 6px; }
.scan-sub-text { font-family: var(--font-data); font-size: 0.7rem; color: var(--text-dim); letter-spacing: 1px; }

/* ── PROGRESS BAR ── */
.stProgress > div > div { background: rgba(0,230,180,0.06) !important; border-radius: 4px !important; height: 3px !important; }
.stProgress > div > div > div { background: linear-gradient(90deg, var(--accent), var(--accent2)) !important; border-radius: 4px !important; }

/* ── FINDING ROW ── */
.finding-row { display: flex; align-items: flex-start; gap: 12px; padding: 12px 16px; background: rgba(2,7,17,0.6); border: 1px solid var(--border2); border-radius: 8px; margin-bottom: 7px; transition: border-color 0.2s; }
.finding-row:hover { border-color: var(--border); }
.f-dot { width: 7px; height: 7px; border-radius: 50%; margin-top: 5px; flex-shrink: 0; }
.f-text { font-family: var(--font-data); font-size: 0.8rem; color: var(--text-mid); line-height: 1.55; }

/* ── ACTION BOX ── */
.action-box { border-radius: 10px; padding: 18px 22px; margin-top: 18px; display: flex; align-items: flex-start; gap: 14px; }
.ab-critical { background: rgba(255,68,102,0.06);  border: 1px solid rgba(255,68,102,0.22); }
.ab-warning  { background: rgba(255,170,0,0.06);   border: 1px solid rgba(255,170,0,0.22); }
.ab-safe     { background: rgba(0,214,143,0.06);   border: 1px solid rgba(0,214,143,0.22); }
.ab-icon { font-size: 1.6rem; line-height: 1; }
.ab-label { font-family: var(--font-mono); font-size: 0.55rem; letter-spacing: 3px; text-transform: uppercase; color: var(--text-dim); margin-bottom: 4px; }
.ab-text { font-family: var(--font-data); font-size: 0.8rem; color: var(--text); line-height: 1.5; }

/* ── TABS ── */
.stTabs [data-baseweb="tab-list"] { background: transparent !important; border-bottom: 1px solid var(--border) !important; gap: 0 !important; }
.stTabs [data-baseweb="tab"] { font-family: var(--font-mono) !important; font-size: 0.62rem !important; letter-spacing: 2px !important; text-transform: uppercase !important; color: var(--text-dim) !important; background: transparent !important; border: none !important; padding: 10px 18px !important; transition: color 0.2s !important; }
.stTabs [aria-selected="true"] { color: var(--accent) !important; border-bottom: 2px solid var(--accent) !important; }
.stTabs [data-baseweb="tab-panel"] { background: rgba(8,14,28,0.5) !important; border: 1px solid var(--border) !important; border-top: none !important; border-radius: 0 0 12px 12px !important; padding: 24px !important; }

/* ── SECTION HEADING ── */
.sh { font-family: var(--font-mono); font-size: 0.58rem; letter-spacing: 4px; text-transform: uppercase; color: var(--text-dim); margin-bottom: 16px; padding-bottom: 10px; border-bottom: 1px solid var(--border2); display: flex; align-items: center; gap: 8px; }
.sh::before { content: "◈"; color: var(--accent); font-size: 0.65rem; }

/* ── PILLS ── */
.pill { display: inline-flex; align-items: center; gap: 5px; padding: 3px 9px; border-radius: 20px; font-family: var(--font-mono); font-size: 0.58rem; font-weight: 700; letter-spacing: 1.5px; text-transform: uppercase; }
.p-green  { background: rgba(0,214,143,0.10);  color: var(--safe);   border: 1px solid rgba(0,214,143,0.25); }
.p-red    { background: rgba(255,68,102,0.10); color: var(--danger); border: 1px solid rgba(255,68,102,0.25); }
.p-yellow { background: rgba(255,170,0,0.10);  color: var(--warn);   border: 1px solid rgba(255,170,0,0.25); }
.p-grey   { background: rgba(100,120,150,0.1); color: #8faabb;       border: 1px solid rgba(100,120,150,0.2); }
.p-blue   { background: rgba(0,119,255,0.10);  color: #66aaff;       border: 1px solid rgba(0,119,255,0.25); }

/* ── DATA TABLE ── */
.data-table { width: 100%; border-collapse: collapse; }
.data-table tr { border-bottom: 1px solid var(--border2); }
.data-table tr:last-child { border-bottom: none; }
.data-table td { padding: 10px 6px; font-family: var(--font-data); font-size: 0.78rem; vertical-align: top; }
.dt-key { color: var(--text-dim); font-size: 0.6rem; letter-spacing: 2px; text-transform: uppercase; font-family: var(--font-mono); white-space: nowrap; padding-right: 20px; width: 160px; }
.dt-val { color: var(--text); }

/* ── URL CARD ── */
.url-card { background: rgba(2,7,17,0.7); border: 1px solid var(--border2); border-radius: 10px; padding: 14px 18px; margin-bottom: 10px; transition: border-color 0.2s; }
.url-card:hover { border-color: var(--border); }
.url-str { font-family: var(--font-data); font-size: 0.72rem; color: var(--text-mid); word-break: break-all; margin-bottom: 10px; line-height: 1.45; }
.url-meta { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.url-engines { font-family: var(--font-mono); font-size: 0.58rem; letter-spacing: 1px; color: var(--text-dim); }

/* ── INDICATOR CARD ── */
.ind-card { background: rgba(2,7,17,0.7); border: 1px solid var(--border2); border-left: 3px solid rgba(255,170,0,0.4); border-radius: 0 9px 9px 0; padding: 13px 17px; margin-bottom: 9px; transition: border-color 0.2s; }
.ind-card:hover { border-left-color: rgba(255,170,0,0.7); }
.ind-phrase { font-family: var(--font-data); font-size: 0.8rem; color: var(--warn); margin-bottom: 5px; }
.ind-weight { font-family: var(--font-mono); font-size: 0.6rem; letter-spacing: 1.5px; color: var(--text-dim); }
.weight-bar-wrap { height: 3px; background: rgba(255,170,0,0.08); border-radius: 3px; margin-top: 8px; overflow: hidden; }
.weight-bar { height: 100%; background: linear-gradient(90deg, var(--warn), rgba(255,68,102,0.8)); border-radius: 3px; }

/* ── ATTACHMENT CARD ── */
.att-card { display: flex; align-items: center; gap: 14px; padding: 13px 17px; background: rgba(2,7,17,0.7); border: 1px solid var(--border2); border-radius: 10px; margin-bottom: 9px; transition: border-color 0.2s; }
.att-card:hover { border-color: var(--border); }
.att-icon { font-size: 1.3rem; flex-shrink: 0; }
.att-name { font-family: var(--font-data); font-size: 0.8rem; color: var(--text); flex: 1; }
.att-size { font-family: var(--font-mono); font-size: 0.6rem; color: var(--text-dim); margin-top: 2px; letter-spacing: 1px; }

/* ── HISTORY CARD ── */
.hist-card { background: rgba(2,7,17,0.8); border: 1px solid var(--border2); border-radius: 10px; padding: 12px 14px; margin-bottom: 8px; transition: border-color 0.2s, background 0.2s; }
.hist-card:hover { border-color: var(--border); background: rgba(8,14,28,0.9); }
.hist-score { font-family: var(--font-mono); font-size: 1.1rem; font-weight: 700; float: right; line-height: 1; }
.hist-subject { font-family: var(--font-data); font-size: 0.72rem; color: var(--text); margin-bottom: 4px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 160px; }
.hist-time { font-family: var(--font-mono); font-size: 0.58rem; color: var(--text-dim); letter-spacing: 1px; }

/* ── INFO CHIP ── */
.info-chip { display: inline-flex; align-items: center; gap: 6px; background: rgba(0,119,255,0.08); border: 1px solid rgba(0,119,255,0.2); border-radius: 6px; padding: 6px 12px; font-family: var(--font-data); font-size: 0.72rem; color: #66aaff; }

/* ── BREAKDOWN CARD ── */
.breakdown-card {
  background: rgba(2,7,17,0.7);
  border: 1px solid var(--border2);
  border-radius: 12px;
  padding: 24px 28px;
}
.breakdown-vec { margin-bottom: 20px; }
.breakdown-vec:last-child { margin-bottom: 0; }
.breakdown-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 7px; }
.breakdown-label { font-family: var(--font-mono); font-size: 0.62rem; letter-spacing: 2px; text-transform: uppercase; color: var(--text-mid); }
.breakdown-val { font-family: var(--font-mono); font-size: 0.75rem; font-weight: 700; }
.breakdown-bar-track { height: 5px; background: rgba(255,255,255,0.05); border-radius: 4px; overflow: hidden; }
.breakdown-bar-fill { height: 100%; border-radius: 4px; }

/* ── COMPOSITE SCORE BOX ── */
.composite-box {
  background: rgba(2,7,17,0.7);
  border: 1px solid var(--border2);
  border-radius: 12px;
  padding: 22px 28px;
  margin-top: 16px;
  display: flex;
  align-items: center;
  gap: 20px;
}
.composite-num { font-family: var(--font-mono); font-size: 2.8rem; font-weight: 700; line-height: 1; }
.composite-meta { font-family: var(--font-data); font-size: 0.75rem; color: var(--text-mid); margin-top: 4px; }
.composite-label { font-family: var(--font-mono); font-size: 0.55rem; letter-spacing: 3px; text-transform: uppercase; color: var(--text-dim); margin-bottom: 4px; }

/* ── MISC ── */
hr { border-color: var(--border2) !important; margin: 28px 0 !important; }
.stSuccess { background: rgba(0,214,143,0.06) !important; border: 1px solid rgba(0,214,143,0.2) !important; border-radius: 8px !important; }
.stInfo    { background: rgba(0,119,255,0.06) !important; border: 1px solid rgba(0,119,255,0.2) !important; border-radius: 8px !important; }
.stWarning { background: rgba(255,170,0,0.06) !important; border: 1px solid rgba(255,170,0,0.2) !important; border-radius: 8px !important; }
.stError   { background: rgba(255,68,102,0.06) !important; border: 1px solid rgba(255,68,102,0.2) !important; border-radius: 8px !important; }
.streamlit-expanderHeader { background: rgba(2,7,17,0.8) !important; border: 1px solid var(--border2) !important; border-radius: 8px !important; font-family: var(--font-mono) !important; font-size: 0.65rem !important; letter-spacing: 1.5px !important; color: var(--text-mid) !important; }

@keyframes fadeInUp { from { opacity:0; transform:translateY(16px); } to { opacity:1; transform:translateY(0); } }
.fade-in { animation: fadeInUp 0.5s ease forwards; }

.sidebar-heading { font-family: Space Mono,monospace; font-size: 0.55rem; letter-spacing: 3px; text-transform: uppercase; color: #3d5470; margin-bottom: 12px; padding-bottom: 8px; border-bottom: 1px solid rgba(255,255,255,0.05); }
</style>
""", unsafe_allow_html=True)


# ====================================================
# HELPERS
# ====================================================

def render_masthead(status="SYSTEM READY", status_color="var(--accent)"):
    now = datetime.datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    st.markdown(f"""
    <div class="masthead fade-in">
      <div class="logo-mark">🛡️</div>
      <div>
        <p class="brand-name">Phishing Email Detector</p>
        <p class="brand-sub">Threat Intelligence Engine · v3.0</p>
      </div>
      <div class="status-cluster">
        <div class="status-dot" style="background:{status_color};box-shadow:0 0 8px {status_color};"></div>
        <span class="status-text">{status}</span>
        <span class="uptime-badge">{now}</span>
      </div>
    </div>
    """, unsafe_allow_html=True)


def draw_risk_gauge(score):
    color = "#ff4466" if score >= 7 else "#ffaa00" if score >= 4 else "#00d68f"
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=score,
        number={"font": {"size": 42, "color": color, "family": "Space Mono"}},
        domain={"x": [0, 1], "y": [0, 1]},
        title={"text": "RISK SCORE", "font": {"size": 10, "color": "#3d5470", "family": "Space Mono"}},
        gauge={
            "axis": {"range": [0, 10], "tickwidth": 0, "tickcolor": "rgba(0,0,0,0)",
                     "tickfont": {"color": "#3d5470", "size": 8, "family": "Space Mono"}, "nticks": 6},
            "bar": {"color": color, "thickness": 0.16},
            "bgcolor": "rgba(0,0,0,0)", "borderwidth": 0,
            "steps": [
                {"range": [0,   3.3], "color": "rgba(0,214,143,0.06)"},
                {"range": [3.3, 6.6], "color": "rgba(255,170,0,0.06)"},
                {"range": [6.6, 10],  "color": "rgba(255,68,102,0.06)"},
            ],
            "threshold": {"line": {"color": color, "width": 3}, "thickness": 0.8, "value": score}
        }
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#b8c8dc", "family": "Space Mono"},
        height=230, margin=dict(l=16, r=16, t=38, b=10)
    )
    return fig


def build_report_md(res, subject="", sender=""):
    now  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    spf  = res["spf_analysis"]
    urls = res.get("url_analysis", [])
    atts = res.get("attachment_analysis", [])
    inds = res["content_analysis"].get("matched_indicators", [])
    lines = [
        "# Phishing Email Detector — Threat Analysis Report",
        f"**Generated:** {now}  |  **Engine:** Phishing Email Detector v3.0", "",
        "---", "", "## Executive Summary",
        "| Field | Value |", "|---|---|",
        f"| Verdict | **{res['summary']['verdict']}** |",
        f"| Risk Score | **{res['summary']['risk_score']} / 10** |",
        f"| Confidence | **{res['summary']['confidence']}%** |",
        f"| Subject | {subject or '—'} |", f"| Sender | {sender or '—'} |",
        "", "## Key Findings",
    ]
    for r in res.get("reasons", []):
        lines.append(f"- {r}")
    lines += ["", "## Network & Authentication",
              f"- **Domain:** {spf.get('domain','—')}",
              f"- **SPF Status:** {spf.get('status','—').upper()}",
              f"- **Raw Record:** `{spf.get('raw_record','—')}`",
              "", "## URL Analysis"]
    for u in urls:
        lines.append(f"- `{u['url']}` — **{u['status'].upper()}** ({u.get('malicious',0)} engines)")
    if not urls:
        lines.append("- No URLs detected.")
    lines += ["", "## Behavioural Indicators"]
    for i in inds:
        lines.append(f"- \"{i['phrase']}\" — weight +{i['weight']}")
    if not inds:
        lines.append("- None detected.")
    lines += ["", "## Attachments"]
    for a in atts:
        lines.append(f"- `{a['filename']}` — {'⚠ FLAGGED' if a['risk_flag'] else '✓ Clean'}")
    if not atts:
        lines.append("- No attachments.")
    lines += ["", "---", "_Report generated by Phishing Email Detector Threat Intelligence Engine_"]
    return "\n".join(lines)


def save_to_history(subject, sender, score, verdict, result):
    if "scan_history" not in st.session_state:
        st.session_state.scan_history = []
    st.session_state.scan_history.insert(0, {
        "ts":      datetime.datetime.now().strftime("%H:%M:%S"),
        "subject": subject[:40] if subject else "(no subject)",
        "sender":  sender[:30]  if sender  else "—",
        "score":   score,
        "verdict": verdict,
        "result":  result,
    })
    st.session_state.scan_history = st.session_state.scan_history[:8]


def build_timeline_html(steps, active_index):
    html = ""
    for j, (t, d) in enumerate(steps):
        cls = "done" if j < active_index else ("active" if j == active_index else "")
        sym = "\u2713" if j < active_index else str(j + 1)
        connector = '<div class="t-line"></div>' if j < len(steps) - 1 else ""
        step = '<div class="timeline-step ' + cls + '">'
        step += '<div class="timeline-connector">'
        step += '<div class="t-node">' + sym + '</div>'
        step += connector
        step += '</div>'
        step += '<div style="padding-top:3px;">'
        step += '<div class="t-title">' + t + '</div>'
        step += '<div class="t-desc">' + d + '</div>'
        step += '</div>'
        step += '</div>'
        html += step
    return '<div class="timeline-wrap">' + html + '</div>' 


# ====================================================
# SESSION STATE INIT
# ====================================================
for key, default in [
    ("stage", "input"), ("analysis_result", None), ("temp_data", None),
    ("scan_history", []), ("current_subject", ""), ("current_sender", ""),
]:
    if key not in st.session_state:
        st.session_state[key] = default


# ====================================================
# SIDEBAR
# ====================================================
with st.sidebar:
    st.markdown(
        '<div style="padding:16px 0 20px;">'
        '<p style="font-family:Space Mono,monospace;font-size:0.6rem;letter-spacing:3px;'
        'text-transform:uppercase;color:#3d5470;margin:0;">◈ Phishing Email Detector</p></div>',
        unsafe_allow_html=True
    )

    history = st.session_state.scan_history
    total   = len(history)
    highs   = sum(1 for h in history if h["score"] >= 7)
    avg_s   = round(sum(h["score"] for h in history) / total, 1) if total else 0

    st.markdown(f"""
    <div style="margin-bottom:24px;">
      <p class="sidebar-heading">Session Stats</p>
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;">
        <div style="background:rgba(2,7,17,0.8);border:1px solid rgba(0,230,180,0.08);border-radius:8px;padding:10px 8px;text-align:center;">
          <div style="font-family:Space Mono,monospace;font-size:1.3rem;font-weight:700;color:#fff;">{total}</div>
          <div style="font-family:Space Mono,monospace;font-size:0.5rem;letter-spacing:1.5px;color:#3d5470;text-transform:uppercase;margin-top:2px;">Total</div>
        </div>
        <div style="background:rgba(2,7,17,0.8);border:1px solid rgba(255,68,102,0.1);border-radius:8px;padding:10px 8px;text-align:center;">
          <div style="font-family:Space Mono,monospace;font-size:1.3rem;font-weight:700;color:#ff4466;">{highs}</div>
          <div style="font-family:Space Mono,monospace;font-size:0.5rem;letter-spacing:1.5px;color:#3d5470;text-transform:uppercase;margin-top:2px;">Critical</div>
        </div>
        <div style="background:rgba(2,7,17,0.8);border:1px solid rgba(0,230,180,0.08);border-radius:8px;padding:10px 8px;text-align:center;">
          <div style="font-family:Space Mono,monospace;font-size:1.3rem;font-weight:700;color:#b8c8dc;">{avg_s}</div>
          <div style="font-family:Space Mono,monospace;font-size:0.5rem;letter-spacing:1.5px;color:#3d5470;text-transform:uppercase;margin-top:2px;">Avg</div>
        </div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<p class="sidebar-heading">Recent Scans</p>', unsafe_allow_html=True)
    if not history:
        st.markdown(
            '<p style="font-family:Space Mono,monospace;font-size:0.65rem;color:#3d5470;letter-spacing:1px;">'
            'No scans this session.</p>',
            unsafe_allow_html=True
        )
    else:
        for idx, h in enumerate(history):
            sc = "#ff4466" if h["score"] >= 7 else "#ffaa00" if h["score"] >= 4 else "#00d68f"
            st.markdown(f"""
            <div class="hist-card">
              <span class="hist-score" style="color:{sc};">{h['score']}</span>
              <div class="hist-subject">{h['subject']}</div>
              <div class="hist-time">⏱ {h['ts']} · {h['verdict']}</div>
            </div>
            """, unsafe_allow_html=True)
            if st.button("Load", key=f"hist_{idx}", use_container_width=True):
                st.session_state.analysis_result = h["result"]
                st.session_state.current_subject = h["subject"]
                st.session_state.current_sender  = h["sender"]
                st.session_state.stage = "results"
                st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)
    if st.session_state.stage != "input":
        if st.button("＋  New Scan", use_container_width=True):
            st.session_state.stage = "input"
            st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown('<p class="sidebar-heading">Display Options</p>', unsafe_allow_html=True)
    show_raw_spf = st.toggle("Show Raw SPF Record", value=True)
    compact_urls = st.toggle("Compact URL Display", value=False)


# ====================================================
# ██  INPUT STAGE
# ====================================================
if st.session_state.stage == "input":
    render_masthead()

    st.markdown(
        '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:22px;">'
        '<p style="font-family:Space Mono,monospace;font-size:0.6rem;letter-spacing:3px;'
        'color:#00e6b4;text-transform:uppercase;margin:0;">◈ Configure Detection Vector</p>'
        '<span style="font-family:Space Mono,monospace;font-size:0.55rem;letter-spacing:2px;'
        'text-transform:uppercase;color:#3d5470;">INPUT MODULE · ACTIVE</span>'
        '</div>',
        unsafe_allow_html=True
    )

    mode = st.radio("", ["✦  Manual Entry", "✦  Raw email File Upload (.eml)"],
                    horizontal=True, label_visibility="collapsed")
    st.markdown("<br>", unsafe_allow_html=True)

    subject, sender, body, attachments = "", "", "", []

    if "Manual" in mode:
        c1, c2 = st.columns(2)
        with c1:
            subject = st.text_input("Subject Line", placeholder="e.g. Urgent: Verify your account now")
        with c2:
            sender = st.text_input("Sender Address", placeholder="e.g. no-reply@secure-bank-verify.net")
        body = st.text_area("Email Body", height=200, placeholder="Paste the complete email body for analysis...")
    else:
        uploaded_file = st.file_uploader("Drop .eml file for deep forensic inspection", type=["eml"])
        if uploaded_file:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp:
                tmp.write(uploaded_file.read())
                email_path = tmp.name
            subject, sender, body, msg = extract_email_content(email_path)
            attachments = extract_attachments(msg) if msg else []
            st.success(f"✓  Parsed: {subject[:70]}")

    st.markdown("<br>", unsafe_allow_html=True)
    cb, ci = st.columns([1.4, 3])
    with cb:
        if st.button("▶  EXECUTE THREAT SCAN", use_container_width=True):
            st.session_state.stage = "scanning"
            st.session_state.temp_data = (subject, sender, body, attachments)
            st.session_state.current_subject = subject
            st.session_state.current_sender  = sender
            st.rerun()
    with ci:
        st.markdown(
            '<div class="info-chip" style="margin-top:14px;">'
            'ℹ &nbsp; NLP heuristics · SPF/DKIM inspection · URL threat feeds · Attachment sandbox'
            '</div>',
            unsafe_allow_html=True
        )



# ====================================================
# ██  SCANNING STAGE
# ====================================================
elif st.session_state.stage == "scanning":
    render_masthead("SCANNING", "#ffaa00")

    _, mid, _ = st.columns([1, 2, 1])
    with mid:
        st.markdown("""
        <div class="scan-centre fade-in">
          <div class="scan-rings">
            <div class="ring ring-1"></div>
            <div class="ring ring-2"></div>
            <div class="ring ring-3"></div>
            <div class="ring-core"></div>
          </div>
          <p class="scan-title-text">Initialising Analysis</p>
          <p class="scan-sub-text">Neural heuristic engine · active</p>
        </div>
        """, unsafe_allow_html=True)

    steps = [
        ("SPF / DKIM Validation",    "Authenticating sender identity against DNS records"),
        ("URL Reputation Check",      "Cross-referencing 87 global threat intelligence feeds"),
        ("Attachment Sandboxing",     "Executing payload analysis in isolated environment"),
        ("NLP Behavioural Analysis",  "Scanning social engineering patterns &amp; urgency markers"),
    ]

    # Create placeholders ONCE, outside the loop
    step_ph = st.empty()
    bar     = st.progress(0)

    for i in range(len(steps)):
        # Render the full timeline for this step, then sleep
        step_ph.markdown(build_timeline_html(steps, i), unsafe_allow_html=True)
        bar.progress((i + 1) * 25)
        time.sleep(0.7)

    subject, sender, body, attachments = st.session_state.temp_data
    result = analyze_email_input(subject=subject, sender=sender, body=body, attachments=attachments)
    save_to_history(subject, sender, result["summary"]["risk_score"], result["summary"]["verdict"], result)
    st.session_state.analysis_result = result
    st.session_state.stage = "results"
    st.rerun()


# ====================================================
# ██  RESULTS STAGE
# ====================================================
elif st.session_state.stage == "results":
    res     = st.session_state.analysis_result
    score   = res["summary"]["risk_score"]
    verdict = res["summary"]["verdict"]
    conf    = int(res["summary"]["confidence"])
    subj    = st.session_state.current_subject
    sndr    = st.session_state.current_sender

    if verdict == "Highly Suspicious":
        v_cls, ab_cls = "v-critical", "ab-critical"
        v_icon, v_label, v_title = "🚨", "CRITICAL THREAT", "Highly Suspicious"
        v_body     = "Multiple high-confidence attack signatures detected. Do not interact with this email."
        dot_col    = "#ff4466"
        action_icon = "🚨"
        action_text = "REPORT & DELETE — Do not click links, open attachments, or reply. Forward to your security team immediately."
        status_str, status_col = "THREAT DETECTED", "#ff4466"
    elif verdict == "Moderately Suspicious":
        v_cls, ab_cls = "v-warning", "ab-warning"
        v_icon, v_label, v_title = "⚠️", "CAUTION ADVISED", "Moderately Suspicious"
        v_body     = "Suspicious patterns found. Verify sender through a secondary channel before acting."
        dot_col    = "#ffaa00"
        action_icon = "⚠️"
        action_text = "VERIFY BEFORE ACTING — Confirm sender identity independently. Do not use contact info provided within this email."
        status_str, status_col = "SUSPICIOUS", "#ffaa00"
    else:
        v_cls, ab_cls = "v-safe", "ab-safe"
        v_icon, v_label, v_title = "✅", "THREAT LEVEL", "Negligible Risk"
        v_body     = "No significant threat indicators found. Standard caution still advised."
        dot_col    = "#00d68f"
        action_icon = "✅"
        action_text = "CLEAR — No malicious patterns identified. Normal caution applies when clicking external links."
        status_str, status_col = "ALL CLEAR", "#00d68f"

    render_masthead(status_str, status_col)

    # Glitch effect on critical verdict title
    gw_open  = f'<span class="glitch-wrap" data-text="{v_title}">' if score >= 7 else ""
    gw_close = "</span>" if score >= 7 else ""

    # ── Verdict Banner ──
    subj_line = (
        f'<p style="font-family:DM Mono,monospace;font-size:0.62rem;color:#3d5470;'
        f'margin-top:8px;letter-spacing:1px;">Subject: {subj[:70]}</p>'
        if subj else ""
    )
    st.markdown(f"""
    <div class="verdict-wrap {v_cls} fade-in">
      <div class="verdict-icon-wrap">{v_icon}</div>
      <div style="flex:1;">
        <p class="verdict-eyebrow">{v_label}</p>
        <h1 class="verdict-heading">{gw_open}{v_title}{gw_close}</h1>
        <p class="verdict-body">{v_body}</p>
        {subj_line}
      </div>
      <div class="verdict-score-badge">
        <div class="verdict-score-num">{score}</div>
        <div style="font-family:Space Mono,monospace;font-size:0.7rem;color:#6b85a0;">/10</div>
        <div class="verdict-score-label">Risk Score</div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Metric Strip ──
    n_url  = len(res.get("url_analysis", []))
    n_att  = len(res.get("attachment_analysis", []))
    n_ind  = len(res["content_analysis"].get("matched_indicators", []))
    spf_ok = res["spf_analysis"].get("status", "unknown") == "pass"

    def dc(v, bad, warn):
        return "delta-bad" if v >= bad else ("delta-warn" if v >= warn else "delta-ok")

    st.markdown(f"""
    <div class="metric-strip fade-in">
      <div class="metric-tile">
        <span class="metric-tile-delta {dc(score,7,4)}">{score}/10</span>
        <div class="metric-tile-icon">🎯</div>
        <div class="metric-tile-val">{score}</div>
        <div class="metric-tile-label">Risk Score</div>
      </div>
      <div class="metric-tile">
        <span class="metric-tile-delta {'delta-ok' if conf>=80 else 'delta-warn'}">{conf}%</span>
        <div class="metric-tile-icon">🧠</div>
        <div class="metric-tile-val">{conf}%</div>
        <div class="metric-tile-label">Confidence</div>
      </div>
      <div class="metric-tile">
        <span class="metric-tile-delta {dc(n_url,3,1)}">{n_url} found</span>
        <div class="metric-tile-icon">🔗</div>
        <div class="metric-tile-val">{n_url}</div>
        <div class="metric-tile-label">URLs Scanned</div>
      </div>
      <div class="metric-tile">
        <span class="metric-tile-delta {dc(n_att,2,1)}">{n_att} found</span>
        <div class="metric-tile-icon">📁</div>
        <div class="metric-tile-val">{n_att}</div>
        <div class="metric-tile-label">Attachments</div>
      </div>
      <div class="metric-tile">
        <span class="metric-tile-delta {'delta-ok' if spf_ok else 'delta-bad'}">{'PASS' if spf_ok else 'FAIL'}</span>
        <div class="metric-tile-icon">🔐</div>
        <div class="metric-tile-val">{'PASS' if spf_ok else 'FAIL'}</div>
        <div class="metric-tile-label">SPF Status</div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Two-column layout ──
    left, right = st.columns([1, 1.7])

    with left:
        st.plotly_chart(draw_risk_gauge(score), use_container_width=True)

        st.markdown(f"""
        <div class="action-box {ab_cls}">
          <div class="ab-icon">{action_icon}</div>
          <div>
            <div class="ab-label">Recommended Action</div>
            <div class="ab-text">{action_text}</div>
          </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        st.download_button(
            "⬇  Export Threat Report (.md)",
            data=build_report_md(res, subj, sndr),
            file_name=f"phishing_detector_report_{ts}.md",
            mime="text/markdown",
            use_container_width=True
        )
        st.download_button(
            "⬇  Export Raw Data (.json)",
            data=json.dumps({
                "generated": datetime.datetime.now().isoformat(),
                "subject": subj, "sender": sndr,
                "summary": res["summary"],
                "reasons": res.get("reasons", []),
                "spf": res["spf_analysis"],
                "urls": res.get("url_analysis", []),
                "attachments": res.get("attachment_analysis", []),
                "indicators": res["content_analysis"].get("matched_indicators", []),
            }, indent=2),
            file_name=f"phishing_detector_{ts}.json",
            mime="application/json",
            use_container_width=True
        )

    with right:
        st.markdown('<p class="sh">Key Findings</p>', unsafe_allow_html=True)
        reasons = res.get("reasons", [])
        if reasons:
            for r in reasons:
                st.markdown(
                    f'<div class="finding-row">'
                    f'<div class="f-dot" style="background:{dot_col};box-shadow:0 0 5px {dot_col};"></div>'
                    f'<div class="f-text">{r}</div></div>',
                    unsafe_allow_html=True
                )
        else:
            st.markdown(
                '<div class="finding-row">'
                '<div class="f-dot" style="background:#00d68f;box-shadow:0 0 5px #00d68f;"></div>'
                '<div class="f-text">No significant threat indicators detected.</div></div>',
                unsafe_allow_html=True
            )

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Detail Tabs ──
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "  🌐  Network & Auth  ",
        "  🔗  URLs  ",
        "  🧠  Behavioural NLP  ",
        "  📁  Attachments  ",
        "  📊  Score Breakdown  ",
    ])

    # ── Tab 1: Network ──
    with tab1:
        spf    = res["spf_analysis"]
        status = spf.get("status", "unknown")
        domain = spf.get("domain", "—")
        raw    = spf.get("raw_record", "No record found")
        spf_pill = {
            "pass":  '<span class="pill p-green">✓ PASS</span>',
            "fail":  '<span class="pill p-red">✗ FAIL</span>',
            "error": '<span class="pill p-yellow">⚠ ERROR</span>',
        }.get(status, '<span class="pill p-grey">UNKNOWN</span>')

        st.markdown('<p class="sh">Sender Authentication</p>', unsafe_allow_html=True)
        st.markdown(f"""
        <table class="data-table">
          <tr><td class="dt-key">Domain</td><td class="dt-val">{domain}</td></tr>
          <tr><td class="dt-key">SPF Status</td><td class="dt-val">{spf_pill}</td></tr>
          <tr><td class="dt-key">DKIM</td><td class="dt-val"><span class="pill p-grey">NOT EVALUATED</span></td></tr>
          <tr><td class="dt-key">DMARC</td><td class="dt-val"><span class="pill p-grey">NOT EVALUATED</span></td></tr>
        </table>
        """, unsafe_allow_html=True)

        if show_raw_spf:
            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown('<p class="sh">Raw SPF Record</p>', unsafe_allow_html=True)
            st.code(raw, language="text")

        if status == "fail":
            st.error("⚠ SPF authentication failed — sender domain unverified. High spoofing risk.")
        elif status == "error":
            if "does not exist" in raw.lower():
                st.error("🚨 Sender domain does not exist. High spoofing risk.")
            else:
                st.warning("SPF lookup error occurred. DNS misconfiguration or no record published.")

    # ── Tab 2: URLs ──
    with tab2:
        urls = res.get("url_analysis", [])
        st.markdown('<p class="sh">URL Reputation Analysis</p>', unsafe_allow_html=True)
        if urls:
            mal  = sum(1 for u in urls if u["status"] == "malicious")
            susp = sum(1 for u in urls if u["status"] == "suspicious")
            cln  = len(urls) - mal - susp
            pills_html = f'<span class="pill p-grey">{len(urls)} total</span>'
            if mal:  pills_html += f'<span class="pill p-red">{mal} malicious</span>'
            if susp: pills_html += f'<span class="pill p-yellow">{susp} suspicious</span>'
            if cln:  pills_html += f'<span class="pill p-green">{cln} clean</span>'
            st.markdown(
                f'<div style="display:flex;gap:10px;margin-bottom:18px;flex-wrap:wrap;">{pills_html}</div>',
                unsafe_allow_html=True
            )
            for u in urls:
                s = u.get("status", "unknown")
                upill = (
                    '<span class="pill p-red">✗ MALICIOUS</span>'   if s == "malicious" else
                    '<span class="pill p-yellow">⚠ SUSPICIOUS</span>' if s == "suspicious" else
                    '<span class="pill p-green">✓ CLEAN</span>'
                )
                url_disp = (u["url"][:60] + "…" if compact_urls and len(u["url"]) > 60 else u["url"])
                st.markdown(
                    f'<div class="url-card">'
                    f'<div class="url-str">🔗 {url_disp}</div>'
                    f'<div class="url-meta">{upill}'
                    f'<span class="url-engines">Flagged by {u.get("malicious", 0)} engines</span>'
                    f'</div></div>',
                    unsafe_allow_html=True
                )
        else:
            st.markdown(
                '<div class="finding-row"><div class="f-dot" style="background:#00d68f;"></div>'
                '<div class="f-text">No URLs detected in email body.</div></div>',
                unsafe_allow_html=True
            )

    # ── Tab 3: Behavioural NLP ──
    with tab3:
        indicators = res["content_analysis"].get("matched_indicators", [])
        st.markdown('<p class="sh">Linguistic & Behavioural Indicators</p>', unsafe_allow_html=True)
        if indicators:
            total_w = sum(i["weight"] for i in indicators)
            max_w   = max(i["weight"] for i in indicators)
            st.markdown(
                f'<div style="display:flex;gap:10px;margin-bottom:18px;">'
                f'<span class="pill p-yellow">{len(indicators)} patterns matched</span>'
                f'<span class="pill p-red">Total weight: +{total_w}</span></div>',
                unsafe_allow_html=True
            )
            for item in indicators:
                bp = int((item["weight"] / max(max_w, 1)) * 100)
                st.markdown(
                    f'<div class="ind-card">'
                    f'<div class="ind-phrase">"{item["phrase"]}"</div>'
                    f'<div class="ind-weight">Urgency / manipulation weight: +{item["weight"]}</div>'
                    f'<div class="weight-bar-wrap"><div class="weight-bar" style="width:{bp}%;"></div></div>'
                    f'</div>',
                    unsafe_allow_html=True
                )
        else:
            st.markdown(
                '<div class="finding-row"><div class="f-dot" style="background:#00d68f;"></div>'
                '<div class="f-text">No behavioural manipulation patterns detected.</div></div>',
                unsafe_allow_html=True
            )

    # ── Tab 4: Attachments ──
    with tab4:
        atts = res.get("attachment_analysis", [])
        st.markdown('<p class="sh">Attachment Security Report</p>', unsafe_allow_html=True)
        if atts:
            flagged = sum(1 for a in atts if a["risk_flag"])
            pills_html = f'<span class="pill p-grey">{len(atts)} total</span>'
            if flagged: pills_html += f'<span class="pill p-red">{flagged} flagged</span>'
            pills_html += f'<span class="pill p-green">{len(atts) - flagged} clean</span>'
            st.markdown(
                f'<div style="display:flex;gap:10px;margin-bottom:18px;">{pills_html}</div>',
                unsafe_allow_html=True
            )
            for att in atts:
                icon      = "🚫" if att["risk_flag"] else "✅"
                flag_pill = (
                    '<span class="pill p-red">⚠ FLAGGED</span>'
                    if att["risk_flag"] else
                    '<span class="pill p-green">✓ CLEAN</span>'
                )
                ext = att["filename"].rsplit(".", 1)[-1].upper() if "." in att["filename"] else "—"
                st.markdown(
                    f'<div class="att-card">'
                    f'<div class="att-icon">{icon}</div>'
                    f'<div style="flex:1;"><div class="att-name">{att["filename"]}</div>'
                    f'<div class="att-size">Extension: .{ext}</div></div>'
                    f'{flag_pill}</div>',
                    unsafe_allow_html=True
                )
        else:
            st.markdown(
                '<div class="finding-row"><div class="f-dot" style="background:#00d68f;"></div>'
                '<div class="f-text">No attachments detected — clean envelope.</div></div>',
                unsafe_allow_html=True
            )

    # ── Tab 5: Score Breakdown ──
    with tab5:
        st.markdown('<p class="sh">Attack Vector Score Breakdown</p>', unsafe_allow_html=True)

        # Compute vector scores
        _urls  = res.get("url_analysis", [])
        _atts  = res.get("attachment_analysis", [])
        _inds  = res["content_analysis"].get("matched_indicators", [])
        _spf   = res["spf_analysis"].get("status", "unknown")

        url_score  = min(10, sum(3 if u["status"] == "malicious" else 1 for u in _urls))
        att_score  = min(10, sum(4 if a["risk_flag"] else 0 for a in _atts))
        lang_score = min(10, sum(i["weight"] for i in _inds))
        spf_score  = 8 if _spf == "fail" else 4 if _spf in ("error", "unknown") else 1
        id_score   = round(min(10, score * 0.9), 1)

        breakdown = {
            "URLs":        url_score,
            "Language":    lang_score,
            "Attachments": att_score,
            "Sender Auth": spf_score,
            "Identity":    id_score,
        }

        col_bars, col_summary = st.columns([1.6, 1])

        with col_bars:
            bars_html = '<div class="breakdown-card">'
            for vec, val in breakdown.items():
                pct   = int(val / 10 * 100)
                c_bar = "#ff4466" if val >= 7 else "#ffaa00" if val >= 4 else "#00d68f"
                bars_html += f"""
                <div class="breakdown-vec">
                  <div class="breakdown-header">
                    <span class="breakdown-label">{vec}</span>
                    <span class="breakdown-val" style="color:{c_bar};">{val}/10</span>
                  </div>
                  <div class="breakdown-bar-track">
                    <div class="breakdown-bar-fill" style="width:{pct}%;background:{c_bar};"></div>
                  </div>
                </div>"""
            bars_html += "</div>"
            st.markdown(bars_html, unsafe_allow_html=True)

        with col_summary:
            st.markdown(f"""
            <div class="composite-box">
              <div>
                <div class="composite-label">Composite Score</div>
                <div class="composite-num" style="color:{dot_col};">
                  {score}<span style="font-size:1rem;color:#3d5470;">/10</span>
                </div>
                <div class="composite-meta">Confidence: {conf}%</div>
                <div class="composite-meta">{verdict}</div>
              </div>
            </div>
            """, unsafe_allow_html=True)