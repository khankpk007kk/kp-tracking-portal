import base64, hashlib, hmac, html, json, os, re, secrets, smtplib, time
from datetime import date, datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from urllib.parse import quote, unquote
import bcrypt, pandas as pd, streamlit as st
import streamlit.components.v1 as components
from supabase import create_client

APP_TITLE = "SECRETARIATE WORKFLOW MANAGEMENT SYSTEM"
st.set_page_config(page_title=APP_TITLE, layout="wide", page_icon="ðŸ“„")

def get_secret(k, d=""):
    try: return st.secrets[k]
    except: return d

SUPABASE_URL = get_secret("SUPABASE_URL", "YOUR_SUPABASE_URL")
SUPABASE_KEY = get_secret("SUPABASE_KEY", "YOUR_SUPABASE_KEY")
SMTP_SERVER, SMTP_PORT = get_secret("SMTP_SERVER", "smtp.gmail.com"), int(get_secret("SMTP_PORT", "587"))
SENDER_EMAIL, SENDER_PASSWORD = get_secret("SENDER_EMAIL", ""), get_secret("SENDER_PASSWORD", "")
IT_MASTER_USER = get_secret("IT_MASTER_USER", "it_section").strip().lower()
IT_RECOVERY_EMAIL = get_secret("IT_RECOVERY_EMAIL", "").strip().lower()
LOGO_PATH = "kpk_logo.png"
STORAGE_BUCKET = get_secret("STORAGE_BUCKET", "file-attachments")
APP_SECRET = get_secret("APP_SECRET", hashlib.sha256(f"{SUPABASE_URL}|{SUPABASE_KEY}|{APP_TITLE}".encode()).hexdigest())

# âœ… FIX #1: SEAT_BPS_SCALE ab 3-22 hai (pehle 17-22 tha)
BPS_SCALE, SEAT_BPS_SCALE = list(range(3, 23)), list(range(3, 23))

PENDING_STATUSES, CLOSED_STATUSES = ["Pending", "Dispatched", "Returned"], ["Successful", "Closed", "Rejected"]
SECTION_LETTERHEAD_NAME, TARGET_SECRET_MARKER = "SECTION_LETTERHEAD", "[TARGET_SECRET:"
DEFAULT_SETTINGS = {"session_timeout_minutes": 120, "max_login_attempts": 5, "lockout_duration_minutes": 15}
DEFAULT_LOGO_DATA_URL = ""

try:
    if os.path.exists(LOGO_PATH):
        with open(LOGO_PATH, "rb") as f:
            DEFAULT_LOGO_DATA_URL = "data:image/png;base64," + base64.b64encode(f.read()).decode()
except: pass

TEMPLATE_DEFAULT_BODY = '<div class="meta-row"><div><strong>No.</strong>{REGISTRY_NO}</div><div><strong>Dated:</strong>{ISSUE_DATE}</div></div><div class="to-block"><strong>To</strong><br>{RECIPIENT_BLOCK}</div><div class="subject-line"><strong>Subject:</strong>{SUBJECT_LINE}</div><div class="reference-line">{REFERENCE_LINE}</div><div class="body-copy">{BODY_HTML}</div><div class="signature-block"><strong>{ISSUER_NAME}</strong><br>{ISSUER_DESIGNATION}</div><div class="copy-block"><strong>Copy forwarded:</strong><br>{COPY_FORWARD}</div>'

DEFAULT_SESSION_STATE = {
    "session_authenticated": False, "user_token": None, "user_role": None,
    "user_bps": 3, "section_name": None, "current_view": "Login",
    "login_attempts": 0, "lockout_until": None, "last_activity": time.time()
}

@st.cache_resource
def init_supabase():
    try:
        if not SUPABASE_URL or SUPABASE_URL == "YOUR_SUPABASE_URL" or not SUPABASE_KEY or SUPABASE_KEY == "YOUR_SUPABASE_KEY":
            return None
        return create_client(SUPABASE_URL, SUPABASE_KEY)
    except: return None

supabase = init_supabase()
nt = lambda v: str(v).strip() if v is not None else ""
nl = lambda v: nt(v).lower()
nu = lambda v: nt(v).upper()
sanitize_base = lambda t: re.sub(r"[^a-zA-Z0-9]+", "", nl(t))[:18] or "section"

def ml_html(t):
    t = nt(t)
    if not t: return ""
    e = html.escape(t)
    b = [x.strip() for x in e.split("\n\n") if x.strip()]
    return "".join(f"<p>{x.replace(chr(10), '<br>')}</p>" for x in b) if b else e.replace("\n", "<br>")

nl_html = lambda t: html.escape(nt(t)).replace("\n", "<br>") if t else ""

def get_pub_url(p):
    if not supabase or not p: return ""
    try:
        r = supabase.storage.from_(STORAGE_BUCKET).get_public_url(p)
        return r.get("publicUrl", "") if isinstance(r, dict) else str(r)
    except: return ""

def get_file_access_url(p, expires_in=3600):
    if not supabase or not p: return ""
    try:
        r = supabase.storage.from_(STORAGE_BUCKET).create_signed_url(p, expires_in)
        if isinstance(r, dict):
            return r.get("signedURL") or r.get("signedUrl") or r.get("signed_url") or r.get("url") or get_pub_url(p)
        return get_pub_url(p)
    except:
        return get_pub_url(p)

# âœ… FIX #11: File size validation added (10MB limit)
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

def upload_file(prefix, uf):
    if not supabase or not uf: return None, "Storage N/A"
    if uf.size > MAX_FILE_SIZE:
        return None, f"File too large. Max {MAX_FILE_SIZE // (1024*1024)}MB allowed"
    sn = re.sub(r"[^A-Za-z0-9._-]+", "", uf.name)
    p = f"{prefix}/{int(time.time())}_{secrets.token_hex(4)}_{sn}"
    try:
        supabase.storage.from_(STORAGE_BUCKET).upload(p, uf.getvalue(), {"content-type": getattr(uf, "type", None) or "application/octet-stream"})
        return p, ""
    except Exception as e: return None, str(e)

# âœ… FIX #2: Non e â†’ None
def dl_file(p):
    if not supabase or not p: return None
    try: return supabase.storage.from_(STORAGE_BUCKET).download(p)
    except: return None

f2url = lambda u: f"data:{u.type or 'image/png'};base64," + base64.b64encode(u.getvalue()).decode()

def mk_token(u):
    exp = int(time.time()) + 43200
    payload = f"{u}|{exp}"
    sig = hmac.new(APP_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return quote(f"{u}|{exp}|{sig}")

def vf_token(t):
    try:
        u, exp, sig = unquote(t).split("|")
        if int(exp) < time.time(): return None
        if not hmac.compare_digest(hmac.new(APP_SECRET.encode(), f"{u}|{exp}".encode(), hashlib.sha256).hexdigest(), sig):
            return None
        return load_profile(u)
    except: return None

set_ck = lambda t: components.html(f"<script>document.cookie='kp_auth_token={t}; path=/; max-age=43200; SameSite=Lax';</script>", height=0, width=0)
clr_ck = lambda: components.html("<script>document.cookie='kp_auth_token=; path=/; max-age=0; SameSite=Lax';</script>", height=0, width=0)

# âœ… FIX #10: Cookie handling with fallback
def get_ck():
    try:
        if hasattr(st, 'context') and hasattr(st.context, 'cookies'):
            return st.context.cookies.get("kp_auth_token", "")
        return ""
    except: return ""

# âœ… FIX #8 & #12: sq default "*"
def dbs(tab, sq="*", fl=None):
    if not supabase: return []
    try:
        q = supabase.table(tab).select(sq)
        if fl:
            for c, v in fl.items(): q = q.eq(c, v)
        return q.execute().data or []
    except: return []

dbi = lambda t, d: supabase.table(t).insert(d).execute().data if supabase else None

# âœ… FIX #4: f.ite ms() â†’ f.items()
def dbu(t, d, f):
    if not supabase: return False
    try:
        q = supabase.table(t).update(d)
        for c, v in f.items(): q = q.eq(c, v)
        q.execute()
        return True
    except: return False

def dbsrch(t, cols, term, lim=100):
    if not supabase or not cols or not term: return []
    try:
        c = nt(term).replace(",", " ")
        if not c: return []
        return supabase.table(t).select("*").or_(",".join([f"{x}.ilike.%{c}%" for x in cols])).limit(lim).execute().data or []
    except: return []

# âœ… FIX #5: c no t in â†’ c not in
def sdf(rec, cols):
    if not rec: return pd.DataFrame(columns=cols)
    df = pd.DataFrame(rec)
    for c in cols:
        if c not in df.columns: df[c] = ""
    return df[cols]

def log_audit(at, pb, tu=None, details=None):
    dbi("audit_logs", {"action_type": at, "performed_by": pb, "target_user": tu, "details": details, "timestamp": datetime.now().isoformat()})

def send_notif(tgt, ttl, msg, nt="general"):
    dbi("notifications", {"target_user": tgt, "title": ttl, "message": msg, "is_read": False, "notification_type": nt, "created_at": datetime.now().isoformat()})

get_unread = lambda u: dbs("notifications", "*", {"target_user": u, "is_read": False})
mark_read = lambda u: dbu("notifications", {"is_read": True}, {"target_user": u})

@st.cache_data(ttl=60)
def get_settings():
    if not supabase: return DEFAULT_SETTINGS.copy()
    try:
        r = supabase.table("system_settings").select("*").order("id").limit(1).execute()
        d = DEFAULT_SETTINGS.copy()
        if r.data: d.update(r.data[0] or {})
        return d
    except: return DEFAULT_SETTINGS.copy()

# âœ… FIX #3: supabas e â†’ supabase
def save_settings(t, a, l, p):
    if not supabase: return False
    try:
        pl = {"session_timeout_minutes": int(t), "max_login_attempts": int(a), "lockout_duration_minutes": int(l)}
        r = supabase.table("system_settings").select("id").order("id").limit(1).execute()
        if r.data: supabase.table("system_settings").update(pl).eq("id", r.data[0]["id"]).execute()
        else: pl["id"] = 1; supabase.table("system_settings").insert(pl).execute()
        get_settings.clear()
        log_audit("settings_updated", p, details=f"t={t},a={a},l={l}")
        return True
    except: return False

uname_exists = lambda u: bool(dbs("registered_sections", "username", {"username": nl(u)}) or dbs("seat_allocations", "username", {"username": nl(u)}))
hash_pw = lambda r: bcrypt.hashpw(r.encode(), bcrypt.gensalt()).decode()

def ver_pw(r, s):
    if not s: return False
    try:
        if s.startswith(("$2a$", "$2b$", "$2y$")): return bcrypt.checkpw(r.encode(), s.encode())
    except: return False
    return hmac.compare_digest(hashlib.sha256(r.encode()).hexdigest(), s)

is_legacy = lambda s: bool(s) and not s.startswith(("$2a$", "$2b$", "$2y$"))
gen_pw = lambda: f"KP@{secrets.token_hex(4).upper()}!{datetime.now().year}"

def send_email(to, u, pw, sn):
    if not SENDER_EMAIL or not SENDER_PASSWORD: return False, "SMTP N/A"
    msg = MIMEMultipart()
    msg["From"] = SENDER_EMAIL
    msg["To"] = to
    msg["Subject"] = f"{APP_TITLE} Credentials"
    msg.attach(MIMEText(f"Hello {sn},\n\nLogin ID: {u}\nPassword: {pw}\n\nRegards,\nIT Section Control Department", "plain"))
    try:
        s = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        s.starttls()
        s.login(SENDER_EMAIL, SENDER_PASSWORD)
        s.sendmail(SENDER_EMAIL, to, msg.as_string())
        s.quit()
        return True, "OK"
    except Exception as e: return False, str(e)

def load_profile(u):
    u = nl(u)
    d = dbs("registered_sections", "*", {"username": u})
    if d and d[0].get("status") == "Active":
        role = "it_admin" if u == IT_MASTER_USER else "department"
        return {"user_token": u, "user_role": role, "user_bps": d[0].get("bps_level", 19), "section_name": "IT Section Control Department" if role == "it_admin" else d[0].get("section_name", "IT Section")}
    s = dbs("seat_allocations", "*", {"username": u})
    if s and s[0].get("status") == "Active":
        return {"user_token": u, "user_role": "seat_user", "user_bps": s[0].get("bps_level", 14), "section_name": s[0].get("section_name")}
    return None

def ensure_it():
    if not supabase: return
    if dbs("registered_sections", "*", {"username": IT_MASTER_USER}):
        dbu("registered_sections", {"department_name": "IT Section Control Department", "section_name": "IT Section Control Department"}, {"username": IT_MASTER_USER})
        return
    dbi("registered_sections", {"username": IT_MASTER_USER, "password_hash": hash_pw(gen_pw()), "department_name": "IT Section Control Department", "section_name": "IT Section Control Department", "head_name": "System Administrator", "bps_level": 20, "email_address": IT_RECOVERY_EMAIL, "telephone": "", "status": "Active"})

def load_draft(u):
    drafts = dbs("letter_drafts", "*", {"username": u})
    if not drafts: return None
    return sorted(drafts, key=lambda x: str(x.get("updated_at", "")), reverse=True)[0]

def save_draft(u, p):
    try:
        ex = dbs("letter_drafts", "id", {"username": u})
        d = {"draft_json": json.dumps(p, ensure_ascii=False), "updated_at": datetime.now().isoformat()}
        if ex: dbu("letter_drafts", d, {"username": u})
        else: d["username"] = u; dbi("letter_drafts", d)
        return True
    except: return False

def get_atts(fr):
    r = fr.get("remarks") or ""
    m = "[ATTACHMENTS_JSON]:"
    if m in r:
        try:
            a = json.loads(r.split(m, 1)[-1].strip())
            if not isinstance(a, list): return []
            for x in a:
                if isinstance(x, dict) and x.get("path"): x["url"] = get_file_access_url(x.get("path"))
            return a
        except: return []
    return []

def set_atts(fn, atts):
    r = dbs("file_tracking", "remarks", {"file_number": fn})
    if not r: return False
    base = (r[0].get("remarks") or "").split("[ATTACHMENTS_JSON]:", 1)[0].rstrip()
    nr = base + ("\n[ATTACHMENTS_JSON]:" + json.dumps(atts, ensure_ascii=False) if atts else "")
    return dbu("file_tracking", {"remarks": nr, "last_updated": datetime.now().isoformat()}, {"file_number": fn})

def upl_atts(fn, files):
    recs = []
    for f in files or []:
        p, e = upload_file(f"attachments/{fn}", f)
        if p: recs.append({"name": f.name, "path": p, "url": get_file_access_url(p)})
    return recs

enc_tgt = lambda t, txt: f"{TARGET_SECRET_MARKER}{base64.urlsafe_b64encode(nt(t).encode()).decode()}]{nt(txt)}"

def dec_tgt(txt):
    t = nt(txt)
    if t.startswith(TARGET_SECRET_MARKER):
        e = t.find("]")
        if e > len(TARGET_SECRET_MARKER):
            try: return base64.urlsafe_b64decode(t[len(TARGET_SECRET_MARKER):e].encode()).decode(), t[e+1:].strip()
            except: return None, t
    return None, t

# âœ… FIX #7: add_c mt â†’ add_cmt
def add_cmt(fn, cb, ct, sn=None, ii=True, rs="private", ts=None):
    ft = nt(ct)
    if rs == "public": ii = False
    elif rs == "targeted" and ts: ii = True; ft = enc_tgt(ts, ft)
    dbi("file_comments", {"file_number": fn, "comment_by": cb, "comment_text": ft, "section_name": sn, "is_internal": ii, "timestamp": datetime.now().isoformat()})

def get_cmts(fn, vs=None):
    out = []
    for c in dbs("file_comments", "*", {"file_number": fn}):
        c = dict(c)
        tgt, clean = dec_tgt(c.get("comment_text") or "")
        c["_tgt"] = tgt
        c["comment_text"] = clean
        if not c.get("is_internal"): out.append(c); continue
        if tgt:
            if vs and (tgt == vs or c.get("section_name") == vs): out.append(c)
            continue
        if vs and c.get("section_name") == vs: out.append(c)
    return sorted(out, key=lambda x: x.get("timestamp", ""), reverse=True)

def save_lh(sn, data, pb):
    pl = json.dumps({"kind": "section_letterhead", **data}, ensure_ascii=False)
    ex = dbs("letter_templates", "*", {"section_name": sn, "template_name": SECTION_LETTERHEAD_NAME})
    if ex:
        ok = dbu("letter_templates", {"template_body": pl, "last_updated": datetime.now().isoformat()}, {"id": ex[0].get("id")})
    else:
        ok = dbi("letter_templates", {"section_name": sn, "template_name": SECTION_LETTERHEAD_NAME, "template_body": pl, "created_by": pb, "last_updated": datetime.now().isoformat()}) is not None
    if ok: log_audit("section_letterhead_saved", pb, details=sn)
    return ok

def get_lh(sn):
    rows = dbs("letter_templates", "*", {"section_name": sn, "template_name": SECTION_LETTERHEAD_NAME})
    if rows:
        try: return json.loads(rows[0].get("template_body") or "{}")
        except: return None
    return None

def bmap(rn="", idv=None, rb="", sl="", rl="", bt="", cf="", iname="", ides="", sn="", dn="", fn=""):
    idd = idv.strftime("%d-%m-%Y") if idv and not isinstance(idv, str) else (idv or "")
    return {
        "REGISTRY_NO": html.escape(nt(rn)), "ISSUE_DATE": html.escape(idd),
        "RECIPIENT_BLOCK": nl_html(rb), "SUBJECT_LINE": html.escape(nt(sl)),
        "REFERENCE_LINE": nl_html(rl), "BODY_HTML": ml_html(bt),
        "COPY_FORWARD": nl_html(cf), "ISSUER_NAME": html.escape(nt(iname)),
        "ISSUER_DESIGNATION": html.escape(nt(ides)), "SECTION_NAME": html.escape(nt(sn)),
        "DEPARTMENT_NAME": html.escape(nt(dn)), "FILE_NUMBER": html.escape(nt(fn))
    }

def render(th, fm):
    r = th or ""
    for k, v in fm.items(): r = r.replace("{" + k + "}", v or "")
    return r

def get_css(ps): return ("8.5in", "11in") if ps == "Letter" else ("210mm", "297mm")

def build_letter(fm, pso=None, sdu=None, enclosures=None, lh=None):
    ps = pso or "A4"
    bh = render(TEMPLATE_DEFAULT_BODY, fm)
    w, mh = get_css(ps)
    st_tag = f'<img src="{sdu}" class="sig-img" alt="Sig">' if sdu else ""
    if st_tag and '<div class="signature-block">' in bh:
        bh = bh.replace('<div class="signature-block">', f'<div class="signature-block">{st_tag}', 1)
    elif st_tag:
        bh += f'<div class="signature-block">{st_tag}<strong>{fm.get("ISSUER_NAME", "")}</strong><br>{fm.get("ISSUER_DESIGNATION", "")}</div>'
    ei = [{"name": i.get("name",""), "url": i.get("url","")} if isinstance(i, dict) else {"name": str(i), "url": ""} for i in (enclosures or [])]
    if ei:
        encl_items = []
        for a in ei:
            a_url = html.escape(a.get("url") or "", quote=True)
            a_name = html.escape(a.get("name") or "att")
            if a.get("url"):
                encl_items.append(f'<li><a href="{a_url}" target="_blank">{a_name}</a></li>')
            else:
                encl_items.append(f'<li>{a_name}</li>')
        bh += f'<div class="enclosures"><strong>Encl ({len(ei)}):</strong><ul>{"".join(encl_items)}</ul></div>'
    lh = lh or {}
    l1 = html.escape(lh.get("line1") or "Government of Khyber Pakhtunkhwa")
    l2 = html.escape(lh.get("line2") or fm.get("DEPARTMENT_NAME", ""))
    l3 = html.escape(lh.get("line3") or "Civil Secretariat Peshawar")
    cont = " | ".join([html.escape(x) for x in [lh.get("head_name"), lh.get("email"), lh.get("phone")] if nt(x)])
    lu = get_pub_url(lh.get("logo_image_path")) or DEFAULT_LOGO_DATA_URL
    contact_html = f'<div class="letterhead-contact">{cont}</div>' if cont else ""
    lh_html = f'<div class="official-letterhead"><img src="{lu}" class="corner-logo" alt="Logo"><div class="letterhead-center"><strong>{l1}</strong><br>{l2}<br>{l3}{contact_html}</div><div class="corner-spacer"></div></div><div class="letterhead-rule"></div>'
    css = "@page {{ size: {0}; margin: 14mm; }} body {{ font-family:'Times New Roman',serif; background:#f3f6fa; margin:0; padding:20px; color:#111827; }} .page {{ width:{1}; min-height:{2}; background:white; padding:16mm 18mm; box-shadow:0 10px 30px rgba(15,23,42,.12); border:1px solid #e5e7eb; box-sizing:border-box; margin:0 auto; }} .official-letterhead {{ display:flex; align-items:center; gap:14px; margin-bottom:8px; }} .corner-logo {{ width:78px; height:78px; object-fit:contain; }} .letterhead-center {{ flex:1; text-align:center; font-size:16px; line-height:1.5; font-weight:700; }} .letterhead-contact {{ font-size:12px; font-weight:400; margin-top:4px; }} .corner-spacer {{ width:78px; }} .letterhead-rule {{ border-bottom:2px solid #15346b; margin-bottom:18px; }} .meta-row {{ display:flex; justify-content:space-between; font-size:17px; margin-bottom:18px; }} .to-block,.subject-line,.reference-line,.copy-block {{ font-size:18px; line-height:1.55; margin-bottom:16px; }} .body-copy {{ font-size:19px; line-height:1.9; text-align:justify; margin:18px 0; }} .body-copy p {{ margin:0 0 14px; }} .signature-block {{ margin-top:44px; margin-left:auto; width:260px; text-align:center; font-size:18px; }} .sig-img {{ max-height:90px; max-width:240px; display:block; margin:0 auto 6px; }} .enclosures {{ margin-top:26px; font-size:16px; }} .enclosures ul {{ margin:6px 0 0 18px; }} @media print {{ body {{ background:white; padding:0; }} .page {{ box-shadow:none; border:none; width:auto; min-height:auto; }} }}"
    return f'<html><head><meta charset="utf-8"><style>{css.format(ps,w,mh)}</style></head><body><div class="page">{lh_html}{bh}</div></body></html>', ps

dl_btn = lambda l, h, fn, k: st.download_button(label=l, data=h.encode("utf-8"), file_name=fn, mime="text/html", key=k)

def get_pc1(adp):
    adp = nu(adp)
    if not adp: return None
    r = dbs("pc1_master", "*", {"adp_number": adp})
    return r[0] if r else None

def get_apc(fn):
    out = []
    for l in dbs("file_pc1_links", "*", {"file_number": fn}):
        pc = get_pc1(l.get("pc1_adp"))
        if pc: out.append(pc)
    return out

def link_pc(fn, adp, pb):
    adp = nu(adp)
    if not fn or not adp or dbs("file_pc1_links", "*", {"file_number": fn, "pc1_adp": adp}) or not get_pc1(adp):
        return False
    return dbi("file_pc1_links", {"file_number": fn, "pc1_adp": adp, "linked_by": pb}) is not None

def upl_pc(adp, pct, stitle, uf, pb):
    adp = nu(adp)
    if not adp: return False, "ADP req.", None
    if get_pc1(adp): return False, "Exists.", get_pc1(adp)
    if not uf: return False, "Upload req.", None
    sp, e = upload_file("pc1", uf)
    if not sp: return False, f"Fail: {e}", None
    d = {"adp_number": adp, "scheme_title": nt(stitle), "pc_type": pct, "file_name": uf.name, "storage_path": sp, "uploaded_by": pb}
    r = dbi("pc1_master", d)
    if r:
        log_audit("pc1_uploaded", pb, details=adp)
        return True, "OK", r[0] if isinstance(r, list) and r else d
    return False, "Fail", None

def disp(fn, fd, td, at, rm=""):
    sm = {"dispatch": "Dispatched", "forward": "Dispatched", "return": "Returned", "reject": "Rejected"}
    dbu("file_tracking", {"current_desk": td, "status": sm.get(at, "Pending"), "last_updated": datetime.now().isoformat()}, {"file_number": fn})
    dbi("file_thread", {"file_number": fn, "from_desk": fd, "to_desk": td, "action_type": at, "remarks": rm, "timestamp": datetime.now().isoformat()})
    send_notif(td, f"File {at.title()} - {fn}", f"Remarks: {nt(rm)[:150]}", "file_received")

get_thread = lambda fn: sorted(dbs("file_thread", "*", {"file_number": fn}), key=lambda x: x.get("timestamp", ""), reverse=True)

def rej_file(fn, rb, reason):
    row = dbs("file_tracking", "*", {"file_number": fn})
    if not row: return False, "N/A"
    org = row[0].get("originating_section", "")
    if not dbu("file_tracking", {"status": "Rejected", "current_desk": org, "rejection_reason": reason, "rejected_by": rb, "rejected_at": datetime.now().isoformat(), "last_updated": datetime.now().isoformat()}, {"file_number": fn}):
        return False, "Fail"
    dbi("file_thread", {"file_number": fn, "from_desk": rb, "to_desk": org, "action_type": "reject", "remarks": f"REJECTED: {reason}", "timestamp": datetime.now().isoformat()})
    send_notif(org, f"File Rejected - {fn}", f"Reason: {nt(reason)[:150]}", "file_rejected")
    return True, "OK"

def get_overdue(files):
    today = datetime.now().date()
    ov, ds = [], []
    for f in files:
        dd = f.get("due_date")
        if dd and f.get("status") not in CLOSED_STATUSES:
            try:
                dt = datetime.strptime(str(dd)[:10], "%Y-%m-%d").date()
                dl = (dt - today).days
                if dl < 0: ov.append(f)
                elif dl <= 3: ds.append(f)
            except: continue
    return ov, ds

def can_act(ur, act, fd=None, ss=None):
    p = {
        "it_admin": ["view_all", "comment", "system_admin", "user_manage"],
        "department": ["view", "create", "dispatch", "forward", "return", "comment", "complete", "reject", "seat_manage"],
        "seat_user": ["view_assigned", "comment", "complete_assigned", "dispatch", "forward", "return"]
    }
    up = p.get(ur, [])
    if act in ("forward", "complete", "return", "reject"):
        if ur == "seat_user": return fd.get("current_desk") == ss.get("user_token") if fd and ss else False
        if ur == "department": return fd.get("current_desk") == ss.get("user_token") if fd and ss else False
    return act in up

def tog_seat(un, ns, pb):
    ok = dbu("seat_allocations", {"status": ns}, {"username": un})
    if ok:
        log_audit("seat_status_change", pb, un, f"Changed to {ns}")
        send_notif(un, f"Seat {ns}", f"{pb} changed status.", "account_status")
    return ok

def rel_seat(un, pb=None):
    un = nl(un)
    sr = dbs("seat_allocations", "*", {"username": un})
    if not sr: return False, "N/A"
    sn = sr[0].get("section_name")
    dr = dbs("registered_sections", "username", {"section_name": sn, "status": "Active"})
    td = dr[0].get("username") if dr else None
    if td:
        for f in dbs("file_tracking", "*", {"current_desk": un}):
            if f.get("status") in PENDING_STATUSES:
                dbu("file_tracking", {"current_desk": td, "last_updated": datetime.now().isoformat()}, {"file_number": f.get("file_number")})
        ok = dbu("seat_allocations", {"status": "Relinquished"}, {"username": un})
        if ok:
            log_audit("seat_relinquished", pb or un, un, f"Section: {sn}")
            if td: send_notif(td, "Seat Relinquished", f"{un} relinquished.", "account_status")
            return True, "OK"
    return False, "Fail"

for k, v in DEFAULT_SESSION_STATE.items():
    if k not in st.session_state: st.session_state[k] = v

def clr_sess():
    for k, v in DEFAULT_SESSION_STATE.items(): st.session_state[k] = v
    st.session_state.last_activity = time.time()

if not st.session_state.session_authenticated:
    ct = get_ck()
    if ct:
        pr = vf_token(ct)
        if pr:
            st.session_state.update({
                "session_authenticated": True, "user_token": pr["user_token"],
                "user_role": pr["user_role"], "user_bps": pr["user_bps"],
                "section_name": pr["section_name"], "current_view": "Dashboard",
                "last_activity": time.time()
            })

def chk_timeout():
    tm = int(get_settings().get("session_timeout_minutes", 120))
    if st.session_state.session_authenticated and time.time() - st.session_state.last_activity > tm * 60:
        clr_sess()
    st.session_state.last_activity = time.time()

def is_locked():
    if st.session_state.lockout_until:
        if time.time() < st.session_state.lockout_until: return True
        st.session_state.login_attempts = 0
        st.session_state.lockout_until = None
    return False

# âœ… FIX #6: s .get â†’ s.get
def rec_fail():
    s = get_settings()
    ma = int(s.get("max_login_attempts", 5))
    lm = int(s.get("lockout_duration_minutes", 15))
    st.session_state.login_attempts += 1
    if st.session_state.login_attempts >= ma:
        st.session_state.lockout_until = time.time() + lm * 60
        log_audit("account_locked", "system", details="Too many fails")

def auth_user(lu, lp):
    lu = nl(lu)
    if not lu or not lp: return False, "Enter both.", None
    dr = dbs("registered_sections", "*", {"username": lu})
    if dr and dr[0].get("status") == "Active":
        d = dr[0]
        if ver_pw(lp, d.get("password_hash")):
            if is_legacy(d.get("password_hash")):
                dbu("registered_sections", {"password_hash": hash_pw(lp)}, {"username": lu})
            role = "it_admin" if lu == IT_MASTER_USER else "department"
            log_audit("login_success", lu)
            return True, "OK", {"user_token": lu, "user_role": role, "user_bps": d.get("bps_level", 19), "section_name": "IT Section Control Department" if role == "it_admin" else d.get("section_name", "IT Section")}
    sr = dbs("seat_allocations", "*", {"username": lu})
    if sr and sr[0].get("status") == "Active":
        s = sr[0]
        if ver_pw(lp, s.get("password_hash")):
            if is_legacy(s.get("password_hash")):
                dbu("seat_allocations", {"password_hash": hash_pw(lp)}, {"username": lu})
            log_audit("login_success", lu)
            return True, "OK", {"user_token": lu, "user_role": "seat_user", "user_bps": s.get("bps_level", 14), "section_name": s.get("section_name")}
    rec_fail()
    log_audit("login_failed", lu)
    return False, "Invalid credentials.", None

@st.cache_data(ttl=60)
def get_all_files():
    return dbs("file_tracking", "*") if supabase else []

ensure_it()

st.markdown("""<style>
.stApp {
background: linear-gradient(-45deg, #f0f4f8, #d9e2ec, #bcccdc, #9fb3c8);
background-size: 400% 400%;
animation: lightMovement 18s ease infinite;
}
@keyframes lightMovement {
0% { background-position: 0% 50%; }
50% { background-position: 100% 50%; }
100% { background-position: 0% 50%; }
}
section[data-testid="stSidebar"] {
background: linear-gradient(135deg, rgba(255,255,255,.3), rgba(255,255,255,.1));
backdrop-filter: blur(16px); border-right: 1px solid rgba(255,255,255,.4);
}
.main-header { font-size: 2.1rem; font-weight: 700; color: #15346b; margin-bottom: .4rem; text-align: center; }
.sub-header { font-size: 1rem; font-weight: 600; color: #475569; margin-bottom: 1.2rem; text-align: center; }
.metric-box { border: 1px solid #ddd; padding: 14px; border-radius: 16px; text-align: center; background: white; }
.metric-val { font-size: 1.7rem; font-weight: 700; }
.metric-lbl { font-size: .8rem; font-weight: 700; text-transform: uppercase; }
.stButton>button { width: 100%; border-radius: 50px; font-weight: 600; }
div[data-testid="stTabs"] { animation: slideUpFade 1.2s cubic-bezier(0.2, 0.8, 0.2, 1) forwards; opacity: 0; }
.main-header, .sub-header { animation: slideDownFade 1s cubic-bezier(0.2, 0.8, 0.2, 1) forwards; }
@keyframes slideUpFade { from { opacity: 0; transform: translateY(40px); } to { opacity: 1; transform: translateY(0); } }
@keyframes slideDownFade { from { opacity: 0; transform: translateY(-30px); } to { opacity: 1; transform: translateY(0); } }
.logo-anim { position: relative; margin: 0 auto 20px auto; perspective: 1200px; }
.logo-anim img { position: absolute; inset: 0; width: 100%; height: 100%; object-fit: contain; opacity: 0; }
.logo-anim .p1 { clip-path: polygon(0 0, 50% 0, 50% 50%); animation: p_t_l 3.5s cubic-bezier(0.4, 0, 0.2, 1) infinite alternate; }
.logo-anim .p2 { clip-path: polygon(50% 0, 100% 0, 50% 50%); animation: p_t_r 3.5s cubic-bezier(0.4, 0, 0.2, 1) infinite alternate; }
.logo-anim .p3 { clip-path: polygon(100% 0, 100% 50%, 50% 50%); animation: p_r_t 3.5s cubic-bezier(0.4, 0, 0.2, 1) infinite alternate; }
.logo-anim .p4 { clip-path: polygon(100% 50%, 100% 100%, 50% 50%); animation: p_r_b 3.5s cubic-bezier(0.4, 0, 0.2, 1) infinite alternate; }
.logo-anim .p5 { clip-path: polygon(100% 100%, 50% 100%, 50% 50%); animation: p_b_r 3.5s cubic-bezier(0.4, 0, 0.2, 1) infinite alternate; }
.logo-anim .p6 { clip-path: polygon(50% 100%, 0 100%, 50% 50%); animation: p_b_l 3.5s cubic-bezier(0.4, 0, 0.2, 1) infinite alternate; }
.logo-anim .p7 { clip-path: polygon(0 100%, 0 50%, 50% 50%); animation: p_l_b 3.5s cubic-bezier(0.4, 0, 0.2, 1) infinite alternate; }
.logo-anim .p8 { clip-path: polygon(0 50%, 0 0, 50% 50%); animation: p_l_t 3.5s cubic-bezier(0.4, 0, 0.2, 1) infinite alternate; }
@keyframes p_t_l { 0% {transform:translate(-30px,-30px) rotate(-15deg);opacity:0} 40% {opacity:1} 100% {transform:none;opacity:1} }
@keyframes p_t_r { 0% {transform:translate(30px,-30px) rotate(15deg);opacity:0} 40% {opacity:1} 100% {transform:none;opacity:1} }
@keyframes p_r_t { 0% {transform:translate(40px,-10px) rotate(15deg);opacity:0} 40% {opacity:1} 100% {transform:none;opacity:1} }
@keyframes p_r_b { 0% {transform:translate(40px,10px) rotate(15deg);opacity:0} 40% {opacity:1} 100% {transform:none;opacity:1} }
@keyframes p_b_r { 0% {transform:translate(30px,30px) rotate(15deg);opacity:0} 40% {opacity:1} 100% {transform:none;opacity:1} }
@keyframes p_b_l { 0% {transform:translate(-30px,30px) rotate(-15deg);opacity:0} 40% {opacity:1} 100% {transform:none;opacity:1} }
@keyframes p_l_b { 0% {transform:translate(-40px,10px) rotate(-15deg);opacity:0} 40% {opacity:1} 100% {transform:none;opacity:1} }
@keyframes p_l_t { 0% {transform:translate(-40px,-10px) rotate(-15deg);opacity:0} 40% {opacity:1} 100% {transform:none;opacity:1} }
.dashboard-reset-btn-container { margin: 0 0 12px 0; }
div[data-testid="stButton"].dashboard-reset-btn > button {
border-radius: 999px !important; background: #ffffff !important; color: #15346b !important;
border: 1px solid #cbd5e1 !important; font-weight: 700 !important; width: auto !important; padding: 8px 20px !important;
}
div[data-testid="stButton"].dashboard-reset-btn > button:hover { background: #eff6ff !important; }
div[data-testid="column"] div[data-testid="stButton"] > button {
min-height: 104px; border-radius: 18px; padding: 14px 10px;
display: flex; flex-direction: column; align-items: center; justify-content: center;
text-align: center; box-sizing: border-box; transition: transform 0.2s ease, box-shadow 0.2s ease;
width: 100%; font-weight: 800; border: 1px solid #e2e8f0; background: white; color: #1e293b;
}
div[data-testid="column"] div[data-testid="stButton"] > button:hover {
transform: translateY(-4px); box-shadow: 0 8px 18px rgba(15, 23, 42, 0.12);
}
div[data-testid="column"] div[data-testid="stButton"] > button p {
font-size: 0.78rem !important; margin: 0 !important; font-weight: 800;
text-transform: uppercase; letter-spacing: 0.02em; color: #475569;
}
div[data-testid="column"] div[data-testid="stButton"] > button strong {
font-size: 1.65rem !important; font-weight: 800 !important; margin-bottom: 8px !important; color: #0f172a;
}
div[data-testid="column"] div[data-testid="stButton"] > button[data-baseweb="button"][kind="primary"] {
background: linear-gradient(135deg, #15346b 0%, #1e40af 100%); border-color: #15346b;
}
div[data-testid="column"] div[data-testid="stButton"] > button[data-baseweb="button"][kind="primary"] strong,
div[data-testid="column"] div[data-testid="stButton"] > button[data-baseweb="button"][kind="primary"] p {
color: white !important;
}
@media (max-width: 768px) {
div[data-testid="column"] div[data-testid="stButton"] > button { min-height: 90px; padding: 12px 6px; }
div[data-testid="column"] div[data-testid="stButton"] > button strong { font-size: 1.25rem !important; margin-bottom: 6px !important; }
div[data-testid="column"] div[data-testid="stButton"] > button p { font-size: 0.62rem !important; }
}
</style>""", unsafe_allow_html=True)

chk_timeout()

def show_anim_logo(sz=110):
    if not DEFAULT_LOGO_DATA_URL: return
    st.markdown(f'''
<div class="logo-anim" style="width:{sz}px;height:{sz}px;">
<img class="p1" src="{DEFAULT_LOGO_DATA_URL}">
<img class="p2" src="{DEFAULT_LOGO_DATA_URL}">
<img class="p3" src="{DEFAULT_LOGO_DATA_URL}">
<img class="p4" src="{DEFAULT_LOGO_DATA_URL}">
<img class="p5" src="{DEFAULT_LOGO_DATA_URL}">
<img class="p6" src="{DEFAULT_LOGO_DATA_URL}">
<img class="p7" src="{DEFAULT_LOGO_DATA_URL}">
<img class="p8" src="{DEFAULT_LOGO_DATA_URL}">
</div>''', unsafe_allow_html=True)

DASH_FILTERS = {"All", "Pending", "VIP", "Overdue", "Rejected"}

def sync_dash_filter():
    if "dash_filter" not in st.session_state: st.session_state.dash_filter = "All"
    qp = None
    try:
        qp = st.query_params.get("dash_filter")
        if isinstance(qp, list): qp = qp[0] if qp else None
    except: qp = None
    qp = nt(qp)
    if qp in DASH_FILTERS: st.session_state.dash_filter = qp
    elif st.session_state.get("dash_filter") not in DASH_FILTERS: st.session_state.dash_filter = "All"

if st.session_state.current_view == "Login":
    show_anim_logo(140)
    st.markdown(f'<div class="main-header">{APP_TITLE}</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">Civil Secretariat Peshawar - Enterprise Cloud Infrastructure</div>', unsafe_allow_html=True)
    tab_login, tab_register, tab_public = st.tabs(["User Login", "Department Registration", "Public Search"])
    with tab_login:
        st.subheader("Department aur Seat Staff Login")
        login_locked = is_locked()
        if login_locked:
            rem = int(st.session_state.lockout_until - time.time())
            st.error(f"Locked. {max(1, rem//60)} min baad try karein.")
        c1, c2 = st.columns([2,1])
        with c1:
            with st.form("login_form"):
                lu = st.text_input("Username / Seat ID", key="gen_login_user", disabled=login_locked)
                lp = st.text_input("Password", type="password", key="gen_login_pass", disabled=login_locked)
                if st.form_submit_button("Portal Access (Enter)", type="primary", disabled=login_locked):
                    ok, msg, ad = auth_user(lu, lp)
                    if ok:
                        st.session_state.update({"session_authenticated": True, "user_token": ad["user_token"], "user_role": ad["user_role"], "user_bps": ad["user_bps"], "section_name": ad["section_name"], "current_view": "Dashboard", "login_attempts": 0, "last_activity": time.time()})
                        set_ck(mk_token(ad["user_token"]))
                        st.rerun()
                    else: st.error(msg)
        with c2:
            with st.popover("Forgot Credentials?"):
                ru = st.text_input("Username", key="rec_u")
                re_ = st.text_input("Email", key="rec_e")
                if st.button("Send Access Key"):
                    ru = nl(ru)
                    re_ = nl(re_)
                    show = False
                    su = dbs("registered_sections", "*", {"username": ru})
                    seat = dbs("seat_allocations", "*", {"username": ru})
                    if IT_RECOVERY_EMAIL and ru == IT_MASTER_USER and re_ == IT_RECOVERY_EMAIL:
                        tp = gen_pw()
                        if dbu("registered_sections", {"password_hash": hash_pw(tp), "status": "Active"}, {"username": IT_MASTER_USER}):
                            send_email(re_, ru, tp, "IT Section Control Department")
                            log_audit("password_reset", ru, details="IT recovery email")
                            show = True
                    elif su and nl(su[0].get("email_address")) == re_:
                        tp = gen_pw()
                        if dbu("registered_sections", {"password_hash": hash_pw(tp)}, {"username": ru}):
                            send_email(re_, ru, tp, su[0].get("section_name"))
                            log_audit("password_reset", ru, details="Department recovery email")
                            show = True
                    elif seat and nl(seat[0].get("email_address")) == re_:
                        tp = gen_pw()
                        if dbu("seat_allocations", {"password_hash": hash_pw(tp)}, {"username": ru}):
                            send_email(re_, ru, tp, seat[0].get("section_name"))
                            log_audit("password_reset", ru, details="Seat recovery email")
                            show = True
                    st.success("Email sent if matched.") if show else st.info("Will send if matched.")
    with tab_register:
        st.subheader("Department Self-Registration")
        if "reg_msg" in st.session_state:
            st.success(st.session_state.reg_msg)
            st.code(st.session_state.reg_creds)
            del st.session_state.reg_msg
            del st.session_state.reg_creds
        with st.form("dept_reg_form", clear_on_submit=True):
            rd = st.text_input("Department Name")
            rs = st.text_input("Section Name")
            rh = st.text_input("Chief Name")
            rb = st.selectbox("BPS", options=BPS_SCALE, index=16)
            re_ = st.text_input("Email")
            rp = st.text_input("Phone")
            if st.form_submit_button("Generate Profile", type="primary"):
                rd, rs, rh, re_, rp = nt(rd), nt(rs), rh, nl(re_), nt(rp)
                if not (rd and rs and rh and re_):
                    st.error("Required fields.")
                else:
                    ub = sanitize_base(rs)
                    uc = ""
                    raw = ""
                    for _ in range(5):
                        sx = secrets.token_hex(4).lower()
                        cand = f"{ub}{sx}"
                        if not uname_exists(cand):
                            uc = cand
                            raw = f"KP@{sx.upper()}!{datetime.now().year}"
                            break
                    if not uc: st.error("Username fail.")
                    else:
                        res = dbi("registered_sections", {"username": uc, "password_hash": hash_pw(raw), "department_name": rd, "section_name": rs, "head_name": rh, "bps_level": rb, "email_address": re_, "telephone": rp, "status": "Active"})
                        if res:
                            st.session_state.reg_msg = "Created."
                            st.session_state.reg_creds = f"ID: {uc}\nPass: {raw}"
                            send_email(re_, uc, raw, rs)
                            log_audit("department_registered", uc)
                            st.rerun()
                        else: st.error("Failed.")
    with tab_public:
        st.subheader("Public File Tracking")
        sc = st.selectbox("Search Type", ["Letter / Registry Number", "ADP / PC-1/2 Number"])
        sq = st.text_input("Keyword")
        if st.button("Search", type="primary"):
            if not sq: st.error("Keyword req.")
            elif sc == "Letter / Registry Number":
                m = dbsrch("file_tracking", ["registry_number"], sq)
                if m:
                    df = sdf(m, ["registry_number", "status", "current_desk", "due_date"])
                    df.columns = ["Registry Number", "Current Status", "Current Desk", "Due Date"]
                    st.dataframe(df, use_container_width=True, hide_index=True)
                else: st.warning("No match.")
            else:
                pm = dbsrch("pc1_master", ["adp_number"], sq)
                rows = []
                for pc in pm:
                    for lnk in dbs("file_pc1_links", "*", {"pc1_adp": pc.get("adp_number")}):
                        for fr in dbs("file_tracking", "*", {"file_number": lnk.get("file_number")}):
                            rows.append({"registry_number": fr.get("registry_number"), "status": fr.get("status"), "current_desk": fr.get("current_desk"), "due_date": fr.get("due_date")})
                if rows:
                    df = pd.DataFrame(rows).drop_duplicates()
                    df.columns = ["Registry Number", "Current Status", "Current Desk", "Due Date"]
                    st.dataframe(df, use_container_width=True, hide_index=True)
                else: st.warning("No linked files.")

elif st.session_state.current_view == "Dashboard" and st.session_state.session_authenticated:
    with st.sidebar:
        show_anim_logo(110)
        st.markdown("### Control Center")
        st.markdown(f"{str(st.session_state.user_token).upper()}")
        if st.session_state.user_role == "it_admin":
            st.markdown("IT Section Control Department")
        else:
            st.markdown(f"{st.session_state.section_name}")
        st.markdown(f"{str(st.session_state.user_role).upper()} | BPS {st.session_state.user_bps}")
        st.markdown("---")
        if st.session_state.user_role == "it_admin":
            ms = st.radio("IT Admin Menu", ["System Overview", "Security Monitor", "User Management", "Audit Logs", "Settings"])
        else:
            ms = st.radio("Main Menu", ["Executive Dashboard", "File Intake & Dispatch", "Receiving File & Actions", "Seat Allotment & Profiles"])
        st.markdown("---")
        un = get_unread(st.session_state.user_token)
        if un:
            st.markdown(f"{len(un)} Notifications")
            for n in un[:3]: st.caption(f"- {n.get('title','')}")
            if st.button("Mark All Read"):
                mark_read(st.session_state.user_token)
                st.rerun()
        st.markdown("---")
        if st.session_state.user_role == "seat_user":
            with st.popover("Seat Relinquishment"):
                st.warning("Accept karne par seat leave hogi. Data save rahega.")
                ct = st.text_input("Type LEAVE to confirm", key="seat_rel_conf")
                if st.button("Accept & Relinquish", type="primary", key="seat_rel_btn"):
                    if nu(ct) == "LEAVE":
                        ok, msg = rel_seat(st.session_state.user_token, st.session_state.user_token)
                        if ok:
                            log_audit("logout_after_relinquish", st.session_state.user_token)
                            clr_ck()
                            clr_sess()
                            st.rerun()
                        else: st.error(msg)
                    else: st.error("Type LEAVE.")
        if st.button("Exit Session", type="primary"):
            log_audit("logout", st.session_state.user_token)
            clr_ck()
            clr_sess()
            st.rerun()
    
    all_files = get_all_files()
    
    if st.session_state.user_role == "it_admin":
        if ms == "System Overview":
            st.markdown(f'<div class="main-header">{APP_TITLE} - System Overview</div>', unsafe_allow_html=True)
            td = len(dbs("registered_sections", "username"))
            ad = len(dbs("registered_sections", "username", {"status": "Active"}))
            ts = len(dbs("seat_allocations", "username"))
            as_ = len(dbs("seat_allocations", "username", {"status": "Active"}))
            pf = len([r for r in all_files if r.get("status") in PENDING_STATUSES])
            rf = len([r for r in all_files if r.get("status") == "Rejected"])
            cols = st.columns(6)
            for c, v, l in zip(cols, [td, ad, ts, as_, pf, rf], ["Departments", "Active Depts", "Seats", "Active Seats", "Pending", "Rejected"]):
                c.markdown(f'<div class="metric-box"><div class="metric-val">{v}</div><div class="metric-lbl">{l}</div></div>', unsafe_allow_html=True)
            ov, _ = get_overdue(all_files)
            if ov:
                st.markdown("### Overdue Files")
                st.dataframe(sdf(ov, ["file_number", "subject", "current_desk", "due_date", "priority"]), use_container_width=True, hide_index=True)
        elif ms == "Security Monitor":
            st.markdown(f'<div class="main-header">Security Monitor</div>', unsafe_allow_html=True)
            logs = dbs("audit_logs", "*")
            now = datetime.now()
            def recent(ts, h=24):
                try: return (now - datetime.fromisoformat(str(ts).replace("Z", "+00:00")).replace(tzinfo=None)).total_seconds() <= h*3600
                except: return False
            fl = [l for l in logs if l.get("action_type") == "login_failed"]
            f24 = [l for l in fl if recent(l.get("timestamp"))]
            lk = [l for l in logs if l.get("action_type") == "account_locked"]
            rs = [l for l in logs if l.get("action_type") == "password_reset"]
            thr = "LOW" if len(f24) < 5 else ("MEDIUM" if len(f24) < 10 else "HIGH")
            cols = st.columns(4)
            for c, v, l in zip(cols, [len(f24), len(lk), len(rs), thr], ["Failed (24h)", "Lockouts", "Resets", "Threat"]):
                c.markdown(f'<div class="metric-box"><div class="metric-val">{v}</div><div class="metric-lbl">{l}</div></div>', unsafe_allow_html=True)
            if fl:
                st.dataframe(sdf(sorted(fl, key=lambda x: x.get("timestamp", ""), reverse=True)[:25], ["timestamp", "performed_by", "details"]), use_container_width=True, hide_index=True)
            if logs:
                st.dataframe(sdf(sorted(logs, key=lambda x: x.get("timestamp", ""), reverse=True)[:50], ["timestamp", "action_type", "performed_by", "target_user", "details"]), use_container_width=True, hide_index=True)
        elif ms == "User Management":
            st.markdown("### User Management")
            td, ts = st.tabs(["Departments", "Seat Users"])
            with td:
                deps = dbs("registered_sections", "*")
                if deps:
                    st.dataframe(sdf(deps, ["username", "section_name", "department_name", "head_name", "bps_level", "status", "email_address"]), use_container_width=True, hide_index=True)
                    sd = st.selectbox("Select Dept", [d.get("username") for d in deps])
                    ac = st.radio("Action", ["Activate", "Deactivate"], horizontal=True)
                    if st.button("Apply", type="primary"):
                        ns = "Active" if ac == "Activate" else "Inactive"
                        if dbu("registered_sections", {"status": ns}, {"username": sd}):
                            log_audit("department_status_change", st.session_state.user_token, sd, f"Changed to {ns}")
                            st.success(f"{sd} -> {ns}")
                            st.rerun()
            with ts:
                seats = dbs("seat_allocations", "*")
                if seats:
                    for s in seats:
                        u = s.get("username")
                        icon = "ðŸŸ¢" if s.get("status") == "Active" else "ðŸ”´"
                        c1, c2, c3 = st.columns([4, 1, 2])
                        c1.markdown(f"{icon} **{u}** - {s.get('name')}")
                        c2.markdown(f"**{s.get('status')}**")
                        ns = "Inactive" if s.get("status") == "Active" else "Active"
                        bl = "Deactivate" if s.get("status") == "Active" else "Activate"
                        if c3.button(bl, key=f"it_seat_{u}"):
                            if tog_seat(u, ns, st.session_state.user_token):
                                st.success(f"{u} -> {ns}")
                                st.rerun()
                else: st.info("No seat users.")
        elif ms == "Audit Logs":
            logs = dbs("audit_logs", "*")
            if logs:
                st.dataframe(sdf(logs, ["timestamp", "action_type", "performed_by", "target_user", "details"]).sort_values("timestamp", ascending=False).head(100), use_container_width=True, hide_index=True)
            else: st.info("Empty.")
        elif ms == "Settings":
            cs = get_settings()
            with st.form("settings_form"):
                c1, c2, c3 = st.columns(3)
                with c1: nt_i = st.number_input("Timeout (min)", 5, 480, int(cs.get("session_timeout_minutes", 120)))
                with c2: na = st.number_input("Max Attempts", 3, 10, int(cs.get("max_login_attempts", 5)))
                with c3: nl_i = st.number_input("Lockout (min)", 5, 60, int(cs.get("lockout_duration_minutes", 15)))
                if st.form_submit_button("Save", type="primary"):
                    if save_settings(nt_i, na, nl_i, st.session_state.user_token):
                        st.success("Saved.")
                        st.rerun()
                    else: st.error("Failed.")
    else:
        sf = [f for f in all_files if f.get("current_desk") == st.session_state.user_token or f.get("originating_section") == st.session_state.section_name]
        pl = [r for r in sf if r.get("status") in PENDING_STATUSES]
        rj = [r for r in sf if r.get("status") == "Rejected"]
        vip = [r for r in sf if r.get("priority") == "VIP / Political Pressure"]
        ov, ds = get_overdue(sf)
        
        if ms == "Executive Dashboard":
            sync_dash_filter()
            st.markdown(f'<div class="main-header">{APP_TITLE}</div>', unsafe_allow_html=True)
            st.markdown(f'<div class="sub-header">Active Section: {str(st.session_state.section_name).upper()}</div>', unsafe_allow_html=True)
            cols = st.columns(5)
            cards = [
                ("All", len(sf), "TOTAL FILES", "total"),
                ("Pending", len(pl), "PENDING", "pending"),
                ("VIP", len(vip), "VIP", "vip"),
                ("Overdue", len(ov), "OVERDUE", "overdue"),
                ("Rejected", len(rj), "REJECTED", "rejected"),
            ]
            for col, (flt, count, label, css_cls) in zip(cols, cards):
                with col:
                    is_active = st.session_state.get("dash_filter", "All") == flt
                    btn_type = "primary" if is_active else "secondary"
                    if st.button(f"**{count}**\n\n{label}", key=f"dash_card_{flt}", use_container_width=True, type=btn_type):
                        st.session_state.dash_filter = flt
                        st.query_params["dash_filter"] = flt
                        st.rerun()
            st.markdown("<br>", unsafe_allow_html=True)
            if st.session_state.dash_filter != "All":
                st.markdown(f"### Filtered Files: **{st.session_state.dash_filter}**")
                c_reset, _ = st.columns([1, 4])
                with c_reset:
                    if st.button("ðŸ”„ Reset View", key="reset_dash_filter", help="Clear filter"):
                        st.session_state.dash_filter = "All"
                        st.query_params.clear()
                        st.rerun()
                if st.session_state.dash_filter == "Pending": target_files = pl
                elif st.session_state.dash_filter == "VIP": target_files = vip
                elif st.session_state.dash_filter == "Overdue": target_files = ov
                elif st.session_state.dash_filter == "Rejected": target_files = rj
                else: target_files = sf
                if target_files:
                    st.dataframe(sdf(target_files, ["file_number", "registry_number", "subject", "current_desk", "status", "priority", "due_date", "last_updated"]), use_container_width=True, hide_index=True)
                else:
                    st.info(f"No files found in {st.session_state.dash_filter} category.")
            else:
                st.info("Upar diye gaye boxes par direct click karke specific files filter karein.")
        
        elif ms == "File Intake & Dispatch":
            st.markdown("### Live Letter Composer & Dispatch")
            if "intake_msg" in st.session_state:
                st.success(st.session_state.intake_msg)
                del st.session_state.intake_msg
            section_lh = get_lh(st.session_state.section_name)
            if st.session_state.user_role in ["department", "it_admin"]:
                with st.expander("Section Letterhead / Departmental Heading", expanded=False):
                    cur = section_lh or {}
                    with st.form("section_lh_form"):
                        l1 = st.text_input("Heading Line 1", value=cur.get("line1", "Government of Khyber Pakhtunkhwa"))
                        l2 = st.text_input("Heading Line 2 (Department)", value=cur.get("line2", st.session_state.section_name))
                        l3 = st.text_input("Heading Line 3", value=cur.get("line3", "Civil Secretariat Peshawar"))
                        hn = st.text_input("Head Name", value=cur.get("head_name", ""))
                        em = st.text_input("Email", value=cur.get("email", ""))
                        ph = st.text_input("Phone", value=cur.get("phone", ""))
                        lg = st.file_uploader("Official Logo", type=["png", "jpg", "jpeg"], key="lh_logo")
                        if st.form_submit_button("Save Letterhead", type="primary"):
                            lp = cur.get("logo_image_path", "")
                            if lg:
                                p, e = upload_file(f"templates/logo/{sanitize_base(st.session_state.section_name)}", lg)
                                lp = p if p else lp
                            if save_lh(st.session_state.section_name, {"line1": l1, "line2": l2, "line3": l3, "head_name": hn, "email": em, "phone": ph, "logo_image_path": lp}, st.session_state.user_token):
                                st.session_state.intake_msg = "Letterhead saved."
                                st.rerun()
            else:
                with st.expander("Section Letterhead / Departmental Heading", expanded=False):
                    if section_lh:
                        st.markdown(f"**{section_lh.get('line1', '')}**")
                        st.markdown(f"{section_lh.get('line2', '')}")
                        st.markdown(f"{section_lh.get('line3', '')}")
                        cont = " | ".join([x for x in [section_lh.get('head_name'), section_lh.get('email'), section_lh.get('phone')] if x])
                        if cont: st.caption(cont)
                        lb = dl_file(section_lh.get("logo_image_path"))
                        if lb: st.image(lb, width=90)
                    else: st.info("Section head ne letterhead set nahi ki.")
            
            st.markdown("---")
            st.markdown("#### ðŸ“ Live Printable Letter")
            dr_rec = load_draft(st.session_state.user_token)
            dr = {}
            if dr_rec and not st.session_state.get("draft_ignore"):
                try: dr = json.loads(dr_rec.get("draft_json") or "{}")
                except: dr = {}
            
            def dd(k, d):
                try: return datetime.strptime(dr.get(k, ""), "%Y-%m-%d").date()
                except: return d
            
            with st.expander("ðŸ—‚ï¸ Drafts", expanded=False):
                if dr_rec: st.caption(f"Last saved: {str(dr_rec.get('updated_at', ''))[:19]}")
                else: st.caption("Auto-save active.")
                if st.button("Clear Draft", key="clear_draft"):
                    save_draft(st.session_state.user_token, {})
                    st.session_state.draft_ignore = True
                    st.session_state.draft_last_payload = None
                    for k in ["cmp_file_no", "cmp_reg_no", "cmp_subject", "cmp_priority", "cmp_due", "cmp_issue_date", "cmp_page_size", "cmp_recipient", "cmp_reference", "cmp_body", "cmp_copy", "cmp_issuer_name", "cmp_issuer_desig", "cmp_dest_type", "cmp_desk", "cmp_dept"]:
                        st.session_state.pop(k, None)
                    st.rerun()
            
            ca, cb = st.columns(2)
            with ca:
                ic = st.text_input("File Number *", value=dr.get("in_code", ""), key="cmp_file_no")
                ir = st.text_input("Registry Number *", value=dr.get("in_reg_num", ""), key="cmp_reg_no")
                idv = st.date_input("Issue Date", value=dd("issue_date", date.today()), key="cmp_issue_date")
                isu = st.text_input("Subject *", value=dr.get("in_sub", ""), key="cmp_subject")
                pri = st.selectbox("Priority", ["Normal", "VIP / Political Pressure"], index=0 if dr.get("priority", "Normal") == "Normal" else 1, key="cmp_priority")
                dud = st.date_input("Due Date", min_value=date.today(), value=dd("due_date", date.today() + timedelta(days=14)), key="cmp_due")
            with cb:
                ops = st.selectbox("Print Size", ["A4", "Letter"], index=0 if dr.get("page_size", "A4") == "A4" else 1, key="cmp_page_size")
                rcp = st.text_area("To / Recipient", value=dr.get("recipient", ""), height=100, key="cmp_recipient")
                ref = st.text_area("Reference", value=dr.get("reference", ""), height=80, key="cmp_reference")
            
            bdy = st.text_area("Main Body", value=dr.get("body", ""), height=200, key="cmp_body")
            cpf = st.text_area("Copy Forward", value=dr.get("copy", ""), height=80, key="cmp_copy")
            o1, o2, o3 = st.columns(3)
            with o1: isn = st.text_input("Issuer Name", value=dr.get("issuer_name", "Assistant Chief-II"), key="cmp_issuer_name")
            with o2: isd = st.text_input("Designation", value=dr.get("issuer_desig", "Infrastructure Section"), key="cmp_issuer_desig")
            with o3: sig = st.file_uploader("Signature", type=["png", "jpg", "jpeg"], key="cmp_signature")
            sdu = f2url(sig) if sig else None
            
            st.markdown("##### ðŸ“Ž Enclosures")
            efs = st.file_uploader("Attachments", type=["pdf", "png", "jpg", "jpeg", "doc", "docx", "xls", "xlsx"], accept_multiple_files=True, key="cmp_enc")
            inc_enc = [ef for ef in (efs or []) if st.checkbox(f"Include: {ef.name}", value=True, key=f"enc_{ef.name}_{ef.size}")]
            
            st.markdown("##### ðŸšš Destination")
            rt = st.radio("Destination", ["Current Section Desk", "Another Department"], horizontal=True, index=0 if dr.get("dest_type", "Current Section Desk") == "Current Section Desk" else 1, key="cmp_dest_type")
            sdd = None
            fst = "Pending"
            ss = dbs("seat_allocations", "*", {"section_name": st.session_state.section_name, "status": "Active"})
            so = {f"{s.get('name')} ({s.get('username')})": s.get("username") for s in ss} if ss else {}
            ads = dbs("registered_sections", "*", {"status": "Active"})
            do = {f"{d.get('section_name')} ({d.get('department_name')})": d.get("username") for d in ads if d.get("section_name") != st.session_state.section_name}
            
            if rt == "Current Section Desk":
                if so:
                    cs = st.selectbox("Desk Staff", list(so.keys()), key="cmp_desk")
                    sdd = so[cs]
                else:
                    sdd = st.session_state.user_token
                    st.info("No active seat.")
            else:
                fst = "Dispatched"
                if do:
                    cd = st.selectbox("Department", list(do.keys()), key="cmp_dept")
                    sdd = do[cd]
                else: st.warning("No departments.")
            
            dp = {"in_code": ic, "in_reg_num": ir, "in_sub": isu, "issue_date": idv.isoformat(), "due_date": dud.isoformat(), "priority": pri, "page_size": ops, "recipient": rcp, "reference": ref, "body": bdy, "copy": cpf, "issuer_name": isn, "issuer_desig": isd, "dest_type": rt}
            nts = time.time()
            ls = st.session_state.get("draft_last_save", 0)
            if dp != st.session_state.get("draft_last_payload") and (nts - ls) > 4:
                if any(str(v).strip() for k, v in dp.items() if k not in ("issue_date", "due_date", "priority", "page_size", "dest_type")):
                    if save_draft(st.session_state.user_token, dp):
                        st.session_state.draft_last_save = nts
                        st.session_state.draft_last_payload = dp
                        st.session_state.draft_ignore = False
            
            pfm = bmap(ir or "PREVIEW-REG", idv, rcp, isu or "Preview", ref, bdy, cpf, isn, isd, st.session_state.section_name, st.session_state.section_name, ic or "PREVIEW")
            ph, _ = build_letter(pfm, ops, sdu, [{"name": ef.name, "url": ""} for ef in inc_enc], lh=section_lh)
            components.html(ph, height=800, scrolling=True)
            dl_btn("Download Preview", ph, "preview.html", "prev_dl")
            
            if st.button("ðŸ“¨ SEND - Dispatch", type="primary", key="send_btn"):
                icn = nt(ic)
                irn = nt(ir)
                isn_ = nt(isu)
                if not icn or not irn or not isn_:
                    st.error("File No, Registry No, Subject required.")
                elif dbs("file_tracking", "*", {"registry_number": irn}):
                    st.error("Yeh registry number pehle se mojood hai.")
                elif not sdd:
                    st.error("Destination select karein.")
                else:
                    ar = []
                    en = []
                    for ef in inc_enc:
                        p, e = upload_file(f"attachments/{icn}", ef)
                        if p:
                            ar.append({"name": ef.name, "path": p, "url": get_file_access_url(p)})
                            en.append({"name": ef.name, "url": get_file_access_url(p)})
                    ffm = bmap(irn, idv, rcp, isn_, ref, bdy, cpf, isn, isd, st.session_state.section_name, st.session_state.section_name, icn)
                    lh_html, fps = build_letter(ffm, ops, sdu, en, lh=section_lh)
                    rt_ = f"Size: {fps}"
                    if ar: rt_ += "\n[ATTACHMENTS_JSON]:" + json.dumps(ar)
                    nfd = {"file_number": icn, "registry_number": irn, "subject": isn_, "originating_section": st.session_state.section_name, "current_desk": sdd, "status": fst, "remarks": rt_, "priority": pri, "due_date": dud.isoformat(), "last_updated": datetime.now().isoformat(), "letter_body": lh_html}
                    res = dbi("file_tracking", nfd)
                    if res:
                        dbi("file_thread", {"file_number": icn, "from_desk": st.session_state.user_token, "to_desk": sdd, "action_type": "dispatch", "remarks": f"Dispatched with {len(ar)} enclosures", "timestamp": datetime.now().isoformat()})
                        send_notif(sdd, f"New File - {icn}", f"Subject: {isn_} | Enc: {len(ar)}", "file_received")
                        log_audit("file_created", st.session_state.user_token, details=f"{icn}/{irn}")
                        get_all_files.clear()
                        save_draft(st.session_state.user_token, {})
                        st.session_state.draft_last_payload = None
                        st.session_state.draft_ignore = True
                        for k in ["cmp_file_no", "cmp_reg_no", "cmp_subject", "cmp_priority", "cmp_due", "cmp_issue_date", "cmp_page_size", "cmp_recipient", "cmp_reference", "cmp_body", "cmp_copy", "cmp_issuer_name", "cmp_issuer_desig", "cmp_dest_type", "cmp_desk", "cmp_dept"]:
                            st.session_state.pop(k, None)
                        st.session_state.intake_msg = f"File {icn} dispatched."
                        st.rerun()
                    else: st.error("Save failed.")
        
        elif ms == "Receiving File & Actions":
            st.markdown("### Receiving File & Actions")
            if sf:
                fo = {f"{r.get('file_number')} - {str(r.get('subject', 'N/A'))[:60]}": r for r in sf}
                sl = st.selectbox("Select File", list(fo.keys()))
                sfile = fo[sl]
                fn = sfile.get("file_number")
                c1, c2, c3 = st.columns(3)
                c1.markdown(f"**File:** {fn}")
                c1.markdown(f"**Reg:** {sfile.get('registry_number', '')}")
                c2.markdown(f"**Status:** {sfile.get('status')}")
                c2.markdown(f"**Priority:** {sfile.get('priority')}")
                c3.markdown(f"**Desk:** {sfile.get('current_desk')}")
                c3.markdown(f"**Origin:** {sfile.get('originating_section')}")
                if sfile.get("rejection_reason"):
                    st.error(f"Rejected: {sfile.get('rejection_reason')}")
                
                st.markdown("---")
                st.markdown("#### Letter Preview")
                lb = sfile.get("letter_body") or ""
                if lb:
                    components.html(lb, height=800, scrolling=True)
                    dl_btn("Download HTML", lb, f"{fn}.html", f"dl_{fn}")
                else: st.info("No letter body.")
                
                st.markdown("---")
                st.markdown("#### ðŸ“Ž Attachments")
                atts = get_atts(sfile)
                with st.expander("Add / Remove / Search Attachments", expanded=False):
                    asrch = st.text_input("Search", key=f"att_srch_{fn}")
                    fa = [a for a in atts if asrch.lower() in str(a.get("name", "")).lower()] if asrch else atts
                    if fa:
                        ro = [(f"{a.get('name', 'att')} ({str(a.get('path', ''))[-8:]})", a.get("path")) for a in fa if a.get("path")]
                        if ro:
                            rl = st.selectbox("Remove", [x[0] for x in ro], key=f"rm_sel_{fn}")
                            if st.button("Remove Selected", key=f"rm_btn_{fn}"):
                                sp = dict(ro).get(rl)
                                nl_i = [a for a in atts if a.get("path") != sp]
                                if set_atts(fn, nl_i):
                                    get_all_files.clear()
                                    st.success("Removed.")
                                    st.rerun()
                    else: st.caption("No match.")
                    naf = st.file_uploader("Add New", type=["pdf", "png", "jpg", "jpeg", "doc", "docx", "xls", "xlsx"], accept_multiple_files=True, key=f"add_att_{fn}")
                    if st.button("Upload & Add", key=f"add_btn_{fn}"):
                        nr = upl_atts(fn, naf)
                        if nr:
                            ep = {a.get("path") for a in atts}
                            merged = atts + [r for r in nr if r.get("path") not in ep]
                            if set_atts(fn, merged):
                                get_all_files.clear()
                                st.success("Added.")
                                st.rerun()
                        else: st.error("Upload failed.")
                
                if atts:
                    for a in atts:
                        an = a.get("name", "att")
                        ap = a.get("path", "")
                        au = a.get("url", "")
                        p1, p2, p3 = st.columns([4, 2, 2])
                        p1.markdown(f"ðŸ“„ **{an}**")
                        if au:
                            p2.markdown(f"[Download]({au})")
                        else:
                            fb = dl_file(ap)
                            if fb: p2.download_button("Download", fb, file_name=an, key=f"dl_a_{ap}")
                            else: p2.caption("Unavailable")
                        if p3.button("Remove", key=f"rm_att_{ap}"):
                            new_list = [x for x in atts if x.get("path") != ap]
                            if set_atts(fn, new_list):
                                get_all_files.clear()
                                st.success("Removed.")
                                st.rerun()
                else: st.info("No attachments.")
                
                st.markdown("---")
                st.markdown("#### Actions")
                a1, a2, a3, a4 = st.columns(4)
                with a1:
                    if can_act(st.session_state.user_role, "complete", sfile, dict(st.session_state)):
                        if st.button("Mark Complete", key=f"comp_{fn}"):
                            if dbu("file_tracking", {"status": "Successful", "last_updated": datetime.now().isoformat()}, {"file_number": fn}):
                                log_audit("file_completed", st.session_state.user_token, details=fn)
                                get_all_files.clear()
                                st.success("Completed.")
                                st.rerun()
                with a2:
                    if can_act(st.session_state.user_role, "reject", sfile):
                        with st.popover("Reject"):
                            rr = st.text_area("Reason", key=f"rej_{fn}")
                            if st.button("Confirm Reject", key=f"rej_btn_{fn}"):
                                if rr:
                                    ok, msg = rej_file(fn, st.session_state.user_token, rr)
                                    if ok:
                                        log_audit("file_rejected", st.session_state.user_token, details=fn)
                                        get_all_files.clear()
                                        st.success("Rejected.")
                                        st.rerun()
                                    else: st.error(msg)
                                else: st.error("Reason required.")
                with a3:
                    if can_act(st.session_state.user_role, "forward", sfile, dict(st.session_state)):
                        with st.popover("Forward"):
                            drows = dbs("registered_sections", "*", {"status": "Active"})
                            dopts = {f"{d.get('section_name')} ({d.get('department_name')})": d.get("username") for d in drows if d.get("username") != st.session_state.user_token}
                            if dopts:
                                fd = st.selectbox("Forward to", list(dopts.keys()), key=f"fwd_{fn}")
                                fr = st.text_area("Remarks", key=f"fwd_r_{fn}")
                                st.markdown("**Attachments**")
                                ca = get_atts(sfile)
                                fs = st.text_input("Search attachments", key=f"fwd_as_{fn}")
                                fa = [a for a in ca if fs.lower() in str(a.get("name", "")).lower()] if fs else ca
                                sp = []
                                for a in fa:
                                    if st.checkbox(a.get("name", "att"), value=True, key=f"fwd_cb_{fn}_{a.get('path')}"):
                                        sp.append(a.get("path"))
                                fnf = st.file_uploader("Add new", type=["pdf", "png", "jpg", "jpeg", "doc", "docx", "xls", "xlsx"], accept_multiple_files=True, key=f"fwd_nf_{fn}")
                                if st.button("Confirm Forward", type="primary", key=f"fwd_btn_{fn}"):
                                    ur = upl_atts(fn, fnf)
                                    se = [a for a in ca if a.get("path") in sp]
                                    esp = {a.get("path") for a in se}
                                    final = se + [r for r in ur if r.get("path") not in esp]
                                    set_atts(fn, final)
                                    disp(fn, st.session_state.user_token, dopts[fd], "forward", fr)
                                    log_audit("file_forwarded", st.session_state.user_token, details=fn)
                                    get_all_files.clear()
                                    st.success("Forwarded.")
                                    st.rerun()
                            else: st.warning("No departments.")
                with a4:
                    if can_act(st.session_state.user_role, "return", sfile, dict(st.session_state)):
                        with st.popover("Return"):
                            rr = st.text_area("Remarks", key=f"ret_r_{fn}")
                            ca = get_atts(sfile)
                            rs = st.text_input("Search attachments", key=f"ret_as_{fn}")
                            fa = [a for a in ca if rs.lower() in str(a.get("name", "")).lower()] if rs else ca
                            sp = []
                            for a in fa:
                                if st.checkbox(a.get("name", "att"), value=True, key=f"ret_cb_{fn}_{a.get('path')}"):
                                    sp.append(a.get("path"))
                            rnf = st.file_uploader("Add new", type=["pdf", "png", "jpg", "jpeg", "doc", "docx", "xls", "xlsx"], accept_multiple_files=True, key=f"ret_nf_{fn}")
                            if st.button("Confirm Return", type="primary", key=f"ret_btn_{fn}"):
                                ft = get_thread(fn)
                                if not ft:
                                    st.error("No history.")
                                else:
                                    lf = ft[0].get("from_desk")
                                    if not lf:
                                        st.error("Sender not found.")
                                    else:
                                        ur = upl_atts(fn, rnf)
                                        se = [a for a in ca if a.get("path") in sp]
                                        esp = {a.get("path") for a in se}
                                        final = se + [r for r in ur if r.get("path") not in esp]
                                        set_atts(fn, final)
                                        disp(fn, st.session_state.user_token, lf, "return", rr)
                                        log_audit("file_returned", st.session_state.user_token, details=fn)
                                        get_all_files.clear()
                                        st.success("Returned.")
                                        st.rerun()
                
                st.markdown("---")
                st.markdown("#### PC-1 / PC-2")
                apc = get_apc(fn)
                if apc:
                    for pc in apc:
                        p1, p2, p3 = st.columns([3, 4, 2])
                        p1.markdown(f"**{pc.get('adp_number')}** ({pc.get('pc_type')})")
                        p2.markdown(pc.get("scheme_title") or "")
                        fb = dl_file(pc.get("storage_path"))
                        if fb:
                            p3.download_button("Download", fb, file_name=pc.get("file_name") or f"{pc.get('adp_number')}.file", key=f"dl_pc_{fn}_{pc.get('adp_number')}")
                        else: p3.caption("Unavailable")
                else: st.info("No PC attached.")
                
                with st.expander("Attach / Upload PC"):
                    te, tn = st.tabs(["Existing", "New"])
                    with te:
                        ps = st.text_input("Search ADP", key=f"pc_s_{fn}")
                        if st.button("Search", key=f"pc_sb_{fn}"):
                            if ps:
                                pr = dbsrch("pc1_master", ["adp_number", "scheme_title"], ps, lim=20)
                                if pr:
                                    for pc in pr:
                                        st.markdown(f"**{pc.get('adp_number')}** | {pc.get('pc_type')} | {pc.get('scheme_title')}")
                                        if st.button("Attach", key=f"att_pc_{fn}_{pc.get('adp_number')}"):
                                            if link_pc(fn, pc.get("adp_number"), st.session_state.user_token):
                                                st.success("Attached.")
                                                st.rerun()
                                            else: st.warning("Already attached.")
                                else: st.warning("No results.")
                    with tn:
                        na = st.text_input("ADP Number", key=f"na_{fn}")
                        pt = st.selectbox("Type", ["PC-1", "PC-2"], key=f"pt_{fn}")
                        st_ = st.text_input("Title", key=f"st_{fn}")
                        pf = st.file_uploader("Document", key=f"pf_{fn}")
                        if st.button("Save & Attach", key=f"pc_ub_{fn}"):
                            ep = get_pc1(na)
                            if ep:
                                if link_pc(fn, ep.get("adp_number"), st.session_state.user_token):
                                    st.success("Attached existing.")
                                    st.rerun()
                                else: st.info("Already attached.")
                            else:
                                ok, msg, pr = upl_pc(na, pt, st_, pf, st.session_state.user_token)
                                if ok:
                                    if link_pc(fn, pr.get("adp_number"), st.session_state.user_token):
                                        st.success("Uploaded & attached.")
                                        st.rerun()
                                    else: st.error("Upload OK but attach failed.")
                                else: st.error(msg)
                
                st.markdown("---")
                st.markdown("#### Secret / Targeted Remarks")
                comments = get_cmts(fn, st.session_state.section_name)
                if comments:
                    for c in comments[:20]:
                        tgt = c.get("_tgt")
                        badge = "ðŸŒ Public" if not c.get("is_internal") else ("ðŸŽ¯ Targeted" if tgt else "ðŸ”’ Private")
                        st.markdown(f"**{c.get('comment_by')}** | {badge} | {str(c.get('timestamp', ''))[:16]}")
                        if tgt: st.caption(f"Target: {tgt}")
                        st.markdown(f"> {c.get('comment_text')}")
                        st.markdown("---")
                else: st.info("No remarks.")
                
                tr_rows = dbs("registered_sections", "*", {"status": "Active"})
                tm = {f"{r.get('section_name')} ({r.get('department_name')})": r.get("section_name") for r in tr_rows if r.get("section_name") != st.session_state.section_name}
                with st.form("add_cmt_form", clear_on_submit=True):
                    rv = st.selectbox("Visibility", ["Private - sirf meri section", "Targeted Secret - selected section ko show", "Public - sab ko show"])
                    ts = None
                    if rv.startswith("Targeted"):
                        if tm:
                            tl = st.selectbox("Target Section", list(tm.keys()))
                            ts = tm[tl]
                        else: st.warning("No target available.")
                    nc = st.text_area("Remark", key=f"cmt_{fn}")
                    if st.form_submit_button("Submit"):
                        if not nc:
                            st.error("Text required.")
                        elif rv.startswith("Targeted") and not ts:
                            st.error("Target select karein.")
                        else:
                            rs = "private"
                            if rv.startswith("Targeted"): rs = "targeted"
                            elif rv.startswith("Public"): rs = "public"
                            add_cmt(fn, st.session_state.user_token, nc, st.session_state.section_name, True, rs, ts)
                            st.success("Added.")
                            st.rerun()
                
                st.markdown("---")
                st.markdown("#### Movement History")
                thr = get_thread(fn)
                if thr:
                    st.dataframe(sdf(thr, ["timestamp", "from_desk", "to_desk", "action_type", "remarks"]), use_container_width=True, hide_index=True)
                else: st.info("No history.")
            else: st.info("No files available.")
        
        elif ms == "Seat Allotment & Profiles":
            if st.session_state.user_bps >= 17:
                st.markdown("### Seat Credentials Management")
                my = dbs("seat_allocations", "*", {"section_name": st.session_state.section_name})
                if my:
                    for s in my:
                        u = s.get("username")
                        icon = "ðŸŸ¢" if s.get("status") == "Active" else "ðŸ”´"
                        c1, c2, c3 = st.columns([4, 1, 2])
                        c1.markdown(f"{icon} **{u}** - {s.get('name')} (BPS {s.get('bps_level')})")
                        c2.markdown(f"**{s.get('status')}**")
                        ns = "Inactive" if s.get("status") == "Active" else "Active"
                        bl = "Deactivate" if s.get("status") == "Active" else "Activate"
                        if c3.button(bl, key=f"ds_{u}"):
                            if tog_seat(u, ns, st.session_state.user_token):
                                st.success(f"{u} -> {ns}")
                                st.rerun()
                else: st.info("No seats.")
                
                st.markdown("---")
                st.markdown("#### Create New Seat")
                if "seat_msg" in st.session_state:
                    st.success(st.session_state.seat_msg)
                    del st.session_state.seat_msg
                    st.session_state.seat_tp = gen_pw()
                if "seat_tp" not in st.session_state:
                    st.session_state.seat_tp = gen_pw()
                with st.form("seat_form"):
                    sn = st.text_input("Full Name")
                    sc = st.text_input("Login Shortcode")
                    # âœ… FIX #1: SEAT_BPS_SCALE ab 3-22 hai
                    sb = st.selectbox("Staff BPS", options=SEAT_BPS_SCALE, index=0)
                    se = st.text_input("Email")
                    sp = st.text_input("Phone")
                    spw = st.text_input("Password", value=st.session_state.seat_tp, type="password")
                    if st.form_submit_button("Generate Seat", type="primary"):
                        sn, sc, spw, se, sp = nt(sn), nl(sc), nt(spw), nl(se), nt(sp)
                        if not sn or not sc or not spw:
                            st.error("Fields required.")
                        elif uname_exists(sc):
                            st.error("Username exists.")
                        else:
                            res = dbi("seat_allocations", {"username": sc, "password_hash": hash_pw(spw), "name": sn, "section_name": st.session_state.section_name, "bps_level": sb, "email_address": se, "telephone": sp, "status": "Active"})
                            if res:
                                st.session_state.seat_msg = f"Seat created: {sc}"
                                log_audit("seat_created", st.session_state.user_token, sc)
                                st.rerun()
                            else: st.error("Failed.")
            else: st.info("Seat allotment sirf BPS 17-22 officers ke liye available hai.")

else:
    st.session_state.current_view = "Login"
