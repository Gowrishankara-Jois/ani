# campus_streamlit_firebase.py
"""
Campus Micro-Disruption Alert System - Streamlit + Firebase edition

Features:
- Firestore (users, reports, notifications)
- Firebase Storage for attachments (if credentials present)
- Role-based UI: student / staff / admin
- Report creation, listing, assign, status updates
- Charts (category breakdown), CSV export
- Local fallback for uploads and in-memory data if Firebase credentials absent
- Uses pbkdf2:sha256 hashing for passwords
- Streamlit sidebar navigation and responsive layout
"""

import os
import io
import time
import math
import json
import uuid
import base64
import logging
import tempfile
from datetime import datetime, timedelta

import streamlit as st
import pandas as pd

# Firebase libraries (optional)
try:
    import firebase_admin
    from firebase_admin import credentials, firestore, storage as fb_storage, exceptions as fb_exceptions
    FIREBASE_AVAILABLE = True
except Exception:
    FIREBASE_AVAILABLE = False

from hashlib import pbkdf2_hmac
from typing import Optional, Tuple, Dict, Any, List

# ---------- Configuration & Logging ----------
APP_TITLE = "Campus Micro-Disruption Alerts (Streamlit + Firebase)"
UPLOAD_DIR = os.path.join(os.getcwd(), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
LOGFILE = os.path.join(os.getcwd(), "campus_streamlit.log")
logging.basicConfig(filename=LOGFILE, level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("campus_streamlit")

# Load .env style settings
from dotenv import load_dotenv
load_dotenv()

FIREBASE_CREDS_PATH = os.getenv("FIREBASE_CREDENTIALS")  # path to service account JSON
FIREBASE_STORAGE_BUCKET = os.getenv("FIREBASE_STORAGE_BUCKET")  # e.g., your-project-id.appspot.com

# Secret for session state fallback (Streamlit manages sessions; we add a key)
SESSION_KEY = os.getenv("STREAMLIT_SESSION_STATE_KEY", "campus_streamlit_default_key")
st.set_page_config(page_title=APP_TITLE, layout="wide")

# ---------- Helpers: Password hashing ----------
def hash_password(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    Returns (salt, hashed) where salt is bytes and hashed is bytes.
    Uses pbkdf2_hmac with sha256, 200k iterations.
    """
    if salt is None:
        salt = os.urandom(16)
    hashed = pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return salt, hashed

def verify_password(password: str, salt: bytes, hashed: bytes) -> bool:
    try:
        new_h = pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
        return new_h == hashed
    except Exception:
        return False

# ---------- Firebase initialization (if available) ----------
USE_FIREBASE = False
db = None
storage_bucket = None

if FIREBASE_AVAILABLE:
    # Two ways to provide credentials: env var 'GOOGLE_APPLICATION_CREDENTIALS' OR FIREBASE_CREDS_PATH
    try:
        cred_path = None
        if FIREBASE_CREDS_PATH and os.path.isfile(FIREBASE_CREDS_PATH):
            cred_path = FIREBASE_CREDS_PATH
            cred = credentials.Certificate(cred_path)
            firebase_admin.initialize_app(cred, {"storageBucket": FIREBASE_STORAGE_BUCKET} if FIREBASE_STORAGE_BUCKET else None)
            logger.info("Firebase initialized using FIREBASE_CREDENTIALS path.")
        elif os.getenv("GOOGLE_APPLICATION_CREDENTIALS"):
            # If GOOGLE_APPLICATION_CREDENTIALS is set, firebase_admin will pick it up
            firebase_admin.initialize_app()
            logger.info("Firebase initialized using GOOGLE_APPLICATION_CREDENTIALS.")
        else:
            # Can't initialize without credentials
            logger.warning("Firebase available but no credentials provided. Falling back to local storage.")
            FIREBASE_AVAILABLE = False
    except Exception as e:
        logger.exception("Failed to initialize Firebase: %s", e)
        FIREBASE_AVAILABLE = False

if FIREBASE_AVAILABLE:
    try:
        db = firestore.client()
        if FIREBASE_STORAGE_BUCKET:
            storage_bucket = fb_storage.bucket(FIREBASE_STORAGE_BUCKET)
        else:
            storage_bucket = fb_storage.bucket()
        USE_FIREBASE = True
        logger.info("Firestore and Storage clients created.")
    except Exception as e:
        logger.exception("Firebase components not available; falling back to local: %s", e)
        USE_FIREBASE = False

# If firebase not available, we'll use a simple local sqlite-like (in-memory) structure (dicts)
if not USE_FIREBASE:
    logger.info("Running in local fallback mode (no Firebase).")
    # Local "collections"
    LOCAL_USERS = {}         # username -> dict
    LOCAL_REPORTS = {}       # report_id -> dict
    LOCAL_NOTIFS = []       # list of dict notifications
    # create demo users
    if "admin" not in LOCAL_USERS:
        salt, h = hash_password("adminpass")
        LOCAL_USERS["admin"] = {"username":"admin","fullname":"Administrator","email":"admin@example.com","role":"admin","salt":salt.hex(),"hash":h.hex(),"created_at":datetime.utcnow().isoformat()}
        salt, h = hash_password("staffpass")
        LOCAL_USERS["staff"] = {"username":"staff","fullname":"Staff Member","email":"staff@example.com","role":"staff","salt":salt.hex(),"hash":h.hex(),"created_at":datetime.utcnow().isoformat()}
        salt, h = hash_password("studentpass")
        LOCAL_USERS["student"] = {"username":"student","fullname":"Demo Student","email":"student@example.com","role":"student","salt":salt.hex(),"hash":h.hex(),"created_at":datetime.utcnow().isoformat()}
        logger.info("Seeded local demo users.")

# ---------- Utility wrappers for DB operations (Firestore or local) ----------
def create_user(username: str, password: str, role: str = "student", fullname: str = "", email: str = "") -> bool:
    username = username.strip().lower()
    if USE_FIREBASE:
        coll = db.collection("users")
        doc = coll.document(username).get()
        if doc.exists:
            return False
        salt, h = hash_password(password)
        payload = {
            "username": username, "fullname": fullname, "email": email, "role": role,
            "salt": salt.hex(), "hash": h.hex(), "created_at": datetime.utcnow().isoformat()
        }
        coll.document(username).set(payload)
        logger.info("Created Firebase user %s", username)
        return True
    else:
        if username in LOCAL_USERS:
            return False
        salt, h = hash_password(password)
        LOCAL_USERS[username] = {"username":username,"fullname":fullname,"email":email,"role":role,"salt":salt.hex(),"hash":h.hex(),"created_at":datetime.utcnow().isoformat()}
        logger.info("Created local user %s", username)
        return True

def get_user(username: str) -> Optional[dict]:
    if not username:
        return None
    username = username.strip().lower()
    if USE_FIREBASE:
        doc = db.collection("users").document(username).get()
        if not doc.exists:
            return None
        return doc.to_dict()
    else:
        return LOCAL_USERS.get(username)

def verify_user_login(username: str, password: str) -> Tuple[bool, Optional[dict]]:
    user = get_user(username)
    if not user:
        return False, None
    try:
        salt = bytes.fromhex(user["salt"])
        hashed = bytes.fromhex(user["hash"])
        if verify_password(password, salt, hashed):
            return True, user
    except Exception:
        return False, None
    return False, None

def _generate_report_id() -> str:
    return str(uuid.uuid4())

def create_report(payload: dict) -> str:
    """
    payload must include at least:
    title, description, category, priority, location, reporter_username, attachment (optional)
    returns report_id
    """
    payload = dict(payload)
    payload["created_at"] = datetime.utcnow().isoformat()
    payload["updated_at"] = payload["created_at"]
    payload["status"] = payload.get("status", "Open")
    payload["report_id"] = _generate_report_id()
    if USE_FIREBASE:
        db.collection("reports").document(payload["report_id"]).set(payload)
        logger.info("Created report %s in Firestore by %s", payload["report_id"], payload.get("reporter_username"))
    else:
        LOCAL_REPORTS[payload["report_id"]] = payload
        logger.info("Created local report %s by %s", payload["report_id"], payload.get("reporter_username"))
    return payload["report_id"]

def update_report(report_id: str, updates: dict) -> bool:
    if USE_FIREBASE:
        doc_ref = db.collection("reports").document(report_id)
        doc = doc_ref.get()
        if not doc.exists:
            return False
        updates["updated_at"] = datetime.utcnow().isoformat()
        doc_ref.update(updates)
        logger.info("Updated report %s with %s", report_id, updates)
        return True
    else:
        r = LOCAL_REPORTS.get(report_id)
        if not r:
            return False
        r.update(updates)
        r["updated_at"] = datetime.utcnow().isoformat()
        logger.info("Updated local report %s", report_id)
        return True

def get_report(report_id: str) -> Optional[dict]:
    if USE_FIREBASE:
        doc = db.collection("reports").document(report_id).get()
        if not doc.exists:
            return None
        return doc.to_dict()
    else:
        return LOCAL_REPORTS.get(report_id)

def list_reports(filters: dict = None, q: str = "", page: int = 1, per_page: int = 15) -> Tuple[List[dict], int]:
    """
    Returns (reports_list, total_count)
    filters may include category, priority, status
    q is search query (checks title, description, location)
    """
    filters = filters or {}
    all_reports = []
    if USE_FIREBASE:
        coll = db.collection("reports")
        # Firestore queries are limited; for simplicity we fetch all and filter client-side (fine for small scale)
        docs = coll.stream()
        for d in docs:
            rd = d.to_dict()
            all_reports.append(rd)
    else:
        all_reports = list(LOCAL_REPORTS.values())

    # Apply filters client-side
    def match(r):
        if "category" in filters and filters["category"]:
            if r.get("category", "").lower() != filters["category"].lower():
                return False
        if "priority" in filters and filters["priority"]:
            if r.get("priority", "").lower() != filters["priority"].lower():
                return False
        if "status" in filters and filters["status"]:
            if r.get("status", "").lower() != filters["status"].lower():
                return False
        if q:
            ql = q.lower()
            if ql in r.get("title","").lower() or ql in r.get("description","").lower() or ql in r.get("location","").lower():
                return True
            return False
        return True

    filtered = [r for r in all_reports if match(r)]
    # Sort by created_at desc
    filtered.sort(key=lambda x: x.get("created_at",""), reverse=True)
    total = len(filtered)
    start = (page-1) * per_page
    end = start + per_page
    page_items = filtered[start:end]
    return page_items, total

def add_notification_record(username: str, message: str):
    payload = {"username": username, "message": message, "seen": False, "created_at": datetime.utcnow().isoformat()}
    if USE_FIREBASE:
        db.collection("notifications").add(payload)
    else:
        LOCAL_NOTIFS.append(payload)
    logger.info("Notification for %s: %s", username, message)

def list_notifications(username: str) -> List[dict]:
    if USE_FIREBASE:
        docs = db.collection("notifications").where("username", "==", username).order_by("created_at", direction=firestore.Query.DESCENDING).stream()
        return [d.to_dict() for d in docs]
    else:
        return sorted([n for n in LOCAL_NOTIFS if n["username"] == username], key=lambda x: x["created_at"], reverse=True)

def mark_notifications_read(username: str):
    if USE_FIREBASE:
        docs = db.collection("notifications").where("username", "==", username).where("seen", "==", False).stream()
        for d in docs:
            db.collection("notifications").document(d.id).update({"seen": True})
    else:
        for n in LOCAL_NOTIFS:
            if n["username"] == username:
                n["seen"] = True

# ---------- File upload helper ----------
def upload_attachment(file_obj, filename_hint: str) -> Tuple[bool, Optional[str]]:
    """
    file_obj: a file-like object
    filename_hint: original filename
    returns (success, remote_filename_or_local_path)
    """
    # secure name
    ext = os.path.splitext(filename_hint)[1] or ""
    fname = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex}{ext}"
    # If Firebase storage available, upload
    if USE_FIREBASE and storage_bucket:
        try:
            blob = storage_bucket.blob(fname)
            # file_obj may be an UploadedFile from Streamlit; ensure we read bytes
            file_obj.seek(0)
            blob.upload_from_file(file_obj, content_type=None)
            # make public-ish (optional): blob.make_public()
            logger.info("Uploaded to Firebase Storage: %s", fname)
            return True, fname
        except Exception as e:
            logger.exception("Firebase storage upload failed: %s", e)
            # fallback to local
    # Save locally fallback
    try:
        path = os.path.join(UPLOAD_DIR, fname)
        with open(path, "wb") as f:
            file_obj.seek(0)
            f.write(file_obj.read())
        logger.info("Saved attachment locally: %s", path)
        return True, fname
    except Exception as e:
        logger.exception("Local upload failed: %s", e)
        return False, None

# ---------- Priority engine ----------
def compute_priority_score(report: dict) -> float:
    """
    Simple weighted scoring:
    - priority: High=3, Medium=2, Low=1
    - keywords in description: adds weight
    - age: older reports slightly higher priority
    """
    base_map = {"low": 1.0, "medium": 2.0, "high": 3.0}
    p = report.get("priority", "Low").lower()
    score = base_map.get(p, 1.0)
    desc = report.get("description","").lower()
    keywords = ["danger", "urgent", "immediately", "fire", "leak", "broken", "no power"]
    for kw in keywords:
        if kw in desc:
            score += 0.8
    # age factor
    try:
        created = datetime.fromisoformat(report.get("created_at"))
        age_hours = (datetime.utcnow() - created).total_seconds()/3600.0
        score += min(age_hours/24.0, 2.0)  # up to +2 points for older items
    except Exception:
        pass
    return round(score, 3)

# ---------- Streamlit UI helpers ----------
def init_session_state():
    if "user" not in st.session_state:
        st.session_state["user"] = None
    if "role" not in st.session_state:
        st.session_state["role"] = None
    if "last_activity" not in st.session_state:
        st.session_state["last_activity"] = datetime.utcnow().isoformat()

init_session_state()

# ---------- UI components ----------
def header():
    st.markdown(f"# {APP_TITLE}")
    st.write("Built with Streamlit — choose Firebase for persistent storage. If Firebase credentials are missing the app runs in local fallback mode.")
    st.write("---")

def sidebar_auth_block():
    st.sidebar.title("Account")
    if st.session_state["user"]:
        st.sidebar.markdown(f"**Signed in as:** {st.session_state['user']} ({st.session_state['role']})")
        if st.sidebar.button("Logout"):
            st.session_state["user"] = None
            st.session_state["role"] = None
            st.experimental_rerun()
    else:
        st.sidebar.markdown("### Login")
        with st.sidebar.form("login_form"):
            lu = st.text_input("Username")
            lp = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Login")
            if submitted:
                ok, user = verify_user_login(lu, lp)
                if ok:
                    st.session_state["user"] = user["username"]
                    st.session_state["role"] = user["role"]
                    st.success("Logged in")
                    add_notification_record(user["username"], f"Signed in at {datetime.utcnow().isoformat()}")
                    logger.info("User logged in: %s", user["username"])
                    st.experimental_rerun()
                else:
                    st.error("Invalid credentials")

        st.sidebar.markdown("---")
        st.sidebar.markdown("Don't have an account? Create one:")
        if st.sidebar.button("Register"):
            st.session_state["_show_register"] = True

def register_flow():
    st.header("Register new account")
    with st.form("register_form"):
        username = st.text_input("username")
        fullname = st.text_input("Full name")
        email = st.text_input("Email")
        role = st.selectbox("Role", ["student","staff"])
        password = st.text_input("Password", type="password")
        password2 = st.text_input("Confirm password", type="password")
        submitted = st.form_submit_button("Create account")
        if submitted:
            if password != password2:
                st.error("Passwords do not match")
            elif len(password) < 6:
                st.error("Password too short (min 6)")
            else:
                ok = create_user(username, password, role=role, fullname=fullname, email=email)
                if ok:
                    st.success("Account created. Please log in.")
                    st.session_state["_show_register"] = False
                else:
                    st.error("Username already exists")

def show_notifications():
    st.header("Notifications")
    if not st.session_state["user"]:
        st.warning("Login to see notifications")
        return
    notes = list_notifications(st.session_state["user"])
    if not notes:
        st.info("No notifications")
    else:
        for n in notes:
            seen = n.get("seen", False)
            cols = st.columns([9,1])
            cols[0].write(f"{'[NEW] ' if not seen else ''}{n['message']}")
            cols[1].write(n.get("created_at",""))
    if st.button("Mark all read"):
        mark_notifications_read(st.session_state["user"])
        st.success("Marked read")
        st.experimental_rerun()

# ---------- App pages ----------
def page_home():
    header()
    st.subheader("Quick Actions")
    c1, c2, c3 = st.columns(3)
    if c1.button("Report an Issue"):
        st.session_state["_navigate"] = "report"
        st.experimental_rerun()
    if c2.button("View Dashboard"):
        st.session_state["_navigate"] = "dashboard"
        st.experimental_rerun()
    if c3.button("Notifications"):
        st.session_state["_navigate"] = "notifications"
        st.experimental_rerun()
    st.write("Demo mode:", "Firebase connected" if USE_FIREBASE else "Local fallback")

def page_report():
    st.header("Report an Issue")
    if not st.session_state["user"]:
        st.warning("Please login to report")
        return
    with st.form("report_form", clear_on_submit=True):
        title = st.text_input("Title")
        desc = st.text_area("Description", height=140)
        location = st.text_input("Location (optional)")
        category = st.selectbox("Category", ["Facility","AV","Network","Other"])
        priority = st.selectbox("Priority", ["Low","Medium","High"])
        file_u = st.file_uploader("Attachment (optional) — image or pdf", type=["png","jpg","jpeg","gif","pdf"])
        submitted = st.form_submit_button("Submit Report")
        if submitted:
            attach_name = None
            if file_u:
                success, fname = upload_attachment(file_u, file_u.name)
                if success:
                    attach_name = fname
                else:
                    st.error("Failed to upload attachment")
                    return
            payload = {
                "title": title,
                "description": desc,
                "location": location or "",
                "category": category,
                "priority": priority,
                "reporter_username": st.session_state["user"],
                "attachment": attach_name
            }
            rid = create_report(payload)
            add_notification_record("staff", f"New report submitted: {title}")  # generic notify staff
            st.success(f"Report submitted ({rid})")
            st.info("You can view it on dashboard")

def page_dashboard():
    st.header("Dashboard")
    role = st.session_state.get("role")
    page = st.number_input("Page", min_value=1, value=1, step=1)
    per_page = st.selectbox("Per page", [10, 15, 25, 50], index=0)
    q = st.text_input("Search (title/description/location)")
    cat = st.selectbox("Filter category", ["", "Facility","AV","Network","Other"])
    pr = st.selectbox("Filter priority", ["", "Low","Medium","High"])
    st.write(" ")

    filters = {}
    if cat:
        filters["category"] = cat
    if pr:
        filters["priority"] = pr

    items, total = list_reports(filters=filters, q=q, page=page, per_page=per_page)
    st.write(f"Found {total} reports (showing {len(items)})")
    # show chart (category breakdown)
    rows = []
    for r in items:
        rows.append({"category": r.get("category","Other")})
    if rows:
        dfc = pd.DataFrame(rows)
        st.subheader("Category breakdown (current page)")
        st.bar_chart(dfc["category"].value_counts())

    # Table
    for r in items:
        with st.expander(f"{r.get('title')} — {r.get('priority')} — {r.get('status')}"):
            st.markdown(f"**Category:** {r.get('category')}    **Location:** {r.get('location')}")
            st.markdown(f"**Description:**\n{r.get('description')}")
            if r.get("attachment"):
                if USE_FIREBASE and storage_bucket:
                    # provide download link via signed url would require extra code; show name
                    st.write(f"Attachment (stored in Firebase Storage): {r.get('attachment')}")
                else:
                    p = os.path.join(UPLOAD_DIR, r.get("attachment"))
                    if os.path.exists(p):
                        st.download_button("Download attachment", data=open(p,"rb").read(), file_name=r.get("attachment"))
            st.write("Reported at:", r.get("created_at"))
            st.write("Reporter:", r.get("reporter_username"))
            if role == "staff":
                col1, col2, col3 = st.columns([2,2,6])
                with col1:
                    if st.button("Assign to me", key=f"assign_{r.get('report_id')}"):
                        update_report(r.get("report_id"), {"assignee_username": st.session_state["user"], "status":"In Progress"})
                        add_notification_record(r.get("reporter_username"), f"Your report '{r.get('title')}' was assigned to {st.session_state['user']}")
                        st.success("Assigned to you")
                        st.experimental_rerun()
                with col2:
                    ns = st.selectbox("New status", ["Open","In Progress","Resolved"], key=f"status_{r.get('report_id')}")
                    if st.button("Update status", key=f"upst_{r.get('report_id')}"):
                        update_report(r.get("report_id"), {"status": ns})
                        add_notification_record(r.get("reporter_username"), f"Status updated for '{r.get('title')}' to {ns}")
                        st.success("Status updated")
                        st.experimental_rerun()
                with col3:
                    st.write("Priority score:", compute_priority_score(r))

    # CSV export (staff/admin)
    if role in ("staff","admin"):
        if st.button("Export CSV of current results"):
            # Build CSV
            sio = io.StringIO()
            writer = csv.writer(sio)
            writer.writerow(["id","title","description","category","priority","location","status","reporter","assignee","created_at","updated_at"])
            for r in items:
                writer.writerow([
                    r.get("report_id"),
                    r.get("title"),
                    r.get("description"),
                    r.get("category"),
                    r.get("priority"),
                    r.get("location"),
                    r.get("status"),
                    r.get("reporter_username"),
                    r.get("assignee_username", ""),
                    r.get("created_at"),
                    r.get("updated_at")
                ])
            st.download_button("Download CSV", data=sio.getvalue().encode("utf-8"), file_name="reports.csv")

def page_report_view(report_id):
    r = get_report(report_id)
    if not r:
        st.error("Report not found")
        return
    st.header(f"Report: {r.get('title')}")
    st.markdown(f"**Category:** {r.get('category')}  |  **Priority:** {r.get('priority')}  |  **Status:** {r.get('status')}")
    st.markdown(f"**Description:**\n{r.get('description')}")
    st.markdown(f"**Reported by:** {r.get('reporter_username')} at {r.get('created_at')}")
    if r.get("attachment"):
        st.write("Attachment:", r.get("attachment"))

    if st.session_state.get("role") == "staff":
        staff_list = []
        if USE_FIREBASE:
            docs = db.collection("users").where("role", "in", ["staff","admin"]).stream()
            for d in docs:
                staff_list.append(d.id)
        else:
            for u,v in LOCAL_USERS.items():
                if v["role"] in ("staff","admin"):
                    staff_list.append(u)
        assignee = st.selectbox("Assign to staff", [""]+staff_list)
        new_status = st.selectbox("Status", ["Open","In Progress","Resolved"], index= ["Open","In Progress","Resolved"].index(r.get("status", "Open")))
        if st.button("Save changes"):
            updates = {"status": new_status}
            if assignee:
                updates["assignee_username"] = assignee
            update_report(report_id, updates)
            add_notification_record(r.get("reporter_username"), f"Your report '{r.get('title')}' was updated by staff.")
            st.success("Updated")
            st.experimental_rerun()

def page_notifications():
    show_notifications()

# ---------- Main app routing ----------
def main():
    st.title(APP_TITLE)
    sidebar_auth_block()

    # routing via query params / session
    page = st.experimental_get_query_params().get("page", ["home"])[0]
    if st.session_state.get("_show_register"):
        page = "register"
    # quick nav
    with st.sidebar:
        st.markdown("## Navigate")
        choices = ["home","report","dashboard","notifications"]
        for c in choices:
            if st.button(c.capitalize()):
                st.experimental_set_query_params(page=c)
                st.experimental_rerun()
        st.markdown("---")
        st.write("Firebase:", "Connected" if USE_FIREBASE else "Not connected (local fallback)")

    if page == "register":
        register_flow()
    elif page == "report":
        page_report()
    elif page == "dashboard":
        page_dashboard()
    elif page == "notifications":
        page_notifications()
    elif page == "home":
        page_home()
    else:
        # custom route: report view? e.g., page=report_view&rid=...
        if page == "report_view":
            rid = st.experimental_get_query_params().get("rid", [None])[0]
            if rid:
                page_report_view(rid)
            else:
                st.error("No report id supplied")
        else:
            page_home()

if __name__ == "__main__":
    st.set_page_config(page_title=APP_TITLE, layout="wide")
    # Print environment mode
    logger.info("Starting app. Firebase available: %s", USE_FIREBASE)
    main()
