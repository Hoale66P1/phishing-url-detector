import os
import sqlite3
import threading
import time
from datetime import datetime
from io import BytesIO
from urllib.parse import urlparse

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from detector.model import MaliciousURLDetector

DB_DIR = "database"
DB_PATH = os.path.join(DB_DIR, "history.db")
WHITELIST_PATH = os.path.join("data", "whitelist_vn.txt")

CONF_THRESHOLD_HIGH = 0.85
CONF_THRESHOLD_MEDIUM = 0.55

_db_lock = threading.Lock()


@st.cache_data(ttl=3600)
def _load_whitelist() -> set[str]:
    if not os.path.isfile(WHITELIST_PATH):
        print("Loaded whitelist: 0 domains (file missing)")
        return set()
    domains: set[str] = set()
    with open(WHITELIST_PATH, encoding="utf-8") as f:
        for line in f:
            d = line.strip()
            if d and not d.startswith("#"):
                domains.add(d.lower())
    print(f"Loaded whitelist: {len(domains)} domains")
    return domains


WHITELIST_SET = _load_whitelist()


CYBER_CSS = """
<style>
.stApp { background-color: #0a0a0f; color: #00ff88; font-family: 'Courier New', monospace; }
[data-testid="stSidebar"] { background-color: #0d0d1a; border-right: 1px solid #00aaff33; }
h1, h2, h3 { color: #00ccff !important; text-shadow: 0 0 10px #00ccff88; font-family: 'Courier New', monospace !important; }
.stTextInput input { background-color: #0d1117; color: #00ff88; border: 1px solid #00aaff; border-radius: 4px; font-family: 'Courier New', monospace; }
.stButton > button { background-color: #003366; color: #00ccff; border: 1px solid #00aaff; border-radius: 4px; font-family: 'Courier New', monospace; font-weight: bold; letter-spacing: 1px; transition: all 0.3s; }
.stButton > button:hover { background-color: #00aaff; color: #000; box-shadow: 0 0 15px #00aaffaa; }
.stTabs [data-baseweb="tab"] { color: #00aaff; background: transparent; font-family: 'Courier New', monospace; }
.stTabs [aria-selected="true"] { color: #00ff88 !important; border-bottom: 2px solid #00ff88 !important; }
[data-testid="stDataFrame"] { border: 1px solid #00aaff33; }
.stMarkdown p, label { color: #aaffcc !important; font-family: 'Courier New', monospace !important; line-height: 1.6 !important; }
header[data-testid="stHeader"] { background-color: #0a0a0f !important; border-bottom: 1px solid #00aaff22; }
header[data-testid="stHeader"] * { color: #00aaff !important; }
[data-testid="stToolbar"] { background-color: #0a0a0f !important; }
</style>
"""


def _get_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _init_db():
    os.makedirs(DB_DIR, exist_ok=True)
    with _db_lock:
        conn = _get_connection()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                prediction_label TEXT NOT NULL,
                confidence REAL NOT NULL,
                scan_timestamp TEXT NOT NULL,
                method TEXT DEFAULT 'ML_MODEL',
                confidence_level TEXT DEFAULT 'MEDIUM'
            );
        """)
        for col_sql in (
            "ALTER TABLE scan_history ADD COLUMN method TEXT DEFAULT 'ML_MODEL'",
            "ALTER TABLE scan_history ADD COLUMN confidence_level TEXT DEFAULT 'MEDIUM'",
        ):
            try:
                conn.execute(col_sql)
            except sqlite3.OperationalError:
                pass
        conn.commit()
        conn.close()


def _save_scan(url: str, label: str, confidence: float,
               method: str = "ML_MODEL", confidence_level: str = "MEDIUM"):
    with _db_lock:
        conn = _get_connection()
        conn.execute(
            "INSERT INTO scan_history "
            "(url, prediction_label, confidence, scan_timestamp, method, confidence_level) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (url, label, confidence,
             datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
             method, confidence_level),
        )
        conn.commit()
        conn.close()


def _get_history(limit: int = 20) -> pd.DataFrame:
    with _db_lock:
        conn = _get_connection()
        df = pd.read_sql_query(
            "SELECT id, url, prediction_label, confidence, scan_timestamp, "
            "method, confidence_level "
            "FROM scan_history ORDER BY id DESC LIMIT ?",
            conn,
            params=(limit,),
        )
        conn.close()
    return df


def _get_all_history() -> pd.DataFrame:
    with _db_lock:
        conn = _get_connection()
        df = pd.read_sql_query(
            "SELECT id, url, prediction_label, confidence, scan_timestamp, "
            "method, confidence_level "
            "FROM scan_history ORDER BY id DESC",
            conn,
        )
        conn.close()
    return df


def _clear_history():
    with _db_lock:
        conn = _get_connection()
        conn.execute("DELETE FROM scan_history")
        conn.commit()
        conn.close()


def _get_stats() -> dict:
    with _db_lock:
        conn = _get_connection()
        cursor = conn.execute("SELECT COUNT(*) FROM scan_history")
        total = cursor.fetchone()[0]
        cursor = conn.execute(
            "SELECT COUNT(*) FROM scan_history WHERE prediction_label = 'Legitimate'"
        )
        safe = cursor.fetchone()[0]
        cursor = conn.execute(
            "SELECT COUNT(*) FROM scan_history WHERE prediction_label = 'Phishing'"
        )
        phishing = cursor.fetchone()[0]
        cursor = conn.execute(
            "SELECT method, COUNT(*) FROM scan_history GROUP BY method"
        )
        method_counts = dict(cursor.fetchall())
        cursor = conn.execute(
            "SELECT confidence_level, COUNT(*) FROM scan_history GROUP BY confidence_level"
        )
        level_counts = dict(cursor.fetchall())
        conn.close()
    return {
        "total": total,
        "safe": safe,
        "phishing": phishing,
        "method": method_counts,
        "level": level_counts,
    }


def _truncate_url(url: str, max_len: int = 30) -> str:
    if len(url) <= max_len:
        return url
    return url[:max_len] + "..."


def _df_to_csv_bytes(df: pd.DataFrame) -> bytes:
    buffer = BytesIO()
    df.to_csv(buffer, index=False, encoding="utf-8-sig")
    return buffer.getvalue()


def _extract_root_domain(url: str) -> str:
    try:
        netloc = urlparse(url if "://" in url else "http://" + url).netloc.lower()
    except Exception:
        return ""
    if netloc.startswith("www."):
        netloc = netloc[4:]
    if ":" in netloc:
        netloc = netloc.split(":", 1)[0]
    return netloc


def _is_whitelisted(url: str, whitelist: set[str]) -> tuple[bool, str]:
    netloc = _extract_root_domain(url)
    if not netloc:
        return False, ""
    if netloc in whitelist:
        return True, netloc
    parts = netloc.split(".")
    for i in range(1, len(parts) - 1):
        candidate = ".".join(parts[i:])
        if candidate in whitelist:
            return True, candidate
    return False, ""


def predict_url(detector: MaliciousURLDetector, url: str,
                whitelist: set[str]) -> dict:
    if not url or not url.strip():
        return {
            "label": "Invalid", "is_phishing": False, "confidence": 0.0,
            "method": "INVALID", "confidence_level": "LOW",
            "note": "URL trong/khong hop le",
        }

    matched, dom = _is_whitelisted(url, whitelist)
    if matched:
        return {
            "label": "Legitimate", "is_phishing": False, "confidence": 1.0,
            "method": "WHITELIST", "confidence_level": "HIGH",
            "note": f"Trusted domain (matched: {dom})",
        }

    result = detector.predict(url)
    conf = result["confidence"]

    if conf >= CONF_THRESHOLD_HIGH:
        level = "HIGH"
    elif conf >= CONF_THRESHOLD_MEDIUM:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "label": result["label"],
        "is_phishing": result["is_phishing"],
        "confidence": conf,
        "method": "ML_MODEL",
        "confidence_level": level,
        "note": None,
    }


def _verdict_style(result: dict) -> tuple[str, str, str, str, str]:
    method = result["method"]
    level = result["confidence_level"]
    is_phishing = result["is_phishing"]

    if method == "WHITELIST":
        return ("#0a1a2d", "#00ffff", "#00ffff",
                "AN TOAN", "[WHITELIST] Pre-approved domain")
    if method == "INVALID":
        return ("#1a1a1a", "#888888", "#cccccc",
                "URL KHONG HOP LE", "[VALIDATION] Invalid URL")
    if level == "HIGH" and not is_phishing:
        return ("#0a2d0a", "#21c354", "#21c354",
                "AN TOAN", "[MODEL] Safe (high confidence)")
    if level == "HIGH" and is_phishing:
        return ("#2d0a0a", "#ff4b4b", "#ff4b4b",
                "NGUY HIEM", "[MODEL] Dangerous (high confidence)")
    if level == "MEDIUM":
        label = "CO THE NGUY HIEM" if is_phishing else "CO THE AN TOAN"
        return ("#2d240a", "#ffb900", "#ffb900",
                label, "[MODEL] Medium confidence -- nen kiem tra them")
    return ("#1a1a1a", "#888888", "#cccccc",
            "KHONG XAC DINH", "[MODEL] Low confidence -- can review")


def _render_verdict_box(result: dict):
    bg, border, color, big_label, badge = _verdict_style(result)
    st.markdown(
        f'<div style="background-color:{bg};border:1px solid {border};border-radius:8px;'
        f'padding:20px;text-align:center;margin-bottom:16px;">'
        f'<span style="color:{color};font-size:28px;font-weight:700;">{big_label}</span><br>'
        f'<span style="color:{color};font-size:13px;letter-spacing:1px;">{badge}</span></div>',
        unsafe_allow_html=True,
    )


@st.cache_resource
def load_model():
    return MaliciousURLDetector()


def _render_sidebar(detector_loaded: bool, model_version: str | None):
    with st.sidebar:
        st.header(">_ Lich su tra cuu")

        if model_version:
            st.caption(f"[SYS] Model: {model_version}  |  Whitelist: {len(WHITELIST_SET)} domains")

        if not detector_loaded:
            st.info("[SYS] Model chua san sang.")
            return

        history_df = _get_history(limit=20)

        if history_df.empty:
            st.info("[SYS] Chua co lich su tra cuu nao.")
        else:
            display_df = history_df.copy()
            display_df.insert(0, "STT", range(1, len(display_df) + 1))
            display_df["url"] = display_df["url"].apply(lambda u: _truncate_url(u, 30))
            display_df = display_df.drop(columns=["id"])
            display_df = display_df.rename(columns={
                "url": "URL",
                "prediction_label": "Nhan",
                "confidence": "Do tin cay",
                "scan_timestamp": "Thoi gian",
                "method": "Method",
                "confidence_level": "Level",
            })

            def _color_label(val):
                if val == "Phishing":
                    return "color: #ff4b4b; font-weight: 600"
                elif val == "Legitimate":
                    return "color: #21c354; font-weight: 600"
                return ""

            styled = display_df.style.map(_color_label, subset=["Nhan"])
            styled = styled.format({"Do tin cay": "{:.1%}"})
            st.dataframe(styled, hide_index=True, use_container_width=True)

        st.divider()

        all_history = _get_all_history()
        if not all_history.empty:
            csv_bytes = _df_to_csv_bytes(all_history)
            st.download_button(
                label="Download toan bo lich su (CSV)",
                data=csv_bytes,
                file_name=f"scan_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True,
            )

        if st.button("Xoa lich su", use_container_width=True):
            _clear_history()
            st.rerun()


def _tab_single_check(detector):
    st.subheader(">_ Kiem tra URL don le")
    st.markdown(
        "Nhap URL ben duoi va nhan **Phan tich** de kiem tra do an toan."
    )

    url_input = st.text_input(
        "URL can kiem tra:",
        placeholder="https://example.com",
        key="single_url_input",
    )

    if st.button("Phan tich URL", type="primary", use_container_width=True, key="btn_single"):
        if not url_input or not url_input.strip():
            st.warning("[SYS] Vui long nhap mot URL de kiem tra.")
            return

        url = url_input.strip()

        with st.spinner(">[SYS] Dang phan tich URL... Hybrid pipeline (Whitelist + ML)..."):
            time.sleep(0.6)
            result = predict_url(detector, url, WHITELIST_SET)
            try:
                features = detector.get_feature_details(url)
            except Exception:
                features = {}

        _save_scan(
            url, result["label"], result["confidence"],
            method=result["method"], confidence_level=result["confidence_level"],
        )

        st.divider()

        confidence_pct = result["confidence"] * 100
        result_label_text = "PHISHING" if result["is_phishing"] else "SAFE"
        if result["method"] == "WHITELIST":
            result_label_text = "SAFE (WHITELIST)"

        terminal_log = (
            f"[SYSTEM] URL submitted for analysis...\n"
            f"[STAGE1] URL validation       : OK\n"
            f"[STAGE2] Whitelist check      : {'MATCH (' + (result['note'] or '') + ')' if result['method'] == 'WHITELIST' else 'no match -> ML'}\n"
            f"[STAGE3] ML inference         : "
            f"{'skipped (whitelisted)' if result['method'] == 'WHITELIST' else 'Random Forest, 17 features'}\n"
            f"[STAGE4] Threshold tier       : {result['confidence_level']}\n"
            f"[RESULT] Label                : {result_label_text}\n"
            f"[RESULT] Confidence           : {confidence_pct:.1f}%\n"
            f"[RESULT] Method               : {result['method']}\n"
            f"[STATUS] Analysis complete."
        )
        st.code(terminal_log, language="bash")

        _render_verdict_box(result)

        st.markdown(f"**Do tin cay:** {confidence_pct:.1f}%  |  "
                    f"**Method:** `{result['method']}`  |  "
                    f"**Level:** `{result['confidence_level']}`")
        st.progress(result["confidence"])

        if result["method"] == "ML_MODEL" and features:
            with st.expander("Xem chi tiet 17 dac trung"):
                feature_df = pd.DataFrame(
                    list(features.items()),
                    columns=["Dac trung", "Gia tri"],
                )
                st.dataframe(feature_df, use_container_width=True, hide_index=True)
        elif result["method"] == "WHITELIST":
            st.info(
                f"[SYS] {result['note']}. ML inference da bo qua. "
                "Domain nay nam trong danh sach tin cay (Tranco top .vn + manual augments)."
            )


def _tab_bulk_check(detector):
    st.subheader(">_ Kiem tra hang loat")
    st.markdown(
        "Nhap nhieu URL (moi URL mot dong) va nhan **Quet tat ca** de kiem tra."
    )

    urls_text = st.text_area(
        "Danh sach URL:",
        height=180,
        placeholder="https://example.com\nhttps://suspicious-site.xyz/login\nhttps://google.com",
        key="bulk_urls_input",
    )

    if st.button("Quet tat ca", type="primary", use_container_width=True, key="btn_bulk"):
        if not urls_text or not urls_text.strip():
            st.warning("[SYS] Vui long nhap it nhat mot URL.")
            return

        raw_urls = [u.strip() for u in urls_text.strip().splitlines() if u.strip()]

        if not raw_urls:
            st.warning("[SYS] Khong tim thay URL hop le nao.")
            return

        results = []
        progress_bar = st.progress(0)
        status_text = st.empty()

        for i, url in enumerate(raw_urls):
            status_text.text(f"[SCAN] Dang quet {i + 1}/{len(raw_urls)}...")
            result = predict_url(detector, url, WHITELIST_SET)
            _save_scan(
                url, result["label"], result["confidence"],
                method=result["method"], confidence_level=result["confidence_level"],
            )
            results.append({
                "URL": url,
                "Ket qua": result["label"],
                "Confidence (%)": round(result["confidence"] * 100, 1),
                "Method": result["method"],
                "Level": result["confidence_level"],
            })
            progress_bar.progress((i + 1) / len(raw_urls))

        status_text.text(f"[STATUS] Hoan tat: {len(raw_urls)} URL da quet.")
        progress_bar.empty()

        st.divider()

        result_df = pd.DataFrame(results)

        def _color_row(row):
            if row["Ket qua"] == "Phishing":
                color = "color: #ff4b4b; font-weight: 600"
            elif row["Method"] == "WHITELIST":
                color = "color: #00ffff; font-weight: 600"
            else:
                color = "color: #21c354; font-weight: 600"
            return [color] * len(row)

        styled_df = result_df.style.apply(_color_row, axis=1)
        st.dataframe(styled_df, use_container_width=True, hide_index=True)

        csv_bytes = _df_to_csv_bytes(result_df)
        st.download_button(
            label="Export ket qua ra CSV",
            data=csv_bytes,
            file_name=f"bulk_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True,
        )


def _tab_dashboard():
    st.subheader(">_ Dashboard Thong ke")

    stats = _get_stats()

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric(label="Tong URL da quet", value=stats["total"])
    with col2:
        st.metric(label="URL An toan", value=stats["safe"])
    with col3:
        st.metric(label="URL Phishing", value=stats["phishing"])

    st.divider()

    if stats["total"] == 0:
        st.info("[SYS] Chua co du lieu thong ke. Hay quet mot vai URL truoc.")
        return

    fig_label = go.Figure(
        data=[
            go.Pie(
                labels=["An toan", "Phishing"],
                values=[stats["safe"], stats["phishing"]],
                hole=0.45,
                marker=dict(colors=["#21c354", "#ff4b4b"],
                            line=dict(color="#0a0a0f", width=2)),
                textinfo="label+percent",
                textfont=dict(size=14, color="#00ff88", family="Courier New"),
                hovertemplate="<b>%{label}</b><br>So luong: %{value}<br>Ty le: %{percent}<extra></extra>",
            )
        ]
    )
    fig_label.update_layout(
        title=dict(text="Phan bo nhan", font=dict(color="#00ccff", family="Courier New")),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#00ccff", family="Courier New"),
        showlegend=True,
        legend=dict(font=dict(size=13, color="#00ff88", family="Courier New")),
        margin=dict(t=50, b=30, l=30, r=30), height=380,
    )

    method_data = stats["method"]
    fig_method = go.Figure(
        data=[
            go.Pie(
                labels=list(method_data.keys()) or ["(no data)"],
                values=list(method_data.values()) or [1],
                hole=0.45,
                marker=dict(colors=["#00ffff", "#00ccff", "#888888"],
                            line=dict(color="#0a0a0f", width=2)),
                textinfo="label+percent",
                textfont=dict(size=14, color="#00ff88", family="Courier New"),
                hovertemplate="<b>%{label}</b><br>So luong: %{value}<br>Ty le: %{percent}<extra></extra>",
            )
        ]
    )
    fig_method.update_layout(
        title=dict(text="Method distribution",
                   font=dict(color="#00ccff", family="Courier New")),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#00ccff", family="Courier New"),
        showlegend=True,
        legend=dict(font=dict(size=13, color="#00ff88", family="Courier New")),
        margin=dict(t=50, b=30, l=30, r=30), height=380,
    )

    c1, c2 = st.columns(2)
    with c1:
        st.plotly_chart(fig_label, use_container_width=True)
    with c2:
        st.plotly_chart(fig_method, use_container_width=True)

    level_data = stats["level"]
    order = ["HIGH", "MEDIUM", "LOW"]
    level_x = [k for k in order if k in level_data]
    level_y = [level_data[k] for k in level_x]
    level_colors_map = {"HIGH": "#21c354", "MEDIUM": "#ffb900", "LOW": "#888888"}
    level_colors = [level_colors_map.get(k, "#00aaff") for k in level_x]

    if level_x:
        fig_level = go.Figure(
            data=[
                go.Bar(
                    x=level_x, y=level_y,
                    marker_color=level_colors,
                    text=level_y, textposition="auto",
                    textfont=dict(color="#0a0a0f", family="Courier New", size=14),
                )
            ]
        )
        fig_level.update_layout(
            title=dict(text="Confidence level distribution",
                       font=dict(color="#00ccff", family="Courier New")),
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#00ccff", family="Courier New"),
            xaxis=dict(title="Level", color="#00ff88", gridcolor="rgba(0, 170, 255, 0.13)"),
            yaxis=dict(title="Count", color="#00ff88", gridcolor="rgba(0, 170, 255, 0.13)"),
            margin=dict(t=50, b=30, l=30, r=30), height=320, showlegend=False,
        )
        st.plotly_chart(fig_level, use_container_width=True)

    st.divider()

    st.markdown("**Lich su quet gan nhat (50 ban ghi)**")
    recent = _get_history(limit=50)
    if not recent.empty:
        def _color_label(val):
            if val == "Phishing":
                return "color: #ff4b4b; font-weight: 600"
            elif val == "Legitimate":
                return "color: #21c354; font-weight: 600"
            return ""

        recent["confidence"] = recent["confidence"] * 100
        styled = recent.style.map(_color_label, subset=["prediction_label"])
        styled = styled.format({"confidence": "{:.0f}%"})
        st.dataframe(
            styled,
            use_container_width=True,
            hide_index=True,
            column_config={
                "id": st.column_config.NumberColumn("ID", width="small"),
                "url": st.column_config.TextColumn("URL", width="large"),
                "prediction_label": st.column_config.TextColumn("Ket qua", width="small"),
                "confidence": st.column_config.ProgressColumn(
                    "Do tin cay", min_value=0.0, max_value=100.0, format="%.0f%%"
                ),
                "scan_timestamp": st.column_config.TextColumn("Thoi gian", width="medium"),
                "method": st.column_config.TextColumn("Method", width="small"),
                "confidence_level": st.column_config.TextColumn("Level", width="small"),
            },
        )


def main():
    st.set_page_config(
        page_title="Phishing URL Detector",
        layout="centered",
    )

    st.markdown(CYBER_CSS, unsafe_allow_html=True)

    _init_db()

    st.title(">_ PHISHING URL DETECTOR")
    st.markdown(
        "<p style='color: #00ccff; font-family: Courier New;'>"
        "Hybrid System | Whitelist + Random Forest v4 | Trained on 590K URLs</p>",
        unsafe_allow_html=True,
    )
    st.divider()

    detector = None
    detector_loaded = False
    model_version = None

    try:
        detector = load_model()
        detector_loaded = True
        model_version = getattr(detector, "model_version", None)
    except FileNotFoundError:
        st.error(
            "**[ERROR] Model chua duoc huan luyen!**\n\n"
            "Vui long chay lenh sau trong terminal truoc:\n"
            "```\npython train.py\n# hoac\npython train_v4.py\n```"
        )

    _render_sidebar(detector_loaded, model_version)

    if not detector_loaded:
        st.stop()

    tab1, tab2, tab3 = st.tabs(["Quet Don le", "Quet Hang loat", "Dashboard Thong ke"])

    with tab1:
        _tab_single_check(detector)

    with tab2:
        _tab_bulk_check(detector)

    with tab3:
        _tab_dashboard()


if __name__ == "__main__":
    main()
