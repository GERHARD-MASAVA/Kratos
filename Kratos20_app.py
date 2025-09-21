# =================================================
# 🚀 Kratos – War Room Dashboard 
# =================================================

import os
import time
import streamlit as st
import pandas as pd
import numpy as np
from datetime import timedelta
from sklearn.ensemble import IsolationForest
import folium
from folium.plugins import HeatMap
from streamlit_folium import st_folium

st.set_page_config(page_title="Kratos – Timeline Playback", layout="wide")

# -----------------------
# Helper: synthetic logs generator (fallback)
# -----------------------
def generate_synthetic_logs(n=500):
    np.random.seed(42)
    df = pd.DataFrame({
        "timestamp": pd.date_range("2025-01-01", periods=n, freq="T"),  # one-minute resolution
        "source_ip": np.random.choice(
            ["10.0.0.1","192.168.1.5","203.0.113.9","198.51.100.77","8.8.8.8"], n
        ),
        "dest_ip": np.random.choice(
            ["10.0.0.100","10.0.0.200","172.16.0.5","10.1.1.1"], n
        ),
        "bytes_sent": np.random.randint(50, 2000, n),
        "failed_logins": np.random.poisson(1, n)
    })
    # Inject some anomalies
    for i in np.random.choice(df.index, size=max(10, int(n*0.03)), replace=False):
        df.loc[i, "bytes_sent"] = np.random.randint(5000,10000)
        df.loc[i, "failed_logins"] = np.random.randint(10,50)
    return df

# -----------------------
# Sidebar: basic controls
# -----------------------
st.sidebar.title("Kratos Controls")
uploaded_file = st.sidebar.file_uploader("Upload log file (CSV/JSON)", type=["csv","json"])
refresh_interval = st.sidebar.selectbox("Auto-refresh interval (seconds)", [10, 30, 60], index=1)
playback_auto = st.sidebar.checkbox("▶️ Auto-play timeline (advance every refresh)", value=False)

if playback_auto:
    st.experimental_autorefresh(interval=refresh_interval * 1000, key="auto_refresh")

# -----------------------
# Load logs (uploaded or synthetic)
# -----------------------
if uploaded_file:
    try:
        if uploaded_file.name.lower().endswith(".csv"):
            logs = pd.read_csv(uploaded_file)
        else:
            logs = pd.read_json(uploaded_file)
        st.sidebar.success(f"Using uploaded file: {uploaded_file.name}")
    except Exception as e:
        st.sidebar.error(f"Failed to read uploaded file: {e}")
        logs = generate_synthetic_logs()
        st.sidebar.info("Falling back to synthetic logs.")
else:
    logs = generate_synthetic_logs()
    st.sidebar.info("No file uploaded — using synthetic demo logs.")

# Ensure required columns
required_cols = {"timestamp","source_ip","dest_ip","bytes_sent","failed_logins"}
if not required_cols.issubset(set(logs.columns)):
    st.error("Log file must have columns: timestamp, source_ip, dest_ip, bytes_sent, failed_logins")
    st.stop()

# Parse / normalize timestamp immediately
logs["timestamp"] = pd.to_datetime(logs["timestamp"], errors="coerce")
if logs["timestamp"].isna().all():
    st.error("Could not parse any timestamps. Make sure timestamp column is in a parseable format.")
    st.stop()

# Sort logs
logs = logs.sort_values("timestamp").reset_index(drop=True)

# Numeric safety
logs["bytes_sent"] = pd.to_numeric(logs["bytes_sent"], errors="coerce").fillna(0).astype(int)
logs["failed_logins"] = pd.to_numeric(logs["failed_logins"], errors="coerce").fillna(0).astype(int)

# -----------------------
# Anomaly detection (IsolationForest)
# -----------------------
model = IsolationForest(contamination=0.05, random_state=42)
logs["score"] = model.fit_predict(logs[["bytes_sent","failed_logins"]])
alerts = logs[logs["score"] == -1].copy()

# Severity classification
def classify_severity(r):
    if r["failed_logins"] > 20 and r["bytes_sent"] > 5000:
        return "High"
    elif r["failed_logins"] > 5 or r["bytes_sent"] > 3000:
        return "Medium"
    else:
        return "Low"

alerts["severity"] = alerts.apply(classify_severity, axis=1)
severity_colors = {"Low":"green","Medium":"orange","High":"red"}

# -----------------------
# Simple geo fallback (demo)
# -----------------------
geo_map_demo = {
    "10.0.0.1": (38.0, -97.0),
    "192.168.1.5": (51.5, -0.1),
    "203.0.113.9": (35.7, 139.7),
    "198.51.100.77": (55.7, 37.6),
    "8.8.8.8": (37.386, -122.0838)
}

def simple_geolocate(ip):
    return geo_map_demo.get(ip, (0,0))

alerts["lat"], alerts["lon"] = zip(*alerts["source_ip"].map(simple_geolocate))

# -----------------------
# UI: tabs
# -----------------------
st.title("Kratos – Timeline Playback (hour-by-hour)")
tab1, tab2, tab3, tab4 = st.tabs(["📊 Dashboard","🗺️ Live Map (Playback)","📜 Logs","🛡️ Countermeasures"])

# -----------------------
# Timeline setup (hour granularity)
# -----------------------
t_min = logs["timestamp"].min().floor("H")
t_max = logs["timestamp"].max().ceil("H")
total_hours = int(((t_max - t_min).total_seconds() // 3600))  # non-negative

# session state for play position
if "hour_pos" not in st.session_state:
    st.session_state.hour_pos = 0  # 0..total_hours

# If auto-play is enabled, advance hour_pos up to total_hours
if playback_auto:
    # advance by 1 hour per refresh (could be tuned)
    if st.session_state.hour_pos < total_hours:
        st.session_state.hour_pos += 1

# Sidebar timeline controls
st.sidebar.markdown("---")
st.sidebar.write(f"Timeline: {t_min} → {t_max} ({total_hours} hours)")
hour_slider = st.sidebar.slider("Select hour offset (hours since start)", 0, max(total_hours, 0), st.session_state.hour_pos)
# If user moves slider, update session state
if hour_slider != st.session_state.hour_pos:
    st.session_state.hour_pos = hour_slider

# Compute current window
current_start = t_min + timedelta(hours=int(st.session_state.hour_pos))
current_end = current_start + timedelta(hours=1)  # one-hour window

# Show timeline status
st.sidebar.write(f"Showing events between: **{current_start}** and **{current_end}**")
if st.sidebar.button("⏮ Reset timeline"):
    st.session_state.hour_pos = 0

# -----------------------
# Filter alerts for the current hour window
# -----------------------
visible_alerts = alerts[(alerts["timestamp"] >= current_start) & (alerts["timestamp"] < current_end)].copy()

# -----------------------
# Dashboard tab
# -----------------------
with tab1:
    st.header("Threat Dashboard")
    severity_filter = st.selectbox("Filter severity:", ["All","Low","Medium","High"], index=0)
    if severity_filter != "All":
        df_view = visible_alerts[visible_alerts["severity"] == severity_filter].copy()
    else:
        df_view = visible_alerts.copy()

    st.metric("Total events (all logs)", len(logs))
    st.metric("Visible alerts (current hour)", len(df_view))

    st.subheader("Live Threat Feed (current hour)")
    if df_view.empty:
        st.info("No detected anomalies in the selected hour.")
    else:
        # Show recent in descending time
        for _, r in df_view.sort_values("timestamp", ascending=False).iterrows():
            st.write(f"[{r['timestamp']}] **{r['severity']}** | {r['source_ip']} → {r['dest_ip']} | failed_logins={r['failed_logins']} bytes={r['bytes_sent']}")

    st.subheader("Hourly overview (counts for current hour vs previous hours)")
    # small trend: counts per hour over the whole period (but highlight current)
    hour_counts = alerts.set_index("timestamp").resample("1H").size()
    if not hour_counts.empty:
        st.line_chart(hour_counts)
    else:
        st.info("No alert trend data available.")

# -----------------------
# Live Map (Playback) tab
# -----------------------
with tab2:
    st.header("Live Map – Timeline Playback (Hour view)")
    m = folium.Map(location=[20,0], zoom_start=2)

    # Add markers for visible alerts
    added = 0
    for _, r in df_view.iterrows():
        lat = r.get("lat", 0)
        lon = r.get("lon", 0)
        # skip invalid coords
        if pd.isna(lat) or pd.isna(lon) or (lat == 0 and lon == 0):
            continue
        popup_html = (
            f"<b>Severity:</b> {r['severity']}<br>"
            f"<b>Time:</b> {r['timestamp']}<br>"
            f"<b>Source:</b> {r['source_ip']} → {r['dest_ip']}<br>"
            f"<b>Failed Logins:</b> {r['failed_logins']}<br>"
            f"<b>Bytes:</b> {r['bytes_sent']}"
        )
        folium.CircleMarker(
            location=[lat, lon],
            radius=7,
            color=severity_colors.get(r["severity"], "blue"),
            fill=True,
            fill_opacity=0.8,
            popup=popup_html,
            tooltip=f"{r['severity']} | {r['source_ip']}"
        ).add_to(m)
        added += 1

    # Heatmap for the visible alerts (if any)
    if not df_view.empty:
        heat_points = df_view[["lat","lon"]].dropna().values.tolist()
        if len(heat_points) > 0:
            HeatMap(heat_points, radius=12, blur=10).add_to(m)

    if added == 0:
        # show baseline map message
        folium.map.LayerControl().add_to(m)
        st.info("No mapped alerts for this hour. If many alerts have (0,0) coords it's because IPs are not geo-resolved in demo mode.")
    st_folium(m, width=1000, height=600)

# -----------------------
# Logs tab
# -----------------------
with tab3:
    st.header("Raw Logs")
    st.dataframe(logs.tail(200))

# -----------------------
# Countermeasures tab
# -----------------------
with tab4:
    st.header("Countermeasures (simulated)")
    if df_view.empty:
        st.success("No alerts in the selected hour to act on.")
    else:
        st.warning(f"{len(df_view)} visible alerts. Select responses below:")
        cols = st.columns([2,1])
        with cols[0]:
            block_ips = st.button("🛑 Block all visible source IPs (simulate)")
        with cols[1]:
            quarantine = st.button("🔒 Isolate target endpoints (simulate)")

        if block_ips:
            blocked = df_view["source_ip"].unique().tolist()
            st.write("Blocked IPs (simulated):")
            for ip in blocked:
                st.write(f"- {ip}")
            st.success("Simulated firewall rules applied.")

        if quarantine:
            dests = df_view["dest_ip"].unique().tolist()
            st.write("Isolated endpoints (simulated):")
            for d in dests:
                st.write(f"- {d}")
            st.success("Simulated endpoint isolation executed.")
