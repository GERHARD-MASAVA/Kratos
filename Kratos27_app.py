# =================================================
# 🚀 Kratos – War Room Dashboard 
# =================================================

import os
import time
import requests
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
# Synthetic logs generator
# -----------------------
def generate_synthetic_logs(n=500):
    np.random.seed(42)
    df = pd.DataFrame({
        "timestamp": pd.date_range("2025-01-01", periods=n, freq="T"),
        "source_ip": np.random.choice(
            [
                "8.8.8.8",        # Google DNS - USA
                "1.1.1.1",        # Cloudflare DNS - Australia
                "77.88.55.77",    # Yandex - Russia
                "185.199.110.153",# GitHub - Europe
                "41.90.5.2",      # Kenya ISP
                "200.89.75.5",    # Argentina
                "103.21.244.0",   # India
                "196.25.1.200"    # South Africa
            ], n
        ),
        "dest_ip": np.random.choice(
            ["10.0.0.100","10.0.0.200","172.16.0.5","10.1.1.1"], n
        ),
        "bytes_sent": np.random.randint(50, 2000, n),
        "failed_logins": np.random.poisson(1, n)
    })
    # Inject anomalies
    for i in np.random.choice(df.index, size=max(10, int(n*0.03)), replace=False):
        df.loc[i, "bytes_sent"] = np.random.randint(5000,10000)
        df.loc[i, "failed_logins"] = np.random.randint(10,50)
    return df

# -----------------------
# Sidebar controls
# -----------------------
st.sidebar.title("Kratos Controls")
uploaded_file = st.sidebar.file_uploader("Upload log file (CSV/JSON)", type=["csv","json"])
refresh_interval = st.sidebar.selectbox("Auto-refresh interval (seconds)", [10, 30, 60], index=1)
playback_auto = st.sidebar.checkbox("▶️ Auto-play timeline (advance every refresh)", value=False)

if playback_auto:
    st.rerun()  # safer refresh

# -----------------------
# Load logs
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

# Parse timestamps
logs["timestamp"] = pd.to_datetime(logs["timestamp"], errors="coerce")
if logs["timestamp"].isna().all():
    st.error("Could not parse timestamps.")
    st.stop()
logs = logs.sort_values("timestamp").reset_index(drop=True)

# Normalize numbers
logs["bytes_sent"] = pd.to_numeric(logs["bytes_sent"], errors="coerce").fillna(0).astype(int)
logs["failed_logins"] = pd.to_numeric(logs["failed_logins"], errors="coerce").fillna(0).astype(int)

# -----------------------
# Anomaly detection
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
# Real Geo-IP lookup (ipinfo.io) + fallback
# -----------------------
IPINFO_TOKEN = "fe4a295a30fcdc"  # <<-- replace with your token

# Fallback IP → Lat/Lon mapping
STATIC_IP_MAP = {
    "8.8.8.8": (37.3861, -122.0839),   # Google DNS (California, USA)
    "1.1.1.1": (-33.8688, 151.2093),   # Cloudflare (Sydney, AU)
    "77.88.55.77": (55.7512, 37.6184), # Yandex (Moscow, RU)
    "185.199.110.153": (52.5200, 13.4050), # GitHub (Berlin, DE)
    "41.90.5.2": (-1.2921, 36.8219),   # Kenya
    "200.89.75.5": (-34.6037, -58.3816), # Argentina
    "103.21.244.0": (28.6139, 77.2090), # India
    "196.25.1.200": (-26.2041, 28.0473) # South Africa
}

def real_geolocate(ip):
    try:
        # Skip private IPs
        if ip.startswith(("10.", "192.168.", "172.16.")):
            return (0, 0)

        # Fallback first
        if ip in STATIC_IP_MAP:
            return STATIC_IP_MAP[ip]

        # Live lookup
        url = f"https://ipinfo.io/{ip}?token={IPINFO_TOKEN}"
        resp = requests.get(url, timeout=5)
        data = resp.json()

        if "loc" in data:
            lat, lon = map(float, data["loc"].split(","))
            return (lat, lon)
        else:
            return (0, 0)
    except Exception:
        return (0, 0)

alerts["lat"], alerts["lon"] = zip(*alerts["source_ip"].map(real_geolocate))

# -----------------------
# UI tabs
# -----------------------
st.title("🌍 Kratos – War Room Dashboard")
tab1, tab2, tab3, tab4 = st.tabs(["📊 Dashboard","🗺️ Live Map (Playback)","📜 Logs","🛡️ Countermeasures"])

# -----------------------
# Timeline setup
# -----------------------
t_min = logs["timestamp"].min().floor("H")
t_max = logs["timestamp"].max().ceil("H")
total_hours = int(((t_max - t_min).total_seconds() // 3600))

if "hour_pos" not in st.session_state:
    st.session_state.hour_pos = 0

if playback_auto and st.session_state.hour_pos < total_hours:
    st.session_state.hour_pos += 1

hour_slider = st.sidebar.slider("Select hour offset", 0, max(total_hours, 0), st.session_state.hour_pos)
if hour_slider != st.session_state.hour_pos:
    st.session_state.hour_pos = hour_slider

current_start = t_min + timedelta(hours=int(st.session_state.hour_pos))
current_end = current_start + timedelta(hours=1)
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
        st.info("No anomalies in this hour.")
    else:
        for _, r in df_view.sort_values("timestamp", ascending=False).iterrows():
            st.write(f"[{r['timestamp']}] **{r['severity']}** | {r['source_ip']} → {r['dest_ip']} | logins={r['failed_logins']} bytes={r['bytes_sent']}")

# -----------------------
# Live Map tab
# -----------------------
with tab2:
    st.header("Live Map – Real Geo-IP + Fallbacks")
    m = folium.Map(location=[20,0], zoom_start=2)

    for _, r in visible_alerts.iterrows():
        if r["lat"] != 0 and r["lon"] != 0:
            folium.CircleMarker(
                location=[r["lat"], r["lon"]],
                radius=7,
                color=severity_colors.get(r["severity"], "blue"),
                fill=True,
                fill_opacity=0.8,
                popup=(f"<b>{r['severity']}</b><br>{r['source_ip']} → {r['dest_ip']}"),
                tooltip=f"{r['severity']} | {r['source_ip']}"
            ).add_to(m)

    # Heatmap (only valid coords)
    heat_points = visible_alerts[(visible_alerts["lat"] != 0) & (visible_alerts["lon"] != 0)][["lat","lon"]].values.tolist()
    if heat_points:
        HeatMap(heat_points, radius=15, blur=12, min_opacity=0.4).add_to(m)
    else:
        st.info("⚠️ No valid geo-coordinates for heatmap in this hour.")

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
    if visible_alerts.empty:
        st.success("No alerts in the selected hour.")
    else:
        st.warning(f"{len(visible_alerts)} alerts. Choose response:")
        if st.button("🛑 Block IPs"):
            st.write("Blocked IPs:", visible_alerts["source_ip"].unique().tolist())
        if st.button("🔒 Isolate endpoints"):
            st.write("Isolated targets:", visible_alerts["dest_ip"].unique().tolist())
