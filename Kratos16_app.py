# =================================================
# 🚀 Kratos – War Room Dashboard v0.6 (Streaming + Timeline)
# =================================================

import os
import time
import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import folium
from folium.plugins import MarkerCluster, HeatMap
from streamlit_folium import st_folium

st.set_page_config(page_title="Kratos Cyber Wedge", layout="wide")

# -----------------------
# Helpers
# -----------------------
def generate_synthetic_logs(n=500):
    np.random.seed(42)
    df = pd.DataFrame({
        "timestamp": pd.date_range("2025-01-01", periods=n, freq="T"),
        "source_ip": np.random.choice(
            ["10.0.0.1","192.168.1.5","203.0.113.9","198.51.100.77","8.8.8.8","1.1.1.1"], n
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

def load_logs_from_path(path="data/your_logs.csv"):
    # read CSV if exists and handle errors gracefully
    try:
        df = pd.read_csv(path)
        return df
    except Exception:
        return None

def ensure_timestamp(df):
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df

def detect_anomalies(df, contamination=0.05):
    model = IsolationForest(contamination=contamination, random_state=42)
    df = df.copy()
    # ensure numerical columns exist
    if "bytes_sent" not in df.columns or "failed_logins" not in df.columns:
        raise RuntimeError("Required numeric columns missing for anomaly detection.")
    df["score"] = model.fit_predict(df[["bytes_sent","failed_logins"]])
    alerts = df[df["score"] == -1].copy()
    return df, alerts

def classify_severity(df_alerts):
    def _sev(r):
        if r["failed_logins"] > 20 and r["bytes_sent"] > 5000:
            return "High"
        elif r["failed_logins"] > 5 or r["bytes_sent"] > 3000:
            return "Medium"
        else:
            return "Low"
    if not df_alerts.empty:
        df_alerts["severity"] = df_alerts.apply(_sev, axis=1)
    else:
        df_alerts["severity"] = pd.Series(dtype=str)
    return df_alerts

# Demo geo map fallback for private IPs
GEO_MAP_FALLBACK = {
    "10.0.0.1": (38.0, -97.0),        # USA
    "192.168.1.5": (51.5, -0.1),      # UK
    "203.0.113.9": (35.7, 139.7),     # Japan
    "198.51.100.77": (55.7, 37.6),    # Russia
    "8.8.8.8": (37.386, -122.0838),   # Google-ish
    "1.1.1.1": (-33.4940, 143.2104),  # Cloudflare-ish
}

def geolocate_ips(series):
    # Very cheap fallback: if ip in fallback map use it, else (0,0)
    lats = []
    lons = []
    for ip in series:
        coord = GEO_MAP_FALLBACK.get(ip, (0,0))
        lats.append(coord[0])
        lons.append(coord[1])
    return lats, lons

# -----------------------
# Sidebar controls (Streaming + Playback)
# -----------------------
st.sidebar.title("Kratos Controls")

# Upload or auto-load from data/your_logs.csv
uploaded_file = st.sidebar.file_uploader("Upload log file (CSV/JSON)", type=["csv","json"])
use_local_path = False
local_path = "data/your_logs.csv"
if uploaded_file is None and os.path.exists(local_path):
    use_local_path = True
    st.sidebar.info(f"Using logs from {local_path} (updates will be picked up automatically).")

# Auto-refresh interval (seconds)
refresh_interval = st.sidebar.selectbox("Refresh interval (seconds)", options=[10, 30, 60], index=1)
# Playback controls
if "play_tick" not in st.session_state:
    st.session_state.play_tick = 0
if "play_start" not in st.session_state:
    st.session_state.play_start = None

play = st.sidebar.checkbox("▶️ Play timeline (auto-advance)", value=False)
play_step_min = st.sidebar.selectbox("Playback speed (minutes / tick)", options=[1, 5, 15, 30], index=1)

# Manual scrub slider placeholder (we will set range after loading logs)
st.sidebar.markdown("---")
st.sidebar.write("Timeline controls:")
manual_time_override = None  # will be set later because we need timestamp range

# Auto-refresh mechanism: only enable when either play or using local file
enable_autorefresh = play or use_local_path
if enable_autorefresh:
    # st.experimental_autorefresh will request a rerun every refresh_interval*1000 ms
    st.experimental_autorefresh(interval=refresh_interval * 1000, key="kratos_autorefresh")

# -----------------------
# Load logs (uploaded / local / synthetic)
# -----------------------
if uploaded_file:
    try:
        if uploaded_file.name.endswith(".csv"):
            logs = pd.read_csv(uploaded_file)
        else:
            logs = pd.read_json(uploaded_file)
        st.sidebar.success(f"Using uploaded file: {uploaded_file.name}")
    except Exception as e:
        st.sidebar.error(f"Failed to read uploaded file: {e}")
        logs = generate_synthetic_logs()
else:
    if use_local_path:
        loaded = load_logs_from_path(local_path)
        if loaded is not None:
            logs = loaded
        else:
            logs = generate_synthetic_logs()
    else:
        logs = generate_synthetic_logs()

# Ensure timestamp & required cols
logs = ensure_timestamp(logs)
required_cols = {"timestamp","source_ip","dest_ip","bytes_sent","failed_logins"}
if not required_cols.issubset(logs.columns):
    st.error("Log file missing required columns: timestamp, source_ip, dest_ip, bytes_sent, failed_logins")
    st.stop()

# Convert numeric columns if needed
logs["bytes_sent"] = pd.to_numeric(logs["bytes_sent"], errors="coerce").fillna(0).astype(int)
logs["failed_logins"] = pd.to_numeric(logs["failed_logins"], errors="coerce").fillna(0).astype(int)

# Sort logs by time to make playback sensible
logs = logs.sort_values("timestamp").reset_index(drop=True)

# -----------------------
# Detection + Alerts
# -----------------------
logs, alerts = detect_anomalies(logs)
alerts = classify_severity(alerts)
# Add geolocation to alerts (fallback)
alerts["lat"], alerts["lon"] = geolocate_ips(alerts["source_ip"])
severity_colors = {"Low":"green","Medium":"orange","High":"red"}

# -----------------------
# Timeline setup
# -----------------------
# Determine time range for playback
if logs["timestamp"].notna().any():
    t_min = logs["timestamp"].min()
    t_max = logs["timestamp"].max()
else:
    t_min = pd.Timestamp.now()
    t_max = pd.Timestamp.now()

# Playback slider: represent as integer minutes from t_min
total_minutes = int((t_max - t_min).total_seconds() // 60) + 1
if total_minutes < 1:
    total_minutes = 1

# Initialize session_state positions
if "play_pos" not in st.session_state:
    st.session_state.play_pos = 0  # minutes since t_min

# If play is checked, advance the play_pos each rerun
if play:
    # increment by play_step_min
    st.session_state.play_pos = min(st.session_state.play_pos + play_step_min, total_minutes)
else:
    # If not playing, do not auto-advance (user controls slider)
    pass

# Manual slider to set play_pos (overrides auto if changed)
slider_pos = st.sidebar.slider("Playback position (minutes since start)", 0, total_minutes, st.session_state.play_pos)
# If user moved slider, sync session state
if slider_pos != st.session_state.play_pos:
    st.session_state.play_pos = slider_pos

# Current playback cutoff time
current_cutoff = t_min + pd.Timedelta(minutes=int(st.session_state.play_pos))

# Provide info in sidebar
st.sidebar.write(f"Playback time: {current_cutoff} (tick {st.session_state.play_pos} of {total_minutes})")
if st.sidebar.button("⏮ Reset playback"):
    st.session_state.play_pos = 0
    st.experimental_rerun()

# -----------------------
# Filter alerts by playback time (show only alerts up to cutoff)
# -----------------------
filtered_alerts = alerts[alerts["timestamp"] <= current_cutoff].copy() if "timestamp" in alerts.columns else alerts.copy()

# Also apply severity filter on UI
st.title("🛡️ Kratos Cyber Wedge – Live War Room (v0.6)")
tab1, tab2, tab3, tab4 = st.tabs(["📊 Dashboard", "🗺️ Live Map", "📜 Logs", "🛡️ Countermeasures"])

# -----------------------
# Dashboard Tab
# -----------------------
with tab1:
    st.header("Dashboard")
    severity_choice = st.selectbox("Filter by severity:", ["All","Low","Medium","High"], index=0)
    if severity_choice != "All":
        view_alerts = filtered_alerts[filtered_alerts["severity"] == severity_choice].copy()
    else:
        view_alerts = filtered_alerts.copy()

    st.metric("Total events", len(logs))
    st.metric("Visible alerts", len(view_alerts))

    st.subheader("Live Threat Feed (most recent first)")
    recent = view_alerts.sort_values("timestamp", ascending=False).head(10)
    for _, r in recent.iterrows():
        st.write(f"[{r['timestamp']}] **{r['severity']}** | {r['source_ip']} → {r['dest_ip']} | failed_logins={r['failed_logins']} bytes={r['bytes_sent']}")

    st.subheader("Charts")
    # hourly trend (based on visible alerts)
    if not view_alerts.empty and "timestamp" in view_alerts.columns:
        trend = view_alerts.set_index("timestamp").resample("1H").size()
        st.line_chart(trend)
        st.bar_chart(view_alerts["severity"].value_counts())
    else:
        st.info("No alert data to plot for current playback position / filters.")

    if not view_alerts.empty:
        csv = view_alerts.to_csv(index=False)
        st.download_button("Download visible alerts (CSV)", csv, "kratos_alerts_visible.csv", "text/csv")

# -----------------------
# Live Map Tab (Enhanced: layers + heatmap + tooltips)
# -----------------------
with tab2:
    st.header("Interactive Map")
    m = folium.Map(location=[20,0], zoom_start=2)

    # Feature groups for severities
    high_layer = folium.FeatureGroup(name="High", show=True).add_to(m)
    med_layer = folium.FeatureGroup(name="Medium", show=False).add_to(m)
    low_layer = folium.FeatureGroup(name="Low", show=False).add_to(m)

    # Add markers
    for _, row in view_alerts.iterrows():
        # if lat/lon are missing or 0, skip
        if pd.isna(row.get("lat")) or pd.isna(row.get("lon")) or (row.get("lat")==0 and row.get("lon")==0):
            continue
        tooltip = f"{row['severity']} | {row['source_ip']} → {row['dest_ip']}"
        marker = folium.CircleMarker(
            location=[row["lat"], row["lon"]],
            radius=7,
            color=severity_colors.get(row["severity"], "blue"),
            fill=True,
            fill_opacity=0.8,
            popup=(f"<b>Severity:</b> {row['severity']}<br>"
                   f"<b>Time:</b> {row['timestamp']}<br>"
                   f"<b>Source:</b> {row['source_ip']} → {row['dest_ip']}<br>"
                   f"<b>Bytes:</b> {row['bytes_sent']}<br>"
                   f"<b>Failed Logins:</b> {row['failed_logins']}"),
            tooltip=tooltip
        )
        if row["severity"] == "High":
            marker.add_to(high_layer)
        elif row["severity"] == "Medium":
            marker.add_to(med_layer)
        else:
            marker.add_to(low_layer)

    # Heatmap of all visible alerts
    if not view_alerts.empty:
        heat_points = view_alerts[["lat","lon"]].dropna().values.tolist()
        if len(heat_points) > 0:
            HeatMap(heat_points, radius=12, blur=10).add_to(m)

    folium.LayerControl(collapsed=False).add_to(m)
    st_folium(m, width=1000, height=600)

# -----------------------
# Logs Tab
# -----------------------
with tab3:
    st.header("Raw Logs (current data view)")
    st.dataframe(logs.tail(200))

# -----------------------
# Countermeasures Tab
# -----------------------
with tab4:
    st.header("Countermeasures (simulated)")
    if view_alerts.empty:
        st.success("No visible alerts at current playback position.")
    else:
        st.warning(f"Simulate blocking {len(view_alerts)} visible suspicious connections.")
        if st.button("Execute simulated block"):
            st.success("Simulated block executed (demo only).")
