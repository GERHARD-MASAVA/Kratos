# ================================================
# 🚀 Kratos Cyber Wedge v0.3 – War Room Dashboard
# ================================================

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import folium
from folium.plugins import MarkerCluster
from streamlit_folium import st_folium
import streamlit as st
import time

# ================================================
# 1. Load Real Logs or Synthetic
# ================================================
@st.cache_data
def load_logs():
    try:
        logs = pd.read_csv("data/your_logs.csv")
        st.success("✅ Loaded real logs from data/your_logs.csv")
    except FileNotFoundError:
        st.warning("⚠️ No real logs found, using synthetic data")
        np.random.seed(42)
        logs = pd.DataFrame({
            "timestamp": pd.date_range("2025-01-01", periods=500, freq="T"),
            "source_ip": np.random.choice(
                ["10.0.0.1", "192.168.1.5", "203.0.113.9", "198.51.100.77"], 500
            ),
            "dest_ip": np.random.choice(
                ["10.0.0.100", "10.0.0.200", "172.16.0.5"], 500
            ),
            "bytes_sent": np.random.randint(50, 2000, 500),
            "failed_logins": np.random.poisson(1, 500)
        })
        # Inject anomalies
        for i in np.random.choice(logs.index, size=15, replace=False):
            logs.loc[i, "bytes_sent"] = np.random.randint(5000, 10000)
            logs.loc[i, "failed_logins"] = np.random.randint(10, 50)
    return logs

# ================================================
# 2. Detection
# ================================================
def detect_anomalies(logs):
    model = IsolationForest(contamination=0.05, random_state=42)
    logs["score"] = model.fit_predict(logs[["bytes_sent", "failed_logins"]])
    alerts = logs[logs["score"] == -1].copy()

    # Severity: simple rule
    def severity(row):
        if row["failed_logins"] > 20 or row["bytes_sent"] > 8000:
            return "High"
        elif row["failed_logins"] > 5 or row["bytes_sent"] > 4000:
            return "Medium"
        else:
            return "Low"

    alerts["severity"] = alerts.apply(severity, axis=1)
    return alerts

logs = load_logs()
alerts = detect_anomalies(logs)

# ================================================
# 3. Mapping (demo)
# ================================================
geo_map = {
    "10.0.0.1": (38.0, -97.0),        # USA
    "192.168.1.5": (51.5, -0.1),      # UK
    "203.0.113.9": (35.7, 139.7),     # Japan
    "198.51.100.77": (55.7, 37.6),    # Russia
}
alerts["lat"] = alerts["source_ip"].map(lambda ip: geo_map.get(ip, (0, 0))[0])
alerts["lon"] = alerts["source_ip"].map(lambda ip: geo_map.get(ip, (0, 0))[1])

# ================================================
# 4. Streamlit War Room UI
# ================================================
st.set_page_config(page_title="Kratos Cyber Wedge", layout="wide")
st.title("🛡️ Kratos Cyber Wedge – War Room v0.3")

# 🚨 Global Threat Banner
if len(alerts) > 0:
    st.markdown(
        f"""
        <div style="padding:15px;background-color:#ff4d4d;color:white;
                    font-size:24px;font-weight:bold;text-align:center;
                    border-radius:10px;animation: blinker 1s linear infinite;">
            🚨 {len(alerts)} Active Threats Detected – Immediate Attention Required 🚨
        </div>
        <style>
        @keyframes blinker {{
            50% {{ opacity: 0; }}
        }}
        </style>
        """,
        unsafe_allow_html=True
    )
else:
    st.success("✅ No active threats detected. Systems stable.")

# Tabs
tab1, tab2, tab3, tab4 = st.tabs(["📊 Overview", "🚨 Alerts", "🗺️ Threat Map", "⚔️ Simulation"])

# Tab 1 – Overview
with tab1:
    st.subheader("📊 System Overview")
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Events", len(logs))
    col2.metric("Threats Detected", len(alerts))
    col3.metric("Detection Model", "Isolation Forest")

    st.line_chart(logs[["bytes_sent", "failed_logins"]])

    st.markdown("### 📰 Recent Events")
    st.dataframe(logs.tail(10))

# Tab 2 – Alerts
with tab2:
    st.subheader("🚨 Detected Threats")
    st.dataframe(alerts[["timestamp", "source_ip", "dest_ip", "bytes_sent", "failed_logins", "severity"]])

    st.download_button("⬇️ Download Alerts CSV", alerts.to_csv(index=False), "alerts.csv")

# Tab 3 – Threat Map
with tab3:
    st.subheader("🗺️ Geo-IP Map of Threat Sources")
    m = folium.Map(location=[20, 0], zoom_start=2)
    marker_cluster = MarkerCluster().add_to(m)
    for _, row in alerts.iterrows():
        color = "red" if row["severity"] == "High" else "orange" if row["severity"] == "Medium" else "green"
        folium.Marker(
            location=[row["lat"], row["lon"]],
            popup=(f"Source: {row['source_ip']} → {row['dest_ip']}<br>"
                   f"Bytes: {row['bytes_sent']}<br>"
                   f"Failed Logins: {row['failed_logins']}<br>"
                   f"Severity: {row['severity']}"),
            icon=folium.Icon(color=color, icon="exclamation-triangle", prefix="fa")
        ).add_to(marker_cluster)
    st_data = st_folium(m, width=700, height=450)

# Tab 4 – Simulation
with tab4:
    st.subheader("⚔️ Kratos Countermeasure Simulation")
    if st.button("🚀 Deploy Countermeasure"):
        if alerts.empty:
            st.success("✅ No threats detected. Systems stable.")
        else:
            st.error(f"🚨 Kratos Response: Blocking {len(alerts)} suspicious connections...")
            st.info("🛡️ Network secured.")

# Auto-refresh every 30s to simulate live feed
st_autorefresh = st.empty()
time.sleep(1)
