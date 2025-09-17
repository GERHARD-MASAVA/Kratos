# ================================================
# 🚀 Kratos Cyber Wedge –Dashboard 
# - Auto-Refresh
# - Live Threat Feed
# ================================================

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import folium
from folium.plugins import MarkerCluster
import streamlit as st
from streamlit_folium import st_folium
from datetime import datetime

# ================================================
# 1. Load or Upload Logs
# ================================================
def load_data():
    np.random.seed(42)
    logs = pd.DataFrame({
        "timestamp": pd.date_range("2025-01-01", periods=500, freq="T"),
        "source_ip": np.random.choice(
            ["10.0.0.1","192.168.1.5","203.0.113.9","198.51.100.77"], 500
        ),
        "dest_ip": np.random.choice(
            ["10.0.0.100","10.0.0.200","172.16.0.5"], 500
        ),
        "bytes_sent": np.random.randint(50, 2000, 500),
        "failed_logins": np.random.poisson(1, 500)
    })
    # Inject anomalies
    for i in np.random.choice(logs.index, size=15, replace=False):
        logs.loc[i, "bytes_sent"] = np.random.randint(5000,10000)
        logs.loc[i, "failed_logins"] = np.random.randint(10,50)
    return logs

st.set_page_config(layout="wide", page_title="Kratos Cyber Wedge")

uploaded_file = st.sidebar.file_uploader("Upload log file", type=["csv","json"])
if uploaded_file:
    if uploaded_file.name.endswith(".csv"):
        logs = pd.read_csv(uploaded_file)
    else:
        logs = pd.read_json(uploaded_file)
else:
    logs = load_data()

# ================================================
# 2. Auto Refresh
# ================================================
st_autorefresh = st.experimental_autorefresh(interval=30000, key="refresh")  
# Refresh every 30 sec

# ================================================
# 3. Anomaly Detection
# ================================================
model = IsolationForest(contamination=0.05, random_state=42)
logs["score"] = model.fit_predict(logs[["bytes_sent","failed_logins"]])
alerts = logs[logs["score"] == -1]

# Severity assignment
def classify(row):
    if row["failed_logins"] > 20 or row["bytes_sent"] > 7000:
        return "HIGH"
    elif row["failed_logins"] > 5 or row["bytes_sent"] > 3000:
        return "MEDIUM"
    else:
        return "LOW"

alerts["severity"] = alerts.apply(classify, axis=1)

# ================================================
# 4. Dashboard Layout
# ================================================
tab1, tab2, tab3, tab4 = st.tabs(["📊 Dashboard","🗺️ Threat Map","📜 Logs","🛡️ Countermeasures"])

with tab1:
    st.header("📊 Kratos Dashboard – Live Threats")
    st.metric("Total Events", len(logs))
    st.metric("Detected Threats", len(alerts))

    # 🔥 Live Threat Feed Panel
    st.subheader("🚨 Live Threat Feed (last 10)")
    latest = alerts.sort_values("timestamp", ascending=False).head(10)
    for _, row in latest.iterrows():
        st.write(f"[{row['timestamp']}] **{row['severity']}** | "
                 f"Source: {row['source_ip']} → {row['dest_ip']} | "
                 f"Failed Logins: {row['failed_logins']} | Bytes: {row['bytes_sent']}")

with tab2:
    st.header("🗺️ Threat Map")
    geo_map = {
        "10.0.0.1": (38.0, -97.0),
        "192.168.1.5": (51.5, -0.1),
        "203.0.113.9": (35.7, 139.7),
        "198.51.100.77": (55.7, 37.6),
    }
    alerts["lat"] = alerts["source_ip"].map(lambda ip: geo_map.get(ip, (0,0))[0])
    alerts["lon"] = alerts["source_ip"].map(lambda ip: geo_map.get(ip, (0,0))[1])

    m = folium.Map(location=[20,0], zoom_start=2)
    marker_cluster = MarkerCluster().add_to(m)

    for _, row in alerts.iterrows():
        color = "green" if row["severity"]=="LOW" else "orange" if row["severity"]=="MEDIUM" else "red"
        folium.Marker(
            location=[row["lat"], row["lon"]],
            popup=(f"<b>{row['severity']} Threat</b><br>"
                   f"Source: {row['source_ip']}<br>"
                   f"Dest: {row['dest_ip']}<br>"
                   f"Failed Logins: {row['failed_logins']}<br>"
                   f"Bytes: {row['bytes_sent']}"),
            icon=folium.Icon(color=color, icon="exclamation-triangle", prefix="fa")
        ).add_to(marker_cluster)
    st_folium(m, width=1000, height=600)

with tab3:
    st.header("📜 Raw Logs")
    st.dataframe(logs.tail(20))

with tab4:
    st.header("🛡️ Countermeasures")
    if len(alerts) > 0:
        st.error(f"🚨 {len(alerts)} active threats detected!")
        st.write("📡 Blocking suspicious connections...")
        st.success("🛡️ Network secured (simulated).")
    else:
        st.success("✅ No active threats detected.")
