# =================================================
# 🚀 Kratos – War Room Dashboard 
# With Upload Logs, Charts, Live Map & Smarter Countermeasures
# =================================================

import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import folium
from folium.plugins import MarkerCluster
from streamlit_folium import st_folium
import plotly.express as px

st.set_page_config(page_title="Kratos Cyber Wedge", layout="wide")

# ================================================
# 1. Generate Synthetic Logs (fallback)
# ================================================
def generate_synthetic_logs():
    np.random.seed(42)
    df = pd.DataFrame({
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
    for i in np.random.choice(df.index, size=15, replace=False):
        df.loc[i, "bytes_sent"] = np.random.randint(5000,10000)
        df.loc[i, "failed_logins"] = np.random.randint(10,50)
    return df

# ================================================
# 2. Load Logs (Upload or Fallback)
# ================================================
uploaded_file = st.sidebar.file_uploader("📂 Upload log file (CSV or JSON)", type=["csv","json"])

if uploaded_file:
    if uploaded_file.name.endswith(".csv"):
        logs = pd.read_csv(uploaded_file)
    else:
        logs = pd.read_json(uploaded_file)
    st.sidebar.success(f"✅ Using uploaded file: {uploaded_file.name}")
else:
    logs = generate_synthetic_logs()
    st.sidebar.info("ℹ️ No file uploaded, using synthetic demo logs.")

# Ensure required columns exist
required_cols = {"timestamp","source_ip","dest_ip","bytes_sent","failed_logins"}
if not required_cols.issubset(logs.columns):
    st.error("❌ Log file missing required columns. Needs: timestamp, source_ip, dest_ip, bytes_sent, failed_logins")
    st.stop()

# ================================================
# 3. Anomaly Detection
# ================================================
model = IsolationForest(contamination=0.05, random_state=42)
logs["score"] = model.fit_predict(logs[["bytes_sent","failed_logins"]])
alerts = logs[logs["score"] == -1].copy()

# Fake geo-map (for now)
geo_map = {
    "10.0.0.1": (38.0, -97.0),   # USA
    "192.168.1.5": (51.5, -0.1), # UK
    "203.0.113.9": (35.7, 139.7),# Japan
    "198.51.100.77": (55.7, 37.6)# Russia
}
alerts["lat"] = alerts["source_ip"].map(lambda ip: geo_map.get(ip, (0,0))[0])
alerts["lon"] = alerts["source_ip"].map(lambda ip: geo_map.get(ip, (0,0))[1])

# ================================================
# 4. Severity Classification
# ================================================
def classify_severity(row):
    if row["failed_logins"] > 20 and row["bytes_sent"] > 5000:
        return "High"
    elif row["failed_logins"] > 5 or row["bytes_sent"] > 3000:
        return "Medium"
    else:
        return "Low"

alerts["severity"] = alerts.apply(classify_severity, axis=1)
severity_colors = {"Low":"green","Medium":"orange","High":"red"}

# ================================================
# 5. UI Layout (Tabs)
# ================================================
tab1, tab2, tab3, tab4 = st.tabs(["📊 Dashboard", "🗺️ Live Map", "📜 Logs", "🛡️ Countermeasures"])

# ================================================
# 📊 Dashboard Tab
# ================================================
with tab1:
    st.title("Kratos Cyber Wedge – War Room")

    # Severity Filter
    severity_choice = st.selectbox("🔎 Filter threats by severity:", ["All", "Low", "Medium", "High"])
    if severity_choice != "All":
        filtered_alerts = alerts[alerts["severity"] == severity_choice]
    else:
        filtered_alerts = alerts

    # 🚨 Threat Banner
    if len(filtered_alerts) > 0:
        if st.checkbox("🔕 Mute Alerts"):
            st.warning(f"{len(filtered_alerts)} {severity_choice if severity_choice!='All' else ''} threats detected (alerts muted)")
        else:
            st.error(f"🚨 {len(filtered_alerts)} {severity_choice if severity_choice!='All' else ''} Threats Detected – Immediate Attention Required 🚨")
    else:
        st.success("✅ No active threats detected. Systems stable.")

    # Threat Counter
    st.metric("Active Threats", len(filtered_alerts))

    # === Extra Charts ===
    st.subheader("📈 Threat Trends (Hourly)")
    logs["timestamp"] = pd.to_datetime(logs["timestamp"], errors="coerce")
    if logs["timestamp"].notna().any():
        hourly_counts = alerts.groupby(alerts["timestamp"].dt.hour).size()
        if not hourly_counts.empty:
            fig_line = px.line(hourly_counts, title="Threats per Hour")
            st.plotly_chart(fig_line, use_container_width=True)
        else:
            st.info("ℹ️ No data available for hourly trend chart.")
    else:
        st.warning("⚠️ Could not parse timestamps in log file.")

    st.subheader("📊 Severity Breakdown")
    if not alerts.empty:
        fig_pie = px.pie(alerts, names="severity", title="Threat Severity Distribution")
        st.plotly_chart(fig_pie, use_container_width=True)
    else:
        st.info("ℹ️ No alerts available to classify by severity.")

    # Recent Events
    st.subheader("Recent Events")
    st.dataframe(logs.tail(10))

# ================================================
# 🗺️ Live Map Tab
# ================================================
with tab2:
    st.subheader("Geo-IP Attack Map")
    m = folium.Map(location=[20,0], zoom_start=2)
    marker_cluster = MarkerCluster().add_to(m)

    for _, row in filtered_alerts.iterrows():
        folium.Marker(
            location=[row["lat"], row["lon"]],
            popup=(f"<b>Severity:</b> {row['severity']}<br>"
                   f"Source: {row['source_ip']} → {row['dest_ip']}<br>"
                   f"Bytes: {row['bytes_sent']}<br>"
                   f"Failed Logins: {row['failed_logins']}"),
            icon=folium.Icon(color=severity_colors[row["severity"]], icon="exclamation-triangle", prefix="fa")
        ).add_to(marker_cluster)

    st_folium(m, width=700, height=500)

# ================================================
# 📜 Logs Tab
# ================================================
with tab3:
    st.subheader("Full Log Data")
    st.dataframe(logs, height=400)

# ================================================
# 🛡️ Countermeasures Tab
# ================================================
with tab4:
    st.subheader("Automated Response")
    if len(filtered_alerts) > 0:
        st.error("🚨 Threats detected! Deploying countermeasures...")

        for _, row in filtered_alerts.iterrows():
            if row["severity"] == "High":
                st.write(f"🛑 Blocking IP {row['source_ip']} at firewall.")
                st.write(f"🔒 Isolating target endpoint {row['dest_ip']}.")
            elif row["severity"] == "Medium":
                st.write(f"⚠️ Adding IP {row['source_ip']} to watchlist.")
            else:
                st.write(f"👀 Monitoring low-level activity from {row['source_ip']}.")

        st.success("🛡️ Automated defenses executed. Network secured.")
    else:
        st.success("✅ No action required. All systems normal.")
