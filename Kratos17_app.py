# =================================================
# 🚀 Kratos – War Room Dashboard 
# =================================================

import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import folium
from folium.plugins import MarkerCluster
from streamlit_folium import st_folium

st.set_page_config(page_title="Kratos Cyber Wedge", layout="wide")

# ================================================
# 1. Generate Synthetic Logs (Fallback)
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
# 2. Load Logs
# ================================================
logs = generate_synthetic_logs()

# Ensure timestamps
logs["timestamp"] = pd.to_datetime(logs["timestamp"], errors="coerce")

# ================================================
# 3. Anomaly Detection
# ================================================
model = IsolationForest(contamination=0.05, random_state=42)
logs["score"] = model.fit_predict(logs[["bytes_sent","failed_logins"]])
alerts = logs[logs["score"] == -1].copy()

# Severity Classification
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
# 4. UI Layout (6 Tabs)
# ================================================
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "📊 Dashboard", "🗺️ Attack Map", "📜 Logs",
    "🛡️ Countermeasures", "🔔 Alerts", "🌐 Threat Intel"
])

# ================================================
# 📊 Dashboard Tab
# ================================================
with tab1:
    st.title("📊 Threat Dashboard")

    severity_choice = st.selectbox("Filter threats by severity:", ["All", "Low", "Medium", "High"])
    if severity_choice != "All":
        filtered_alerts = alerts[alerts["severity"] == severity_choice]
    else:
        filtered_alerts = alerts

    st.metric("Active Threats", len(filtered_alerts))
    st.line_chart(alerts.groupby(alerts["timestamp"].dt.hour).size(), height=250)
    st.bar_chart(alerts["severity"].value_counts(), height=250)
    st.dataframe(logs.tail(10))

# ================================================
# 🗺️ Attack Map Tab
# ================================================
with tab2:
    st.subheader("🌍 Geo-IP Attack Map (Demo)")
    m = folium.Map(location=[20,0], zoom_start=2)
    marker_cluster = MarkerCluster().add_to(m)
    for _, row in alerts.iterrows():
        folium.Marker(
            location=[20+np.random.randn(), 0+np.random.randn()],
            popup=f"Source {row['source_ip']} → {row['dest_ip']} | {row['severity']}",
            icon=folium.Icon(color=severity_colors[row["severity"]], icon="exclamation-triangle", prefix="fa")
        ).add_to(marker_cluster)
    st_folium(m, width=700, height=500)

# ================================================
# 📜 Logs Tab
# ================================================
with tab3:
    st.subheader("📜 Full Log Data")
    st.dataframe(logs, height=400)

# ================================================
# 🛡️ Countermeasures Tab
# ================================================
with tab4:
    st.subheader("🛡️ Automated Response")
    if len(alerts) > 0:
        st.error("🚨 Threats detected! Deploying countermeasures...")
        st.write("📡 Blocking suspicious IPs...")
    else:
        st.success("✅ No action required. All systems normal.")

# ================================================
# 🔔 Alerts Tab (NEW)
# ================================================
with tab5:
    st.subheader("🔔 Real-Time Alerts Feed (Demo)")
    if not alerts.empty:
        for _, row in alerts.tail(5).iterrows():
            st.warning(f"⚠️ {row['timestamp']} | {row['source_ip']} → {row['dest_ip']} | {row['severity']} threat")
    else:
        st.info("No alerts at the moment.")

# ================================================
# 🌐 Threat Intel Tab (NEW)
# ================================================
with tab6:
    st.subheader("🌐 Threat Intelligence Lookup")
    ip_lookup = st.text_input("Enter IP to check reputation:")
    if ip_lookup:
        st.write(f"🔎 Looking up {ip_lookup} (demo mode)")
        st.write("📍 Country: Unknown | 🚨 Risk: Medium | 🔗 Source: Open Threat Feed")
    else:
        st.info("Enter an IP above to query.")
