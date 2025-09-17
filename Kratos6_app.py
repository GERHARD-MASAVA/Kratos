# =================================================
# 🚀 Kratos– War Room Dashboard
# With Mute Alerts Option
# =================================================

import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import folium
from folium.plugins import MarkerCluster
from streamlit_folium import st_folium
import time

st.set_page_config(page_title="Kratos Cyber Wedge", layout="wide")

# ================================================
# 1. Generate or Load Logs
# ================================================
@st.cache_data
def load_data():
    try:
        df = pd.read_csv("data/your_logs.csv")
    except:
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

logs = load_data()

# ================================================
# 2. Anomaly Detection
# ================================================
model = IsolationForest(contamination=0.05, random_state=42)
logs["score"] = model.fit_predict(logs[["bytes_sent","failed_logins"]])
alerts = logs[logs["score"] == -1]

# Map IPs to fake coords for demo
geo_map = {
    "10.0.0.1": (38.0, -97.0),        # USA
    "192.168.1.5": (51.5, -0.1),      # UK
    "203.0.113.9": (35.7, 139.7),     # Japan
    "198.51.100.77": (55.7, 37.6),    # Russia
}
alerts["lat"] = alerts["source_ip"].map(lambda ip: geo_map.get(ip, (0,0))[0])
alerts["lon"] = alerts["source_ip"].map(lambda ip: geo_map.get(ip, (0,0))[1])

# ================================================
# 3. UI Layout (Tabs)
# ================================================
tab1, tab2, tab3, tab4 = st.tabs(["📊 Dashboard", "🗺️ Live Map", "📜 Logs", "🛡️ Countermeasures"])

# ================================================
# 📊 Dashboard Tab
# ================================================
with tab1:
    st.title("Kratos Cyber Wedge – War Room")

    # 🚨 Threat Banner with Mute Option
    if len(alerts) > 0:
        if st.checkbox("🔕 Mute Alerts"):
            st.warning(f"{len(alerts)} active threats detected (alerts muted)")
        else:
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

    # Threat Counter
    st.metric("Active Threats", len(alerts))

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

    for _, row in alerts.iterrows():
        folium.Marker(
            location=[row["lat"], row["lon"]],
            popup=(f"Source: {row['source_ip']} → {row['dest_ip']}<br>"
                   f"Bytes: {row['bytes_sent']}<br>"
                   f"Failed Logins: {row['failed_logins']}"),
            icon=folium.Icon(color="red", icon="exclamation-triangle", prefix="fa")
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
    if len(alerts) > 0:
        st.error("🚨 Threats detected! Deploying countermeasures...")
        st.write(f"📡 Blocking {len(alerts)} suspicious connections...")
        st.write("🛡️ Network secured.")
    else:
        st.success("✅ No action required. All systems normal.")
