# Kratos1_app.py
# Kratos Cyber Wedge v0.1 – Streamlit War Room with 4 tabs

import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import folium
from folium.plugins import MarkerCluster
from streamlit_folium import st_folium
import io

st.set_page_config(page_title="Kratos War Room", layout="wide")

# -----------------------------
# 1) Data generation / detection
# -----------------------------
@st.cache_data
def generate_logs(seed=42, n=500):
    np.random.seed(seed)
    logs = pd.DataFrame({
        "timestamp": pd.date_range("2025-01-01", periods=n, freq="T"),
        "source_ip": np.random.choice(
            ["10.0.0.1","192.168.1.5","203.0.113.9","198.51.100.77"], n
        ),
        "dest_ip": np.random.choice(
            ["10.0.0.100","10.0.0.200","172.16.0.5"], n
        ),
        "bytes_sent": np.random.randint(50, 2000, n),
        "failed_logins": np.random.poisson(1, n)
    })
    # Inject anomalies
    for i in np.random.choice(logs.index, size=max(5, int(n*0.03)), replace=False):
        logs.loc[i, "bytes_sent"] = np.random.randint(5000,10000)
        logs.loc[i, "failed_logins"] = np.random.randint(10,50)
    return logs

@st.cache_data
def detect_anomalies(logs, contamination=0.05):
    model = IsolationForest(contamination=contamination, random_state=42)
    logs = logs.copy()
    logs["score"] = model.fit_predict(logs[["bytes_sent","failed_logins"]])
    alerts = logs[logs["score"] == -1].reset_index(drop=True)
    return logs, alerts

logs = generate_logs()
logs, alerts = detect_anomalies(logs)

# Simple geo mapping for demo
GEO_MAP = {
    "10.0.0.1": (38.0, -97.0),        # USA (central)
    "192.168.1.5": (51.5, -0.1),      # UK (London)
    "203.0.113.9": (35.7, 139.7),     # Japan (Tokyo)
    "198.51.100.77": (55.7, 37.6),    # Russia (Moscow)
}
alerts = alerts.copy()
alerts["lat"] = alerts["source_ip"].map(lambda ip: GEO_MAP.get(ip, (0,0))[0])
alerts["lon"] = alerts["source_ip"].map(lambda ip: GEO_MAP.get(ip, (0,0))[1])

# -----------------------------
# Page Header
# -----------------------------
st.title("🛡️ Kratos — Cyber Wedge War Room")
st.markdown("**Sovereign AI for cyber threat detection** — demo version")

# -----------------------------
# Tabs UI
# -----------------------------
tab_overview, tab_alerts, tab_map, tab_sim = st.tabs(["Overview", "Alerts", "Map", "Simulation"])

# -----------------------------
# Overview Tab
# -----------------------------
with tab_overview:
    st.subheader("Live Overview")
    col1, col2, col3 = st.columns(3)
    col1.metric("Total events", len(logs))
    col2.metric("Active alerts", len(alerts))
    col3.metric("Anomaly rate", f"{round(len(alerts)/len(logs)*100,2)} %")
    st.markdown("---")
    st.subheader("Traffic preview (bytes sent)")
    # simple time-series chart
    chart_df = logs.set_index("timestamp")[["bytes_sent"]].rolling(5).mean()
    st.line_chart(chart_df)
    st.markdown("**Recent events**")
    st.dataframe(logs.tail(10))

# -----------------------------
# Alerts Tab
# -----------------------------
with tab_alerts:
    st.subheader("Detected Alerts")
    if alerts.empty:
        st.success("No threats detected.")
    else:
        st.dataframe(alerts[["timestamp","source_ip","dest_ip","bytes_sent","failed_logins"]])
        # allow download of alerts as CSV
        csv_buffer = io.StringIO()
        alerts.to_csv(csv_buffer, index=False)
        st.download_button("Download alerts (CSV)", csv_buffer.getvalue(), "kratos_alerts.csv", "text/csv")

# -----------------------------
# Map Tab
# -----------------------------
with tab_map:
    st.subheader("Geo-IP Threat Map")
    if alerts.empty:
        st.info("No alerts to show on the map.")
    else:
        # create folium map
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
        # display map in Streamlit
        st_folium(m, width=900, height=500)

# -----------------------------
# Simulation Tab
# -----------------------------
with tab_sim:
    st.subheader("Response Simulation")
    st.markdown("Simulate Kratos countermeasures on current alerts.")
    col_a, col_b = st.columns([2,1])
    with col_a:
        st.write("Choose response strategy:")
        strategy = st.selectbox("Strategy", ["Isolate IPs", "Block IP Range", "Increase Monitoring"])
        severity_threshold = st.slider("Max failed_logins to include in response", min_value=1, max_value=50, value=5)
        sample_rate = st.slider("Simulate on top N alerts", min_value=1, max_value=min(50, max(1, len(alerts))), value=min(5, max(1,len(alerts))))
    with col_b:
        st.write("Preview")
        st.metric("Alerts targeted", min(sample_rate, len(alerts)))
        st.write("Strategy details")
        st.markdown(f"- **{strategy}** will be applied to the top {sample_rate} alerts with failed_logins >= {severity_threshold}.")

    if st.button("Execute Simulation"):
        if alerts.empty:
            st.success("No threats detected. Nothing to simulate.")
        else:
            # pick candidate alerts
            candidates = alerts[alerts["failed_logins"] >= severity_threshold].sort_values(
                by="failed_logins", ascending=False
            ).head(sample_rate)
            if candidates.empty:
                st.warning("No alerts meet the severity threshold. Nothing executed.")
            else:
                st.error(f"Executing '{strategy}' on {len(candidates)} alerts...")
                # show a short table of what would be blocked/isolated
                st.dataframe(candidates[["timestamp","source_ip","dest_ip","bytes_sent","failed_logins"]])
                st.success("Simulation complete. (Demo only — no real network changes.)")

# -----------------------------
# Footer
# -----------------------------
st.markdown("---")
st.caption("Kratos v0.1 — demo. Data synthetic. For development and testing only.")
