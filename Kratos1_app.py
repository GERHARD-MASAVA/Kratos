# ================================================
# 🚀 Kratos Cyber Wedge v0.1 – Geo-IP War Room
# Google Colab Notebook Version
# ================================================

!pip install scikit-learn pandas numpy matplotlib folium --quiet

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt
import folium
from folium.plugins import MarkerCluster
from IPython.display import display

# ================================================
# 1. Generate Synthetic Cyber Logs
# ================================================
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

# Inject anomalies (simulate attacks)
for i in np.random.choice(logs.index, size=15, replace=False):
    logs.loc[i, "bytes_sent"] = np.random.randint(5000,10000)
    logs.loc[i, "failed_logins"] = np.random.randint(10,50)

print("✅ Sample cyber logs created:")
print(logs.head())

# ================================================
# 2. Anomaly Detection (Isolation Forest)
# ================================================
model = IsolationForest(contamination=0.05, random_state=42)
logs["score"] = model.fit_predict(logs[["bytes_sent","failed_logins"]])

alerts = logs[logs["score"] == -1]
print(f"\n🚨 Detected {len(alerts)} anomalies (possible threats)")

# ================================================
# 3. Simple Geo-IP Mapping (manual mapping for demo)
# ================================================
# Fake mapping: assign approximate coords to IPs
geo_map = {
    "10.0.0.1": (38.0, -97.0),        # USA (Kansas, central point)
    "192.168.1.5": (51.5, -0.1),      # UK (London)
    "203.0.113.9": (35.7, 139.7),     # Japan (Tokyo)
    "198.51.100.77": (55.7, 37.6),    # Russia (Moscow)
}

# Add lat/lon columns
alerts["lat"] = alerts["source_ip"].map(lambda ip: geo_map.get(ip, (0,0))[0])
alerts["lon"] = alerts["source_ip"].map(lambda ip: geo_map.get(ip, (0,0))[1])

# ================================================
# 4. World Map Visualization
# ================================================
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

display(m)

# ================================================
# 5. Simulate Countermeasure
# ================================================
def deploy_countermeasure(alerts_df):
    if alerts_df.empty:
        print("✅ No threats detected. Systems stable.")
    else:
        print("🚨 Kratos Response: Threats detected!")
        print(f"📡 Blocking {len(alerts_df)} suspicious connections...")
        print("🛡️ Network secured.")

deploy_countermeasure(alerts)
