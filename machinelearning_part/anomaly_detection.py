import pandas as pd
from sklearn.ensemble import IsolationForest

df = pd.read_csv('ml_features.csv')
iso = IsolationForest(contamination=0.05, random_state=42)
df['anomaly'] = iso.fit_predict(df)

# -1 = anomaly, 1 = normal
anomalies = df[df['anomaly'] == -1]
anomalies.to_csv('anomalies.csv', index=False)
print(f"Anomalies detected: {len(anomalies)}. Saved to anomalies.csv.")
