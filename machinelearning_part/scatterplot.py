import pandas as pd
import matplotlib.pyplot as plt

# Load your dataset with anomaly labels
df = pd.read_csv('ml_features.csv')            # Features used for ML
anomalies = pd.read_csv('anomalies.csv')       # Detected anomalies

# Merge anomaly labels back to main dataframe (assuming same order)
df['anomaly'] = 1  # Mark all as normal initially
df.loc[anomalies.index, 'anomaly'] = -1  # Mark anomalies

# Alternatively, if anomalies.csv contains only anomalies, you can do:
# df['anomaly'] = 1
# df.loc[df.index.isin(anomalies.index), 'anomaly'] = -1

# Separate normal and anomalous points
normal = df[df['anomaly'] == 1]
attack = df[df['anomaly'] == -1]

# Plot scatter plot of two features, e.g., responseTime vs responseSize
plt.figure(figsize=(10,6))
plt.scatter(normal['responseTime'], normal['responseSize'], c='blue', label='Genuine', alpha=0.6)
plt.scatter(attack['responseTime'], attack['responseSize'], c='red', label='Anomalous', alpha=0.6)

plt.xlabel('Response Time')
plt.ylabel('Response Size')
plt.title('Scatter Plot of Genuine vs Anomalous HTTP Requests')
plt.legend()
plt.grid(True)
plt.show()
