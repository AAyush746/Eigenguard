import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv('ml_features.csv')
df['anomaly'] = pd.read_csv('anomalies.csv')['anomaly']

plt.figure(figsize=(8,4))
df['anomaly'].value_counts().plot(kind='bar')
plt.title('Normal vs Anomalous Requests')
plt.xlabel('Label (1=Normal, -1=Anomaly)')
plt.ylabel('Count')
plt.show()

# Plot distribution of response times for anomalies
anomalies = df[df['anomaly'] == -1]
plt.hist(anomalies['responseTime'], bins=20, color='red', alpha=0.7)
plt.title('Response Time Distribution (Anomalies)')
plt.xlabel('Response Time')
plt.ylabel('Frequency')
plt.show()
