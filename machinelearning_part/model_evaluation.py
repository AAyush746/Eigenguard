import pandas as pd
from sklearn.metrics import precision_score, recall_score, f1_score

# Load dataset with true labels
df = pd.read_csv('processed_requests.csv')  # Replace with your file

# Assuming 'true_label' column exists with 0 (genuine) or 1 (attack)
y_true = df['true_label']

# Load predicted labels from your anomaly detection
# For example, from ml_features.csv with anomaly column or anomalies.csv
predictions = pd.read_csv('ml_features.csv')  # Or wherever your predictions are
# Suppose your model used IsolationForest with -1 anomaly, 1 normal
# Map to 0 (normal) and 1 (anomaly)
y_pred = predictions['anomaly'].map({1: 0, -1: 1})

# Calculate metrics
precision = precision_score(y_true, y_pred)
recall = recall_score(y_true, y_pred)
f1 = f1_score(y_true, y_pred)

print(f"Precision: {precision:.2f}")
print(f"Recall: {recall:.2f}")
print(f"F1 Score: {f1:.2f}")
