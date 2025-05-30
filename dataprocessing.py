import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
import os
from datetime import datetime

# Configuration
DATA_DIR = os.path.expanduser("~/Downloads/4th_sem/newfolder1/Eigenguard/collected_data")
INPUT_CSV = os.path.join(DATA_DIR, "processed_requests.csv")
OUTPUT_CSV = os.path.join(DATA_DIR, "ml_ready_data.csv")

# Check if input file exists
if not os.path.exists(INPUT_CSV):
    raise FileNotFoundError(f"Input file {INPUT_CSV} not found. Ensure processed_requests.csv exists.")

# Load data
df = pd.read_csv(INPUT_CSV)

# Feature engineering
def enhance_features(df):
    # Convert timestamp to datetime
    df['timestamp'] = pd.to_datetime(df['timestamp'])

    # IP frequency (requests per IP)
    ip_counts = df['ip'].value_counts()
    df['ip_request_count'] = df['ip'].map(ip_counts)

    # Status anomaly (1 if 4xx or 5xx, 0 otherwise)
    df['status_anomaly'] = df['status'].apply(lambda x: 1 if x >= 400 else 0)

    # Response time outlier (1 if > 2 std above mean)
    rt_mean = df['response_time'].mean()
    rt_std = df['response_time'].std()
    df['response_time_outlier'] = df['response_time'].apply(lambda x: 1 if x > rt_mean + 2 * rt_std else 0)

    # Request rate (requests per IP per minute)
    df['minute'] = df['timestamp'].dt.floor('min')
    request_rate = df.groupby(['ip', 'minute']).size().reset_index(name='request_count')
    df = df.merge(request_rate, on=['ip', 'minute'], how='left')
    df['request_rate'] = df['request_count'].fillna(0)
    df = df.drop(columns=['minute', 'request_count'])

    # Header anomaly (1 if header_count > mean + 2 std)
    hc_mean = df['header_count'].mean()
    hc_std = df['header_count'].std()
    df['header_anomaly'] = df['header_count'].apply(lambda x: 1 if x > hc_mean + 2 * hc_std else 0)

    return df

# Preprocess for ML
def preprocess_data(df):
    # Enhance features
    df = enhance_features(df)

    # Encode categorical variables
    le = LabelEncoder()
    df['method'] = le.fit_transform(df['method'])

    # Convert booleans to integers
    bool_cols = ['is_bot', 'has_referer', 'has_accept_encoding', 'is_weekend']
    for col in bool_cols:
        df[col] = df[col].astype(int)

    # Drop non-numeric or unnecessary columns
    df = df.drop(columns=['timestamp', 'ip'])

    # Save to CSV
    df.to_csv(OUTPUT_CSV, index=False)
    print(f"ML-ready data saved to {OUTPUT_CSV}")

    return df

# Run preprocessing
if __name__ == "__main__":
    df = preprocess_data(df)
    print("ML-ready DataFrame:")
    print(df.head())