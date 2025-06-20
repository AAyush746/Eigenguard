import pandas as pd

df = pd.read_csv('cleaned_requests.csv')
df['timestamp'] = pd.to_datetime(df['timestamp'])
df['hour'] = df['timestamp'].dt.hour
df['dayofweek'] = df['timestamp'].dt.dayofweek

# Encode categorical features
for col in ['method', 'url', 'userAgent', 'ip']:
    df[col + '_code'] = df[col].astype('category').cat.codes

# Select features for ML
features = ['status', 'responseTime', 'responseSize', 'hour', 'dayofweek',
            'method_code', 'url_code', 'userAgent_code', 'ip_code']
df_ml = df[features]
df_ml.to_csv('ml_features.csv', index=False)
print("Features engineered and saved to ml_features.csv")
