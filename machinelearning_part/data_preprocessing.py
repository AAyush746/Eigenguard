import pandas as pd

df = pd.read_csv('processed_requests.csv')

# Fill missing values or drop if necessary
df = df.fillna({'body': '', 'userAgent': '', 'headers': '{}', 'query': '{}'})
df.to_csv('cleaned_requests.csv', index=False)
print("Data cleaned and saved to cleaned_requests.csv")
