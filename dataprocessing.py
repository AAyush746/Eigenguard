import json
import pandas as pd
import os

DATA_DIR = os.path.expanduser("/home/aayush/Downloads/4thsem/newfolder1/Eigenguard/collected_data")
INPUT_JSON = os.path.join(DATA_DIR, "request_log.json")
OUTPUT_CSV = os.path.join(DATA_DIR, "processed_requests.csv")

os.makedirs(DATA_DIR, exist_ok=True)

try:
    with open(INPUT_JSON, 'r', encoding='utf-8') as file:
        json_data = json.load(file)  # Load entire JSON array at once
except FileNotFoundError:
    print(f"Error: JSON file {INPUT_JSON} not found.")
    exit(1)
except json.JSONDecodeError as e:
    print(f"Error: Invalid JSON format in {INPUT_JSON}. {e}")
    exit(1)

print(f"Number of records read: {len(json_data)}")

df = pd.DataFrame(json_data)
df.to_csv(OUTPUT_CSV, index=False)

print(f"CSV saved to: {OUTPUT_CSV}")
print("\nFirst 5 rows of CSV:")
print(df.head())
