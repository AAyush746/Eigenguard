import json
try:
    with open('/home/aayush/Downloads/4thsem/newfolder1/Eigenguard/collected_data/request_log.json', 'r') as f:
        json.load(f)
    print("JSON is valid")
except json.JSONDecodeError as e:
    print(f"JSON is invalid: {e}")