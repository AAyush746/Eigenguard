import json
try:
    with open('/home/aayush/Downloads/4thsem/newfolder1/Eigenguard/collected_data/request_log.json', 'r') as f:
        data = json.load(f)
    print(f"JSON is valid")
    print(f"Number of records: {len(data)}")
    print(f"First record: {data[0] if data else 'Empty'}")
except json.JSONDecodeError as e:
    print(f"JSON is invalid: {e}")