from flask import Flask, jsonify, request
from flask_cors import CORS
import random
import time
from datetime import datetime, timedelta
import threading

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Simulated database for threats
threats_db = []
scan_status = {
    "scanning": False,
    "progress": 0,
    "message": "",
    "completed": False,
    "anomalies_detected": 0
}

# Generate some initial fake threats
def generate_fake_threats():
    threat_types = [
        ("Port Scanning", "high", 85),
        ("Brute Force Attempt", "high", 92),
        ("Suspicious HTTP Request", "medium", 65),
        ("Unusual Login Location", "medium", 58),
        ("Data Exfiltration Attempt", "high", 88),
        ("DNS Tunneling", "medium", 72),
        ("Malware Beaconing", "high", 95),
        ("Policy Violation", "low", 45),
    ]
    
    for i in range(20):
        hours_ago = random.randint(0, 72)
        threat = random.choice(threat_types)
        ip_parts = [str(random.randint(1, 255)) for _ in range(4)]
        
        threats_db.append({
            "timestamp": (datetime.now() - timedelta(hours=hours_ago)).strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": ".".join(ip_parts),
            "description": threat[0],
            "level": threat[1].upper(),
            "anomaly_score": threat[2]
        })

# Generate initial data
generate_fake_threats()

@app.route('/api/dashboard-stats', methods=['GET'])
def get_dashboard_stats():
    """Return dashboard statistics"""
    critical_threats = len([t for t in threats_db if t['level'].lower() == 'high'])
    
    return jsonify({
        "total_anomalies": len(threats_db),
        "critical_threats": critical_threats,
        "security_score": max(0, 100 - (critical_threats * 5)),  # Simple scoring
        "events_processed": random.randint(5000, 10000),
        "ai_metrics": {
            "prediction_confidence": random.randint(80, 95),
            "anomaly_accuracy": random.randint(85, 98),
            "defense_adaptive": random.randint(75, 90)
        },
        "recent_threats": sorted(threats_db, key=lambda x: x['timestamp'], reverse=True)[:10]
    })

@app.route('/api/start-anomaly-scan', methods=['POST'])
def start_anomaly_scan():
    """Start a new anomaly detection scan"""
    if scan_status["scanning"]:
        return jsonify({"success": False, "message": "Scan already in progress"}), 400
    
    data = request.get_json()
    scan_type = data.get('scan_type', 'full')
    
    # Reset scan status
    scan_status.update({
        "scanning": True,
        "progress": 0,
        "message": f"Initializing {scan_type} scan...",
        "completed": False,
        "anomalies_detected": 0
    })
    
    # Start a background thread to simulate the scan
    threading.Thread(target=simulate_scan, args=(scan_type,)).start()
    
    return jsonify({
        "success": True,
        "message": f"{scan_type} scan started successfully"
    })

def simulate_scan(scan_type):
    """Simulate a scan running in the background"""
    total_steps = 10 if scan_type == 'targeted' else 20 if scan_type == 'realtime' else 30
    anomalies_found = 0
    
    for step in range(1, total_steps + 1):
        if not scan_status["scanning"]:
            break
            
        time.sleep(1)  # Simulate work
        
        # Randomly find some anomalies
        if random.random() > 0.7:
            new_anomalies = random.randint(1, 3)
            anomalies_found += new_anomalies
            
            # Add new threats to the database
            for _ in range(new_anomalies):
                threat_types = [
                    ("Port Scanning", "high", random.randint(80, 95)),
                    ("Suspicious Activity", "medium", random.randint(60, 79)),
                    ("Policy Violation", "low", random.randint(40, 59))
                ]
                threat = random.choice(threat_types)
                ip_parts = [str(random.randint(1, 255)) for _ in range(4)]
                
                threats_db.insert(0, {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "source_ip": ".".join(ip_parts),
                    "description": threat[0],
                    "level": threat[1].upper(),
                    "anomaly_score": threat[2]
                })
        
        progress = int((step / total_steps) * 95)  # Don't go to 100% until complete
        scan_status.update({
            "progress": progress,
            "message": f"Scanning network ({progress}% complete) - Found {anomalies_found} anomalies",
            "anomalies_detected": anomalies_found
        })
    
    if scan_status["scanning"]:
        scan_status.update({
            "progress": 100,
            "message": f"Scan completed. Found {anomalies_found} anomalies.",
            "completed": True,
            "scanning": False
        })

@app.route('/api/stop-anomaly-scan', methods=['POST'])
def stop_anomaly_scan():
    """Stop the current scan"""
    scan_status["scanning"] = False
    return jsonify({
        "success": True,
        "message": "Scan stopped successfully"
    })

@app.route('/api/scan-status', methods=['GET'])
def get_scan_status():
    """Return the current scan status"""
    return jsonify(scan_status)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)