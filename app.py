from flask import Flask, render_template, request, jsonify
import json
import os

from main import NufsedC2

app = Flask(__name__)
c2 = NufsedC2()
MODE = 'mock'

# Mock implants data (same as in HTML mock)
mockImplants = [
    {
        "id": "implant-1",
        "status": "connected",
        "lastResponse": "No response yet",
        "user": "Ryan",
        "role": "Admin",
        "thumbnail": "thumb1.jpg",
        "cam": "cam1.jpg",
        "subnet": {
            "192.168.1.0": { "detectedDevices": 5, "ips": ["192.168.1.10","192.168.1.20","192.168.1.30","192.168.1.40","192.168.1.50"] },
            "192.168.2.0": { "detectedDevices": 3, "ips": ["192.168.2.10","192.168.2.20","192.168.2.30"] }
        }
    },
    {
        "id": "implant-2",
        "status": "disconnected",
        "lastResponse": "Error: Timeout",
        "user": "Alice",
        "role": "Guest",
        "thumbnail": "thumb2.jpg",
        "cam": "cam2.jpg",
        "subnet": {
            "10.0.0.0": { "detectedDevices": 2, "ips": ["10.0.0.10","10.0.0.20"] },
            "10.1.0.0": { "detectedDevices":4, "ips": ["10.1.0.10","10.1.0.20","10.1.0.30","10.1.0.40"] }
        }
    }
]

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/set_mode', methods=['POST'])
def set_mode():
    global MODE
    data = request.get_json()
    mode = data.get('mode', 'mock')
    MODE = mode
    return jsonify({"status": "ok", "mode": MODE})

@app.route('/api/stats', methods=['GET'])
def get_stats():
    global MODE, c2
    if MODE == 'mock':
        # Calculate from mockImplants
        active_count = sum(1 for i in mockImplants if i['status'] == 'connected')
        total_count = len(mockImplants)
        disconnected_count = sum(1 for i in mockImplants if i['status'] == 'disconnected')
        return jsonify({
            "activeImplants": active_count,
            "totalImplants": total_count,
            "disconnectedImplants": disconnected_count
        })
    else:
        # Real mode from c2
        stats = c2.get_stats()
        return jsonify(stats)

@app.route('/api/implants', methods=['GET'])
def get_implants():
    global MODE, c2
    if MODE == 'mock':
        return jsonify(mockImplants)
    else:
        # Real mode from c2
        imps = c2.get_implants()
        return jsonify(imps)

@app.route('/api/command', methods=['POST'])
def run_command():
    global MODE, c2
    data = request.get_json()
    cmd = data.get('command', '')

    if MODE == 'mock':
        # Mock response:
        return jsonify({"output": f"Mock response for command: {cmd}"})
    else:
        # Real mode: use c2.run_command
        output = c2.run_command(cmd)
        return jsonify({"output": output})

if __name__ == '__main__':
    # Suppose that in real mode we have some logic to populate c2.targets with real sessions.
    # For demonstration, let's add some dummy "real" targets if you choose real mode in the prompt.
    # In a real scenario, these would be populated dynamically by NufsedC2 as implants connect.
    # Just for demonstration:
    # c2.targets = [
    #     {"id":"implant-3","status":"connected","lastResponse":"Directory listed","user":"Root","role":"Superuser","thumbnail":"thumb3.jpg","cam":"cam3.jpg",
    #      "subnet":{"172.16.0.0":{"detectedDevices":6,"ips":["172.16.0.10","172.16.0.20"]}}},
    # ]

    app.run(host='0.0.0.0', port=8000, debug=True)
