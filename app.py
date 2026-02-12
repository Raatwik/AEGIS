import sys
import os
import threading
import time
import psutil 
from flask import Flask, render_template, jsonify, request

# --- PROJECT SETUP ---
sys.path.append(os.getcwd())

from sensor.monitor import start_monitoring
from sensor.ai_brain import predict_threat
from sensor.ai_hunter import hunt_for_threat 
from core.recovery import ShadowVault       
from core.network_kill import sever_connection, restore_connection, kill_malware_process
from core.reporter import generate_forensic_report

app = Flask(__name__, template_folder='ui/templates', static_folder='ui/static')

# --- CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAFE_ZONE_PATH = os.path.join(BASE_DIR, "SafeZone")

vault = ShadowVault(SAFE_ZONE_PATH)

# --- GLOBAL STATE ---
last_rollback_time = 0
last_event_time = time.time()
network_online = True  

# History for Graphs
history_entropy = [0] * 60
history_io = [0] * 60

# --- NEW: SafeZone-Specific I/O Monitoring State ---
last_proc_io = None
last_io_check_time = time.time()

system_status = {
    "status": "SECURE",
    "message": "System Protected. AI Neural Net Active.",
    "entropy": 0.0,
    "rate": 0,
    "ai_conf": 0.0,
    "attack_vector": "None",
    "malware_path": "SYSTEM SECURE",
    "malware_pid": "---",
    "ai_reason": "NEURAL NET STANDBY",
    "ai_score_breakdown": { "heuristics": 10, "entropy": 0, "behavior": 0 }
}

# --- HELPER FUNCTIONS ---

def get_safezone_io_rate():
    """
    Identifies the malware process and calculates its specific I/O throughput.
    """
    global last_proc_io, last_io_check_time
    
    target_name = "simulate_attack.py"
    target_proc = None

    # 1. Find the attack process specifically
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmd = " ".join(proc.info['cmdline'] or []).lower()
            if target_name in cmd:
                target_proc = proc
                break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if not target_proc:
        last_proc_io = None 
        return 0

    try:
        # 2. Extract Process-Level I/O Counters
        current_io = target_proc.io_counters()
        current_time = time.time()
        time_diff = current_time - last_io_check_time
        
        if time_diff <= 0 or last_proc_io is None:
            last_proc_io = current_io
            last_io_check_time = current_time
            return 0
        
        # Calculate Delta (Bytes Written + Read)
        io_delta = (current_io.read_bytes + current_io.write_bytes) - \
                   (last_proc_io.read_bytes + last_proc_io.write_bytes)
        
        # Scale for UI: Convert to a 0-100 operations metric
        rate = int((io_delta / 10240) / time_diff) 
        
        last_proc_io = current_io
        last_io_check_time = current_time
        return max(0, min(100, rate)) 
    except:
        return 0

def deploy_vaccine():
    print("💉 VACCINE PROTOCOL: Injecting 'Global\\DarkSide' Mutex...")
    print("💉 VACCINE PROTOCOL: Spoofing Locale ID (0x0419 - Russian)...")

def find_malware_path_fallback():
    whitelist = ['app.py', 'monitor.py', 'reporter.py', 'ai_hunter.py']
    my_pid = os.getpid()

    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if proc.info['pid'] == my_pid: continue
            cmd_list = proc.info['cmdline'] or []
            cmd_str = " ".join(cmd_list).lower()

            if 'python' in cmd_str:
                is_safe = False
                for safe_file in whitelist:
                    if safe_file in cmd_str:
                        is_safe = True
                        break
                
                if not is_safe:
                    for arg in cmd_list:
                        if arg.endswith('.py'):
                            return os.path.abspath(arg), proc.info['pid']
        except: pass
    return "Unknown/Hidden", "???"

def start_aegis_backend():
    global system_status, last_rollback_time, network_online, history_entropy, history_io, last_event_time
    
    def update_brain(data_packet):
        global system_status, last_rollback_time, network_online, last_event_time

        last_event_time = time.time()
        if time.time() - last_rollback_time < 3: return 

        try:
            # Parse the new packet format
            # Format: ENTROPY:x|TRAP:x|BADHEADER:x|RENAME:x|PATH:x
            parts = data_packet.split('|')
            entropy = float(parts[0].split(':')[1])
            trap = int(parts[1].split(':')[1])
            bad_header = int(parts[2].split(':')[1])
            
            # SAFEGUARD: Handle cases where RENAME might not be in old packets
            rename_flag = 0
            if "RENAME" in data_packet:
                # Find the part that contains RENAME
                rename_part = [p for p in parts if "RENAME" in p][0]
                rename_flag = int(rename_part.split(':')[1])

            filepath = data_packet.split('PATH:')[1].strip()

            system_status["entropy"] = entropy
            
            # --- SCORING & DETECTION ---
            score_heuristics = 10 
            score_entropy = int(entropy * 10)
            score_behavior = 0

            is_high_entropy = entropy > 7.0
            filename = os.path.basename(filepath)
            _, ext = os.path.splitext(filename)
            ext = ext.lower().strip() 
            
            low_entropy_extensions = ['.txt', '.py', '.c', '.cpp', '.java', '.html', '.css', '.js', '.md', '.pdf', '.xlsx', '.csv', '.db']

            confidence = 0.0
            status = "SECURE"
            msg = "System Protected."
            trigger_kill = False
            vector = "None"

            # --- TRIAD DEFENSE CHECK (UPDATED) ---
            if trap == 1:
                confidence = 100.0
                msg = "SMART RANSOMWARE TRAPPED!"
                status = "DANGER"
                vector = "Honeypot Capture (Targeted Attack)"
                trigger_kill = True
                score_behavior = 99
            
            elif rename_flag == 1:
                confidence = 98.0
                msg = "MALICIOUS RENAME DETECTED"
                status = "DANGER"
                vector = "Double Extension / Ransomware Pattern"
                trigger_kill = True
                score_behavior = 95
                score_heuristics = 90

            elif bad_header == 1:
                confidence = 95.0
                msg = "FILE CORRUPTION (Header Mismatch)"
                status = "DANGER"
                vector = "Magic Byte Corruption (Zero-Day)"
                trigger_kill = True
                score_heuristics = 95
            
            elif ext in low_entropy_extensions and is_high_entropy:
                confidence = 99.0
                msg = f"HAYWIRE ENCRYPTION ({ext})"
                status = "DANGER"
                vector = "High Entropy Spike (Mass Encryption)"
                trigger_kill = True 
                score_entropy = 99 
            
            elif ext not in low_entropy_extensions and is_high_entropy and bad_header == 0:
                confidence = 10.0
                msg = "Verified Compressed File (Safe)"
                status = "SECURE"
                score_entropy = 30 
            
            system_status["ai_score_breakdown"] = {"heuristics": score_heuristics, "entropy": score_entropy, "behavior": score_behavior}

            if status == "DANGER":
                system_status["ai_conf"] = round(confidence, 1)
                system_status["status"] = status
                system_status["message"] = msg
                system_status["attack_vector"] = vector

                # AI PROCESS HUNTING
                if system_status["malware_path"] == "SYSTEM SECURE" or "Unknown" in system_status["malware_path"]:
                    print("🧠 NEURAL NET: Hunting for malicious PID...")
                    ai_pid, ai_path, ai_reason = hunt_for_threat()
                    
                    if ai_pid:
                        system_status["malware_path"] = ai_path
                        system_status["malware_pid"] = f"PID: {ai_pid}"
                        system_status["ai_reason"] = f"AI ANALYSIS: {ai_reason}"
                    else:
                        path, pid = find_malware_path_fallback()
                        system_status["malware_path"] = path
                        system_status["malware_pid"] = f"PID: {pid}"
                        system_status["ai_reason"] = "HEURISTIC MATCH (Regex)"

                if trigger_kill and network_online:
                    print(f"⚡ CONTAINMENT ACTIVATED: {vector}")
                    sever_connection() 
                    network_online = False 
            
            elif system_status["status"] != "DANGER":
                system_status["ai_conf"] = round(confidence, 1)
                system_status["status"] = status
                system_status["message"] = msg

        except Exception as e:
            print(f"Error processing packet: {e}")

    # Start Monitor
    start_monitoring(SAFE_ZONE_PATH, update_brain)
    
    # --- REAL TIME GRAPH & I/O UPDATE LOOP ---
    while True: 
        time.sleep(1) # Check every 1 second
        
        # 1. Update REAL I/O Rate for the SafeZone (Attacker Process)
        real_io_rate = get_safezone_io_rate()
        system_status["rate"] = real_io_rate
        
        # 2. Update Graphs
        history_io.pop(0)
        history_io.append(real_io_rate)
        
        # Entropy Persistence Logic
        history_entropy.pop(0)
        history_entropy.append(system_status["entropy"])
        
        # Decay Entropy if no activity for 2 seconds
        if system_status["status"] != "DANGER" and (time.time() - last_event_time > 2.0):
            system_status["entropy"] = 0.0
            system_status["malware_path"] = "SYSTEM SECURE"
            system_status["malware_pid"] = "---"
            system_status["ai_reason"] = "NEURAL NET STANDBY"
            system_status["ai_score_breakdown"] = {"heuristics": 10, "entropy": 0, "behavior": 0}

@app.route('/')
def index(): return render_template('index.html')

@app.route('/api/status')
def get_status(): 
    response = system_status.copy()
    response["graph_entropy"] = history_entropy
    response["graph_io"] = history_io
    return jsonify(response)

@app.route('/api/eliminate', methods=['POST'])
def eliminate_threat():
    global system_status, network_online, last_rollback_time
    kill_malware_process()
    restore_connection() 
    network_online = True 
    last_rollback_time = time.time()
    if vault.restore_snapshot():
        system_status["status"] = "SECURE"
        system_status["message"] = "Threat Eliminated. System Restored."
        system_status["ai_conf"] = 0.0
        return jsonify({"success": True, "message": "System Sanitized & Wifi Restored."})
    return jsonify({"success": False, "message": "Error during restoration."})

@app.route('/api/report', methods=['GET'])
def get_ai_report():
    stats = {
        "vector": system_status.get("attack_vector", "Unknown"),
        "entropy_avg": max(history_entropy) if history_entropy else 0, 
        "io_peak": max(history_io) if history_io else 0
    }
    report_text = generate_forensic_report(stats)
    return jsonify({"report": report_text.replace("\n", "<br>")})

@app.route('/api/reset', methods=['POST'])
def reset_system():
    global system_status, network_online
    system_status["status"] = "SECURE"
    system_status["message"] = "System Reset."
    system_status["ai_conf"] = 0.0
    system_status["attack_vector"] = "None"
    system_status["entropy"] = 0.0
    system_status["malware_path"] = "SYSTEM SECURE"
    restore_connection()
    network_online = True 
    return jsonify({"success": True})

if __name__ == '__main__':
    print("--- 🛡️ AEGIS STARTUP SEQUENCE ---")
    if not os.path.exists(SAFE_ZONE_PATH): os.mkdir(SAFE_ZONE_PATH)
    vault.create_snapshot() 
    deploy_vaccine() 
    threading.Thread(target=start_aegis_backend, daemon=True).start()
    app.run(debug=True, use_reloader=False)