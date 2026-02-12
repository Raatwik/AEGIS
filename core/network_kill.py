import os
import subprocess
import psutil

# --- CONFIGURATION ---
# REPLACE THIS with your exact adapter name from Control Panel
ADAPTER_NAME = "Wi-Fi" 

def sever_connection():
    """
    Called by AI Detection -> Disables Wi-Fi to stop data leak.
    """
    print(f"\n⚡ KILL SWITCH ENGAGED: DISABLING {ADAPTER_NAME}...")
    try:
        # Windows command to disable the adapter
        subprocess.run(
            f'netsh interface set interface "{ADAPTER_NAME}" admin=disable', 
            shell=True, check=True
        )
        return True
    except Exception as e:
        print(f"❌ KILL FAILED: Run as Admin! Error: {e}")
        return False

def restore_connection():
    """
    Called by 'Eliminate Threat' -> Re-enables Wi-Fi.
    """
    print(f"✅ AEGIS: RESTORING {ADAPTER_NAME}...")
    try:
        # Windows command to enable the adapter
        subprocess.run(
            f'netsh interface set interface "{ADAPTER_NAME}" admin=enable', 
            shell=True, check=True
        )
        return True
    except Exception as e:
        print(f"❌ RESTORE FAILED: {e}")
        return False

def kill_malware_process():
    """
    Terminates the malware process ID.
    """
    print("⚔️ AEGIS: KILLING MALWARE PROCESS...")
    
    # 1. Kill by PID file
    if os.path.exists("malware.pid"):
        try:
            with open("malware.pid", "r") as f:
                pid = int(f.read().strip())
            psutil.Process(pid).terminate()
            print(f"💀 TERMINATED PID: {pid}")
            os.remove("malware.pid")
        except: 
            pass

    # 2. Kill by Name (Safety Net)
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmd = " ".join(proc.info['cmdline'] or []).lower()
            if "simulate_attack.py" in cmd:
                print(f"💀 FOUND & TERMINATED: {proc.info['pid']}")
                proc.terminate()
        except: pass