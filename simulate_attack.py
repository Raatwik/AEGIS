import os
import time
import random
import sys

# --- CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAFE_ZONE = os.path.join(BASE_DIR, "SafeZone")
TRAP_FILE = os.path.join(SAFE_ZONE, "config.sys")

# Skip headers to bypass Heuristics (for Mode 2)
HEADER_SKIP_SIZE = 128 

def ensure_safezone_exists():
    if not os.path.exists(SAFE_ZONE):
        os.makedirs(SAFE_ZONE)

def reset_files():
    ensure_safezone_exists()
    print(f"\n🔄 SYSTEM RESET: Wiping & Restoring clean files in {SAFE_ZONE}...")
    
    for f in os.listdir(SAFE_ZONE):
        path = os.path.join(SAFE_ZONE, f)
        try:
            if os.path.isfile(path): os.remove(path)
        except: pass

    base_content = b"CONFIDENTIAL DATA - TOP SECRET - DO NOT SHARE " * 500
    print("✨ Generating 20 victim files with VALID HEADERS...")
    
    # MAGIC BYTES FOR REALISM
    PDF_HEADER = b"%PDF-1.5\n"
    XLSX_HEADER = b"PK\x03\x04" + (b"\x00" * 20)
    SQL_HEADER = b"SQLite format 3\x00"
    
    for i in range(1, 6):
        with open(os.path.join(SAFE_ZONE, f"financial_record_0{i}.xlsx"), "wb") as f:
            f.write(XLSX_HEADER + base_content + f"\nRow {i}: Account 49281-992".encode())

    for i in range(1, 6):
        with open(os.path.join(SAFE_ZONE, f"project_blueprint_v{i}.pdf"), "wb") as f:
            f.write(PDF_HEADER + base_content + f"\nLayer {i}: Architecture Schema".encode())

    for i in range(1, 6):
        with open(os.path.join(SAFE_ZONE, f"client_database_shard_{i}.db"), "wb") as f:
            f.write(SQL_HEADER + base_content + f"\nDB Shard {i}: Active Clients".encode())

    for i in range(1, 6):
        with open(os.path.join(SAFE_ZONE, f"hr_employee_data_part{i}.csv"), "wb") as f:
            f.write(base_content + f"\nID,Name,Salary\n{i},John Doe,100000".encode())

    # THE HONEYPOT
    with open(TRAP_FILE, "w") as f:
        f.write("SYSTEM_BOOT=1")

    if os.path.exists("malware.pid"):
        try: os.remove("malware.pid")
        except: pass
        
    print(f"✅ RESET COMPLETE. 20 Files ready for attack.\n")

def safe_activity():
    print("\n🟢 MODE 1: SAFE ACTIVITY (User Working)...")
    if not os.path.exists(SAFE_ZONE) or not os.listdir(SAFE_ZONE):
        reset_files()

    print(" -> Writing normal log files (Safe Traffic)...")
    for i in range(5):
        with open(os.path.join(SAFE_ZONE, "app_log.txt"), "a") as f:
            f.write(f"Log entry {i}: System normal at {time.time()} - Operations stable.\n")
        time.sleep(0.5)
        print(f"   -> Log Update {i+1}/5")
    print("✅ Safe Activity Complete.")

def haywire_attack():
    # Formerly "Smart Encryption". This is the Noisy one.
    print("\n💀 MODE 2: HAYWIRE RANSOMWARE (Mass Encryption)...")
    
    if not os.path.exists(SAFE_ZONE) or not os.listdir(SAFE_ZONE):
        reset_files()
        time.sleep(1)

    files = [f for f in os.listdir(SAFE_ZONE) if f != "config.sys" and f != "malware.pid"]
    print(f" -> LOCKING ALL {len(files)} FILES RAPIDLY...")
    
    for fname in files:
        fpath = os.path.join(SAFE_ZONE, fname)
        if os.path.isfile(fpath):
            print(f"   🔥 ENCRYPTING: {fname}")
            try:
                with open(fpath, "rb") as f:
                    data = f.read()
                
                # Keep Header (Stealthy against Heuristics) but HIGH ENTROPY (Noisy)
                header = data[:HEADER_SKIP_SIZE]
                encrypted_body = os.urandom(len(data) - HEADER_SKIP_SIZE)
                final_data = header + encrypted_body

                with open(fpath, "wb") as f:
                    f.write(final_data)
            except Exception as e: 
                pass
            
            # FAST IO (0.1s)
            time.sleep(0.1) 

    print("💀 HAYWIRE ATTACK COMPLETE. ENTROPY SPIKED.")

def corruption_attack():
    print("\n🧬 MODE 3: ZERO-DAY MUTATION (Header Destroy)...")
    if not os.path.exists(SAFE_ZONE): reset_files()
    
    files = [f for f in os.listdir(SAFE_ZONE) if f.endswith(".pdf") or f.endswith(".xlsx")]
    
    for fname in files:
        fpath = os.path.join(SAFE_ZONE, fname)
        print(f"   -> Corrupting File Header: {fname}")
        with open(fpath, "r+b") as f:
            f.write(b"\x00\xFF\x00\xFF" * 10) 
        time.sleep(0.5)
    print("🧬 CORRUPTION COMPLETE.")

def smart_stealth_attack():
    # Formerly "Stealth". This is the Smart/Targeted one.
    print("\n🥷 MODE 4: SMART STEALTH ATTACK (Targeting Criticals)...")
    if not os.path.exists(SAFE_ZONE): reset_files()
    
    print(" -> Analyzing file system structure...")
    time.sleep(1.0) 
    print(" -> Skipping low-value assets (Logs, Temp)...")
    time.sleep(0.5)
    print(" -> 🎯 CRITICAL ASSET FOUND: config.sys")
    time.sleep(0.5)
    print(f" -> ⚡ INJECTING PAYLOAD INTO: {TRAP_FILE}")
    
    with open(TRAP_FILE, "wb") as f:
        f.write(b"MALICIOUS_PAYLOAD_INJECTED")
        
    print(" -> Smart Attack Complete. (Trap Triggered).")

def rename_attack():
    print("\n🏷️ MODE 5: EXTENSION SPOOFER (Double Extension Attack)...")
    if not os.path.exists(SAFE_ZONE): reset_files()
    
    files = [f for f in os.listdir(SAFE_ZONE) if f != "config.sys"]
    print(f" -> RENAMING {len(files)} FILES TO .LOCKED...")
    
    for fname in files:
        src = os.path.join(SAFE_ZONE, fname)
        # Double extension attack: file.pdf -> file.pdf.locked
        dst = os.path.join(SAFE_ZONE, fname + ".locked") 
        
        try:
            print(f"   -> Renaming {fname} to {fname}.locked")
            os.rename(src, dst)
            time.sleep(0.5) # Slower to show the detection working in real-time
        except Exception as e:
            print(f"   Error: {e}")

    print("🏷️ RENAME ATTACK COMPLETE.")

def main():
    with open("malware.pid", "w") as f:
        f.write(str(os.getpid()))

    while True:
        print("\n" + "="*50)
        print("   🦠 MALWARE SIMULATOR V3.1 (RENAME EDITION)   ")
        print("="*50)
        print("0. RESET (Clean Slate)")
        print("1. Safe Activity")
        print("2. HAYWIRE RANSOMWARE (Mass Encryption)")
        print("3. ZERO-DAY MUTATION (Header Corruption)")
        print("4. SMART STEALTH ATTACK (Targeting Config.sys)")
        print("5. EXTENSION SPOOFER (Double Extension Rename)")
        print("Q. Quit")
        
        choice = input("\nSelect Action [0-5]: ").lower()

        try:
            if choice == '0': reset_files()
            elif choice == '1': safe_activity()
            elif choice == '2': haywire_attack()
            elif choice == '3': corruption_attack()
            elif choice == '4': smart_stealth_attack()
            elif choice == '5': rename_attack()
            elif choice == 'q': break
        except: break

if __name__ == "__main__":
    main()