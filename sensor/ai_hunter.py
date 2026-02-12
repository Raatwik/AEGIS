import psutil
import json
import os
from groq import Groq

# --- CONFIGURATION ---
API_KEY = "INsert Groq API key"  # <--- PASTE YOUR KEY HERE

def hunt_for_threat():
    """
    PARANOID MODE (SCRIPT EXTRACTOR):
    1. Finds suspicious Python processes.
    2. Extracts the ACTUAL .py script path from the command line.
    """
    try:
        suspects = []
        my_pid = os.getpid() 
        
        # IGNORE THESE (The Good Guys)
        aegis_files = ['app.py', 'monitor.py', 'reporter.py', 'ai_hunter.py']

        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cwd']):
            try:
                if proc.info['pid'] == my_pid: continue 

                cmd_list = proc.info['cmdline'] or []
                # Keep original for path extraction, create lower for checks
                cmd_str_lower = " ".join(cmd_list).lower()
                
                # 1. IS IT PYTHON?
                if 'python' in cmd_str_lower:
                    is_aegis = False
                    for safe_file in aegis_files:
                        if safe_file in cmd_str_lower:
                            is_aegis = True
                            break
                    
                    if not is_aegis:
                        script_path = "Unknown Script"
                        # Loop through ORIGINAL args to preserve Case Sensitivity
                        for arg in cmd_list:
                            if arg.endswith('.py') or arg.endswith('.exe'):
                                if 'python' not in arg.lower():
                                    script_path = arg
                                    break
                        
                        suspects.append({
                            "pid": proc.info['pid'],
                            "cmd": cmd_str_lower,
                            "script": script_path, 
                            "path": proc.info['cwd'] or "Unknown"
                        })

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        if not suspects:
            return None, None, None

        # 3. PROMPT: Ask AI to pick the worst one
        client = Groq(api_key=API_KEY)
        
        system_prompt = f"""
        You are a Cyber Defense AI. The system is under attack.
        We found these SUSPICIOUS PROCESSES.
        Pick the one that looks like a user-running script (e.g., in Downloads, Desktop, or temp).
        
        SUSPECTS:
        {json.dumps(suspects)}
        
        RETURN JSON:
        {{
            "suspicious_pid": 1234,
            "reason": "Unknown python script running in background."
        }}
        """

        chat_completion = client.chat.completions.create(
            messages=[{"role": "system", "content": system_prompt}],
            model="llama-3.1-8b-instant", 
            temperature=0.1, 
            response_format={"type": "json_object"}
        )

        result = json.loads(chat_completion.choices[0].message.content)
        target_pid = result.get("suspicious_pid")
        reason = result.get("reason", "Paranoid Pattern Match")
        
        # 4. RESOLVE FINAL PATH
        final_path = "Unknown Path"
        
        if target_pid:
            for s in suspects:
                if s['pid'] == target_pid:
                    final_path = s['script']
                    break
        
        return target_pid, final_path, reason

    except Exception as e:
        print(f"❌ AI HUNT FAILED: {e}")
        return None, None, None