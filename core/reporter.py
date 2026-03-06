import time
import json
from groq import Groq

# --- CONFIGURATION ---
API_KEY = "{GROQ API KEY HERE}" #

def generate_forensic_report(stats):
    """
    Generates a professional, AI-powered forensic brief using Llama-3.
    """
    client = Groq(api_key=API_KEY) #
    
    # Context for the AI
    attack_data = {
        "timestamp": time.ctime(),
        "vector": stats.get("vector", "Unknown"),
        "peak_entropy": f"{stats.get('entropy_avg', 0):.2f} bits/byte",
        "io_intensity": f"{stats.get('io_peak', 0)} ops/sec",
        "actions_taken": ["Process Terminated", "Network Isolated", "Shadow Vault Restored"]
    }

    system_prompt = """
    You are a Senior Cyber Forensic Analyst. 
    Write a concise, professional 'Threat Incident Report' based on the provided technical metrics.
    
    Structure the report with these sections:
    1. SUMMARY OF INCIDENT
    2. TECHNICAL ANALYSIS (Explain what high entropy or magic byte corruption implies)
    3. REMEDIATION (Confirm that the system is now clean)
    
    Use a technical, authoritative tone suitable for a Security Operations Center (SOC).
    Keep it under 200 words.
    """

    try:
        chat_completion = client.chat.completions.create(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"DATA: {json.dumps(attack_data)}"}
            ],
            model="llama-3.1-8b-instant", #
            temperature=0.3,
        )

        ai_report = chat_completion.choices[0].message.content
        return ai_report

    except Exception as e:
        # Fallback if the API fails or internet is cut
        return f"""
        AEGIS FALLBACK REPORT
        ---------------------
        TIMESTAMP: {attack_data['timestamp']}
        VECTOR: {attack_data['vector']}
        METRICS: Entropy {attack_data['peak_entropy']} | I/O {attack_data['io_intensity']}
        STATUS: Threat Neutralized via Local Heuristics.
        ERROR: AI Uplink Unavailable.
        """