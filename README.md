🛡️ Aegis Ransomware Defense System
Autonomous. Intelligent. Instant. An advanced endpoint protection platform that detects, neutralizes, and reverses ransomware attacks in real-time using entropy analysis and Generative AI forensics.

🚨 The Problem
Traditional antivirus relies on "signatures" (knowing what a virus looks like). Modern ransomware is polymorphic—it changes every time. Aegis is different. It ignores signatures and analyzes behavior (mathematics).

⚡ Key Features
1. Multi-Vector Detection Engine
🍯 Honeypot Traps: Decoy system files (config.sys) that trigger an instant lockdown if touched.

Virology Math (Shannon Entropy): Detects the mathematical "noise" of encryption. If a text file's entropy spikes > 7.9, it's being encrypted.

🛑 Header Integrity Check: Detects "Zero-Day" wipers that corrupt file headers (Magic Bytes) without full encryption.

2. Active Defense (The "Kill Switch")
Network Air-Gap: Physically disables the Wi-Fi adapter via netsh to prevent data exfiltration (stealing keys).

Assassin Module: Identifies the malicious process ID (PID) and terminates it instantly.

3. "Time Travel" Recovery
Shadow Vault: Maintains a hidden, real-time backup of the protected directory.

Instant Rollback: One-click restoration wipes the infection and restores files to their pre-attack state.

4. Generative AI Forensics (Powered by Groq)
Automated Reporting: Generates a professional "CISO-Level" incident report in seconds.

MITRE ATT&CK Mapping: Automatically maps the attack vector to industry standards:

T1059: Command Execution (Honeypot Trigger)

T1486: Data Encrypted for Impact (High Entropy)

T1027: Obfuscated Files (Header Mismatch)

🛠️ Architecture
Sensor (Watchdog): Monitors file system I/O events in real-time.

Brain (Heuristic Engine): Calculates entropy and checks file headers against known safe types.

Reflex (Assassin): Executes the kill command and network severing.

Analyst (Groq AI): Ingests attack logs and produces the forensic report.

🚀 Installation & Setup
Prerequisites
Python 3.x

Windows OS (Required for netsh network commands)

Administrator Privileges (to control network adapters)

1. Clone the Repository
Bash
git clone https://github.com/yourusername/Aegis-Ransomware-Defense.git
cd Aegis-Ransomware-Defense
2. Install Dependencies
Bash
pip install flask watchdog groq
3. Configure API Key
Open core/reporter.py and add your Groq API key (free at console.groq.com):

Python
# core/reporter.py
API_KEY = "gsk_..."
🎮 Usage (The Demo)
Step 1: Start the Aegis Brain
Run the main application. Must be run as Administrator to allow network severing.

Bash
python app.py
Open your browser to: http://127.0.0.1:5000

Status should be GREEN (SECURE).

Step 2: Launch the Attack Simulator
Open a second terminal and run the simulator tool.

Bash
python simulate_attack.py
Step 3: Choose Your Attack
Select an option from the menu:

Option 2 (Ransomware): Triggers Honeypot & Encryption.

Option 3 (Stealth): Triggers Entropy Detection (Math-based).

Option 4 (Zero-Day): Triggers Header Corruption.

Step 4: Watch the Defense
Dashboard turns RED: "Network Severed."

Click "ELIMINATE THREAT & RESTORE".

Click "GENERATE AI FORENSIC REPORT" to see the analysis.

📸 Screenshots
The Secure Dashboard
(Place your image_5a911f.png here)

The "Red Screen" (Attack Detected)
(Place your image_e0737f.png here)

AI Forensic Report (MITRE Analysis)
(Place your image_59c360.jpg here)

📂 Project Structure
Plaintext
Aegis/
├── SafeZone/            # The folder being protected
├── core/
│   ├── network_kill.py  # Wi-Fi & Process termination logic
│   ├── recovery.py      # Shadow Vault backup system
│   └── reporter.py      # Groq AI integration
├── sensor/
│   ├── ai_brain.py      # Entropy & Header math logic
│   └── monitor.py       # File system watchdog
├── ui/                  # HTML/CSS Dashboard
├── app.py               # Main Flask Server
└── simulate_attack.py   # Malware Simulator
⚠️ Disclaimer
This software is for educational purposes only. The "Simulator" creates files that look encrypted but uses reversible XOR logic. Do not use the defense modules on critical production systems without testing, as the "Kill Switch" effectively disables internet access.