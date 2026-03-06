# Aegis: AI-Powered Ransomware Defense System
**3rd Place Winner @Code Craft Chase 2.0 2026**

Aegis is an autonomous Endpoint Detection and Response (EDR) platform. It bypasses traditional signature-based antivirus by using behavioral mathematics and Generative AI to detect, neutralize, and reverse ransomware attacks in real-time.

## Core Detection Mechanisms

* **Shannon Entropy Analysis:** Calculates file randomness to detect mass-encryption. Plaintext has low entropy, while encrypted data approaches the maximum limit of 8.0. 

$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$

If the entropy value H(X) spikes above 7.9, Aegis triggers an instant lockdown.
* **Honeypot Traps:** Decoy system files (e.g., `config.sys`). Any interaction by a non-system process triggers a 100% confidence alert.
* **Header Integrity Checks:** Detects "Zero-Day" wipers that corrupt file headers (Magic Bytes) to render data unrecoverable without triggering standard encryption alerts.

## Automated Response & Recovery

* **Network Air-Gap:** Physically severs network adapters via `netsh` to halt data exfiltration.
* **Assassin Module:** Identifies the malicious Process ID (PID) via `psutil` and terminates it instantly.
* **Shadow Vault:** Maintains a hidden, real-time backup for instant file restoration.
* **AI Forensics:** Uses the Groq Cloud API (Llama 3.1) to generate automated incident reports mapped to MITRE ATT&CK frameworks.

## Tech Stack

* **Backend / Telemetry:** Python 3, Flask, `psutil`, `watchdog`
* **AI Engine:** Groq Cloud API (Llama 3.1 8b)
* **Frontend:** Vanilla JavaScript, HTML/CSS, Chart.js

## Installation & Setup

**Prerequisites:** Windows OS (Admin privileges required), Python 3.x, Groq API Key.

1. Clone the repository and install dependencies:
    ```bash
    git clone [https://github.com/Raatwik/AEGIS.git](https://github.com/Raatwik/AEGIS.git)
    cd AEGIS
    pip install -r requirements.txt
    ```

2. Create a `.env` file in the root directory and add your API key:
    ```text
    GROQ_API_KEY=your_actual_key_here
    ```

## Usage

1. **Start Aegis:** Run `python app.py` as Administrator.
2. **Access Dashboard:** Open `http://127.0.0.1:5000` in your web browser.
3. **Launch Attack:** Open a new terminal and run `python simulate_attack.py`. Select an attack vector.
4. **Observe & Remediate:** Watch the dashboard detect the threat, sever the network, and allow you to restore the files.


## Contributors
-Sasmit(https://github.com/sasmit-1) - Lead Backend
-Raatwik(https://github.com/Raatwik) - PID Implementation
-Mahi(https://github.com/daiyu5676) - Research & Hueristics + Presentation
-Ekaksh(https://github.com/Ekaksh1) - Research & Heuristics + Presentation