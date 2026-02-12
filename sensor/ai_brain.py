import os
import sys
import pickle
import math
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

# Robust Path Handling
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "aegis_model.pkl")

# --- NEW: RANSOMWARE RENAME HEURISTICS ---
class RenameHeuristic:
    """
    Analyzes file renaming patterns to detect Ransomware behavior.
    MITRE ATT&CK: T1486 (Data Encrypted for Impact)
    """
    
    # Common ransomware extensions
    SUSPICIOUS_EXTENSIONS = {
        '.locked', '.enc', '.crypt', '.cry', '.micro', 
        '.zepto', '.wry', '.odin', '.locky', '.crypted',
        '.dark', '.kratos', '.fucked', '.exx'
    }

    @staticmethod
    def calculate_shannon_entropy(data):
        """Calculates the randomness of a string (used for extension names)."""
        if not data: return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    @staticmethod
    def is_malicious_rename(src_path, dest_path):
        """
        Returns (True, Reason) if the rename looks like ransomware.
        """
        filename_old = os.path.basename(src_path)
        filename_new = os.path.basename(dest_path)
        
        _, ext_old = os.path.splitext(filename_old)
        _, ext_new = os.path.splitext(filename_new)
        ext_new = ext_new.lower()

        # RULE 1: Double Extension (The "Append" Attack)
        # Example: image.jpg -> image.jpg.fun
        if filename_new.startswith(filename_old) and len(filename_new) > len(filename_old):
            return True, f"Double extension detected: {filename_new}"

        # RULE 2: Known Malicious Extension
        # Example: document.docx -> document.locked
        if ext_new in RenameHeuristic.SUSPICIOUS_EXTENSIONS:
            return True, f"Known ransomware extension: {ext_new}"

        # RULE 3: Extension Entropy (Random Characters)
        # Example: resume.pdf -> resume.pdf.a7x9bb2 (High entropy extension)
        # We only check if extension is long enough (4+ chars) to be significant
        if len(ext_new) > 4:
            # Ignore common temp files
            if "tmp" in ext_new or "temp" in ext_new or "bak" in ext_new:
                return False, None
            
            ent = RenameHeuristic.calculate_shannon_entropy(ext_new)
            if ent > 3.5:
                return True, f"High entropy extension ({ent:.2f}): {ext_new}"

        return False, None

# --- EXISTING ML MODEL LOGIC ---

def train_new_model():
    print(f"--- TRAINING AI MODEL ---")
    
    # 1. Synthetic Data Generation
    safe_data = {
        'entropy': np.random.uniform(1.0, 4.5, 500),
        'rate': np.random.randint(0, 5, 500),
        'honeypot': [0] * 500,
        'label': 0 
    }
    malware_data = {
        'entropy': np.random.uniform(7.0, 8.0, 500),
        'rate': np.random.randint(5, 100, 500),
        'honeypot': [0] * 500,
        'label': 1
    }
    trap_data = {
        'entropy': np.random.uniform(0.0, 8.0, 100),
        'rate': np.random.randint(0, 100, 100),
        'honeypot': [1] * 100,
        'label': 1
    }

    df = pd.concat([pd.DataFrame(safe_data), pd.DataFrame(malware_data), pd.DataFrame(trap_data)])

    # 2. Train
    clf = RandomForestClassifier(n_estimators=100)
    clf.fit(df[['entropy', 'rate', 'honeypot']], df['label'])

    # 3. Save
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(clf, f)
    print(f"✅ Model Saved: {MODEL_PATH}")

def predict_threat(entropy, rate, honeypot):
    if not os.path.exists(MODEL_PATH):
        train_new_model()
    
    with open(MODEL_PATH, 'rb') as f:
        model = pickle.load(f)
    
    input_data = pd.DataFrame(
        [[entropy, rate, honeypot]], 
        columns=['entropy', 'rate', 'honeypot']
    )

    confidence = model.predict_proba(input_data)[0][1]
    is_malware = confidence > 0.5
    return is_malware, confidence * 100

if __name__ == "__main__":
    train_new_model()