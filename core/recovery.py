import os
import shutil
import time

class ShadowVault:
    def __init__(self, monitored_path):
        self.monitored_path = monitored_path
        self.vault_path = os.path.join(os.path.dirname(monitored_path), ".AegisVault")
        
    def create_snapshot(self):
        """
        Creates a 'clean state' backup of the SafeZone.
        """
        if os.path.exists(self.vault_path):
            shutil.rmtree(self.vault_path)
        
        shutil.copytree(self.monitored_path, self.vault_path)
        print(f"🔒 SHADOW VAULT: Snapshot created at {self.vault_path}")

    def restore_snapshot(self):
        """
        Wipes the infected folder and restores from the Vault.
        """
        try:
            print("⏳ INITIATING ROLLBACK PROTOCOL...")
            
            # 1. Wipe Infected Zone
            for filename in os.listdir(self.monitored_path):
                file_path = os.path.join(self.monitored_path, filename)
                try:
                    if os.path.isfile(file_path) or os.path.islink(file_path):
                        os.unlink(file_path)
                    elif os.path.isdir(file_path):
                        shutil.rmtree(file_path)
                except Exception as e:
                    print(f"Failed to delete {file_path}. Reason: {e}")

            # 2. Restore from Vault
            for filename in os.listdir(self.vault_path):
                s = os.path.join(self.vault_path, filename)
                d = os.path.join(self.monitored_path, filename)
                if os.path.isdir(s):
                    shutil.copytree(s, d)
                else:
                    shutil.copy2(s, d)
            
            print("✅ SYSTEM RESTORED: All files recovered.")
            return True
        except Exception as e:
            print(f"❌ RESTORE FAILED: {e}")
            return False