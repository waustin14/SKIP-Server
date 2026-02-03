import os
import json
import base64
import threading
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class SecureKeyStore:
    """
    A simple, thread-safe, encrypted file-based key store.
    
    The store is a JSON file encrypted with a master key derived from an
    environment variable. This provides a good balance of security and simplicity.
    """
    def __init__(self, filepath: str, master_key_env_var: str = "KEYSTORE_MASTER_KEY"):
        self._filepath = filepath
        self._lock = threading.Lock()
        
        # 1. Get the master passphrase from the environment.
        master_passphrase = os.environ.get(master_key_env_var)
        if not master_passphrase:
            raise ValueError(f"CRITICAL: Master key environment variable '{master_key_env_var}' not set.")
            
        # 2. Derive a strong encryption key from the passphrase using PBKDF2.
        # This protects against weak passphrases. A salt is used to prevent rainbow table attacks.
        # In a real app, the salt should be stored securely and be unique. For simplicity here,
        # we'll use a fixed salt, but a better approach is to store it alongside the encrypted data.
        salt = b'salt_for_skip_app_' 
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000, # NIST recommended minimum for PBKDF2
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_passphrase.encode()))
        self._fernet = Fernet(key)
        
        # 3. Load the store from disk.
        self._keystore = self._load()

    def _load(self) -> dict:
        """Loads and decrypts the keystore from the file."""
        try:
            with open(self._filepath, 'rb') as f:
                encrypted_data = f.read()
            
            if not encrypted_data:
                return {} # File is empty, start fresh

            decrypted_data = self._fernet.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode('utf-8'))
        except FileNotFoundError:
            return {} # No store file yet, start with an empty one.
        except Exception as e:
            raise IOError(f"Failed to load or decrypt the keystore: {e}")

    def _save(self):
        """Encrypts and saves the current keystore to the file."""
        with self._lock:
            data_bytes = json.dumps(self._keystore).encode('utf-8')
            encrypted_data = self._fernet.encrypt(data_bytes)
            with open(self._filepath, 'wb') as f:
                f.write(encrypted_data)

    def set(self, key_id: str, secret_value: str):
        """Adds or updates a secret in the store."""
        with self._lock:
            self._keystore[key_id] = secret_value
        self._save()

    def get(self, key_id: str) -> str | None:
        """Retrieves a secret from the store."""
        with self._lock:
            return self._keystore.get(key_id)

    def delete(self, key_id: str) -> bool:
        """Deletes a secret from the store."""
        with self._lock:
            if key_id in self._keystore:
                del self._keystore[key_id]
        self._save()
        # Confirm deletion
        return key_id not in self._keystore.keys()
    
    def list_keys(self) -> list[str]:
        """Returns a list of all key IDs in the store."""
        with self._lock:
            return list(self._keystore.keys())