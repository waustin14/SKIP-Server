import os
from typing import Optional

from pem_utils import load_kem_private_key_from_pem


class SecureKeyLoader:
    """
    A context manager to securely load a private key for a temporary operation
    and overwrite it in memory upon completion.
    
    Expects the private key to be in OpenSSL PEM format (-----BEGIN PRIVATE KEY-----).
    """
    def __init__(self, key_path: str):
        if not os.path.exists(key_path):
            raise FileNotFoundError(f"Key file not found at: {key_path}")
        self._key_path = key_path
        self._key_material: Optional[bytearray] = None

    def __enter__(self) -> bytes:
        """
        Called when entering the 'with' block.
        Loads the PEM-formatted private key into a mutable bytearray and returns it.
        """
        print("-> Entering context: Loading private key from PEM into memory...")
        # Load the raw key bytes from the PEM file
        raw_key_bytes = load_kem_private_key_from_pem(self._key_path)
        # Store in a mutable bytearray so we can overwrite it later
        self._key_material = bytearray(raw_key_bytes)
        return bytes(self._key_material)

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Called when exiting the 'with' block.
        This is where the cleanup happens. It is ALWAYS called.
        """
        print("<- Exiting context: Overwriting private key in memory...")
        if self._key_material:
            # Overwrite every byte of the key with zero
            for i in range(len(self._key_material)):
                self._key_material[i] = 0
            # Clear the reference
            del self._key_material
        
        # Returning False (or None) will re-raise any exception that occurred
        # inside the 'with' block, which is standard behavior.
        return False
