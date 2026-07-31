"""Utility functions for parsing OpenSSL PEM format ML-KEM keys.

These functions parse PEM-formatted ML-KEM keys and extract the raw key bytes
for use with liboqs-python. Since the cryptography library may not
natively support ML-KEM OIDs, we manually parse the ASN.1 structure.

ML-KEM OIDs (NIST FIPS 203):
  - ML-KEM-512:  2.16.840.1.101.3.4.4.1
  - ML-KEM-768:  2.16.840.1.101.3.4.4.2
  - ML-KEM-1024: 2.16.840.1.101.3.4.4.3
"""
import base64
import os
from typing import Optional, Tuple

# ML-KEM OIDs as byte sequences (DER encoded)
ML_KEM_512_OID = bytes([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01])  # 2.16.840.1.101.3.4.4.1
ML_KEM_768_OID = bytes([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02])  # 2.16.840.1.101.3.4.4.2
ML_KEM_1024_OID = bytes([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x03])  # 2.16.840.1.101.3.4.4.3

ML_KEM_OIDS = {
    ML_KEM_512_OID: "ML-KEM-512",
    ML_KEM_768_OID: "ML-KEM-768",
    ML_KEM_1024_OID: "ML-KEM-1024",
}


def _parse_pem(pem_data: bytes) -> Tuple[str, bytes]:
    """
    Parse PEM data and return the header type and DER-encoded content.
    
    Args:
        pem_data: Raw PEM file contents
        
    Returns:
        Tuple of (key_type, der_bytes) where key_type is e.g. "PRIVATE KEY"
    """
    lines = pem_data.decode('utf-8').strip().split('\n')
    
    # Find BEGIN and END markers
    begin_marker = None
    end_marker = None
    key_type = ""
    base64_lines = []
    in_content = False
    
    for line in lines:
        line = line.strip()
        if line.startswith('-----BEGIN ') and line.endswith('-----'):
            begin_marker = line
            key_type = line[11:-5]  # Extract "PRIVATE KEY" from "-----BEGIN PRIVATE KEY-----"
            in_content = True
        elif line.startswith('-----END ') and line.endswith('-----'):
            end_marker = line
            in_content = False
        elif in_content and line:
            base64_lines.append(line)
    
    if not begin_marker or not end_marker:
        raise ValueError("Invalid PEM format: missing BEGIN or END markers")
    
    # Decode base64 content
    base64_content = ''.join(base64_lines)
    der_bytes = base64.b64decode(base64_content)
    
    return key_type, der_bytes


def _parse_der_length(data: bytes, offset: int) -> Tuple[int, int]:
    """
    Parse a DER length field starting at offset.
    
    Returns:
        Tuple of (length, bytes_consumed)
    """
    if data[offset] < 0x80:
        # Short form: length is in the byte itself
        return data[offset], 1
    else:
        # Long form: first byte indicates number of length bytes
        num_length_bytes = data[offset] & 0x7F
        length = 0
        for i in range(num_length_bytes):
            length = (length << 8) | data[offset + 1 + i]
        return length, 1 + num_length_bytes


def _extract_ml_kem_public_key(der_bytes: bytes) -> bytes:
    """
    Extract raw ML-KEM public key bytes from a SubjectPublicKeyInfo DER structure.
    
    SubjectPublicKeyInfo ::= SEQUENCE {
        algorithm AlgorithmIdentifier,
        subjectPublicKey BIT STRING
    }
    
    AlgorithmIdentifier ::= SEQUENCE {
        algorithm OBJECT IDENTIFIER,
        parameters ANY DEFINED BY algorithm OPTIONAL
    }
    """
    offset = 0
    
    # Parse outer SEQUENCE
    if der_bytes[offset] != 0x30:
        raise ValueError("Expected SEQUENCE tag for SubjectPublicKeyInfo")
    offset += 1
    seq_len, consumed = _parse_der_length(der_bytes, offset)
    offset += consumed
    
    # Parse AlgorithmIdentifier SEQUENCE
    if der_bytes[offset] != 0x30:
        raise ValueError("Expected SEQUENCE tag for AlgorithmIdentifier")
    offset += 1
    algo_len, consumed = _parse_der_length(der_bytes, offset)
    offset += consumed
    algo_end = offset + algo_len
    
    # Parse OID
    if der_bytes[offset] != 0x06:
        raise ValueError("Expected OBJECT IDENTIFIER tag")
    offset += 1
    oid_len, consumed = _parse_der_length(der_bytes, offset)
    offset += consumed
    oid_bytes = der_bytes[offset:offset + oid_len]
    offset += oid_len
    
    # Verify it's an ML-KEM OID
    if oid_bytes not in ML_KEM_OIDS:
        raise ValueError(f"Unknown OID, not an ML-KEM key: {oid_bytes.hex()}")
    
    # Skip to end of AlgorithmIdentifier (may have NULL parameters)
    offset = algo_end
    
    # Parse BIT STRING containing the public key
    if der_bytes[offset] != 0x03:
        raise ValueError("Expected BIT STRING tag for public key")
    offset += 1
    bitstring_len, consumed = _parse_der_length(der_bytes, offset)
    offset += consumed
    
    # First byte of BIT STRING is the number of unused bits (should be 0)
    unused_bits = der_bytes[offset]
    if unused_bits != 0:
        raise ValueError(f"Unexpected unused bits in public key BIT STRING: {unused_bits}")
    offset += 1
    
    # The rest is the raw public key
    raw_key = der_bytes[offset:offset + bitstring_len - 1]
    return raw_key


def _extract_ml_kem_private_key(der_bytes: bytes) -> bytes:
    """
    Extract raw ML-KEM private key bytes from a PKCS#8 PrivateKeyInfo
    DER structure.

    Handles these provider representations:

      1. Raw liboqs secret key
      2. Secret key followed by public key
      3. Nested OCTET STRING
      4. SEQUENCE containing seed and expanded private key
    """
    offset = 0

    # Parse outer SEQUENCE.
    if der_bytes[offset] != 0x30:
        raise ValueError("Expected SEQUENCE tag for PrivateKeyInfo")

    offset += 1
    _, consumed = _parse_der_length(der_bytes, offset)
    offset += consumed

    # Parse version INTEGER.
    if der_bytes[offset] != 0x02:
        raise ValueError("Expected INTEGER tag for version")

    offset += 1
    version_len, consumed = _parse_der_length(der_bytes, offset)
    offset += consumed
    offset += version_len

    # Parse AlgorithmIdentifier SEQUENCE.
    if der_bytes[offset] != 0x30:
        raise ValueError("Expected SEQUENCE tag for AlgorithmIdentifier")

    offset += 1
    algo_len, consumed = _parse_der_length(der_bytes, offset)
    offset += consumed
    algo_end = offset + algo_len

    # Parse algorithm OID.
    if der_bytes[offset] != 0x06:
        raise ValueError("Expected OBJECT IDENTIFIER tag")

    offset += 1
    oid_len, consumed = _parse_der_length(der_bytes, offset)
    offset += consumed
    oid_bytes = der_bytes[offset:offset + oid_len]

    if oid_bytes not in ML_KEM_OIDS:
        raise ValueError(
            f"Unknown OID, not an ML-KEM key: {oid_bytes.hex()}"
        )

    algorithm = ML_KEM_OIDS[oid_bytes]

    # Expected raw liboqs key sizes.
    key_sizes = {
        "ML-KEM-512": {
            "secret": 1632,
            "public": 800,
        },
        "ML-KEM-768": {
            "secret": 2400,
            "public": 1184,
        },
        "ML-KEM-1024": {
            "secret": 3168,
            "public": 1568,
        },
    }

    expected_secret_length = key_sizes[algorithm]["secret"]
    expected_public_length = key_sizes[algorithm]["public"]
    expected_combined_length = (
        expected_secret_length + expected_public_length
    )

    # Skip to the end of AlgorithmIdentifier.
    offset = algo_end

    # Parse PKCS#8 privateKey OCTET STRING.
    if der_bytes[offset] != 0x04:
        raise ValueError("Expected OCTET STRING tag for private key")

    offset += 1
    octet_len, consumed = _parse_der_length(der_bytes, offset)
    offset += consumed

    raw_key = der_bytes[offset:offset + octet_len]

    if len(raw_key) != octet_len:
        raise ValueError(
            "Truncated private-key OCTET STRING: "
            f"expected {octet_len}, got {len(raw_key)}"
        )

    # Some encoders add a nested OCTET STRING wrapper.
    if raw_key and raw_key[0] == 0x04:
        inner_offset = 1
        inner_len, consumed = _parse_der_length(
            raw_key,
            inner_offset,
        )
        inner_offset += consumed

        inner_end = inner_offset + inner_len

        if inner_end == len(raw_key):
            raw_key = raw_key[inner_offset:inner_end]

    # Some OpenSSL encodings use:
    #
    # SEQUENCE {
    #     OCTET STRING seed,
    #     OCTET STRING expanded-private-key
    # }
    if raw_key and raw_key[0] == 0x30:
        inner_offset = 1
        seq_len, consumed = _parse_der_length(
            raw_key,
            inner_offset,
        )
        inner_offset += consumed
        sequence_end = inner_offset + seq_len

        if sequence_end > len(raw_key):
            raise ValueError("Truncated inner private-key SEQUENCE")

        octet_values = []

        while inner_offset < sequence_end:
            if raw_key[inner_offset] != 0x04:
                break

            inner_offset += 1
            value_len, consumed = _parse_der_length(
                raw_key,
                inner_offset,
            )
            inner_offset += consumed

            value_end = inner_offset + value_len

            if value_end > sequence_end:
                raise ValueError(
                    "Truncated OCTET STRING in private-key SEQUENCE"
                )

            octet_values.append(
                raw_key[inner_offset:value_end]
            )

            inner_offset = value_end

        # Prefer a candidate with exactly the expected secret-key size.
        for value in octet_values:
            if len(value) == expected_secret_length:
                raw_key = value
                break
        else:
            # A provider may place secret || public in one field.
            for value in octet_values:
                if len(value) == expected_combined_length:
                    raw_key = value
                    break

    # liboqs-compatible raw secret key.
    if len(raw_key) == expected_secret_length:
        return raw_key

    # oqs-provider representation:
    #
    #   secret key || public key
    #
    # ML-KEM-1024:
    #   3168 + 1568 = 4736 bytes
    if len(raw_key) == expected_combined_length:
        secret_key = raw_key[:expected_secret_length]
        appended_public_key = raw_key[expected_secret_length:]

        if len(appended_public_key) != expected_public_length:
            raise ValueError(
                f"Invalid appended {algorithm} public-key length: "
                f"got {len(appended_public_key)}, "
                f"expected {expected_public_length}"
            )

        return secret_key

    raise ValueError(
        f"Unsupported {algorithm} private-key representation: "
        f"got {len(raw_key)} bytes; expected "
        f"{expected_secret_length} bytes or "
        f"{expected_combined_length} bytes"
    )

def load_kem_public_key_from_pem(pem_path: str) -> bytes:
    """
    Load an ML-KEM public key from an OpenSSL PEM file.
    
    Args:
        pem_path: Path to the PEM file containing the public key
                  (-----BEGIN PUBLIC KEY-----)
        
    Returns:
        Raw public key bytes suitable for use with liboqs-python KEM APIs
        
    Raises:
        FileNotFoundError: If the PEM file does not exist
        ValueError: If the key is not a valid ML-KEM public key
    """
    if not os.path.exists(pem_path):
        raise FileNotFoundError(f"Public key file not found: {pem_path}")
    
    with open(pem_path, "rb") as f:
        pem_data = f.read()
    
    key_type, der_bytes = _parse_pem(pem_data)
    
    if key_type != "PUBLIC KEY":
        raise ValueError(f"Expected 'PUBLIC KEY' but got '{key_type}'")
    
    return _extract_ml_kem_public_key(der_bytes)


def load_kem_private_key_from_pem(pem_path: str, password: Optional[bytes] = None) -> bytes:
    """
    Load an ML-KEM private key from an OpenSSL PEM file.
    
    Args:
        pem_path: Path to the PEM file containing the private key
                  (-----BEGIN PRIVATE KEY-----)
        password: Currently unused (encrypted keys not supported)
        
    Returns:
        Raw private key bytes suitable for use with liboqs-python KEM APIs
        
    Raises:
        FileNotFoundError: If the PEM file does not exist
        ValueError: If the key is not a valid ML-KEM private key
    """
    if not os.path.exists(pem_path):
        raise FileNotFoundError(f"Private key file not found: {pem_path}")
    
    if password is not None:
        raise NotImplementedError("Encrypted private keys are not yet supported")
    
    with open(pem_path, "rb") as f:
        pem_data = f.read()
    
    key_type, der_bytes = _parse_pem(pem_data)
    
    if key_type not in ("PRIVATE KEY", "ML-KEM PRIVATE KEY"):
        raise ValueError(f"Expected 'PRIVATE KEY' but got '{key_type}'")
    
    return _extract_ml_kem_private_key(der_bytes)
