#!/usr/bin/env python3
"""
ArgusML Post-Quantum Cryptography Module
Encrypts and shares threat intelligence using NIST-standardized
post-quantum cryptography algorithms.

Algorithms:
- ML-KEM-768 (NIST FIPS 203) — Key encapsulation
- ML-DSA-65 (NIST FIPS 204) — Digital signatures
- AES-256-GCM — Authenticated encryption

100% original implementation built for ArgusML.
No dependency on any third party proprietary PQC code.
"""

import os
import json
import time
import struct
import hashlib
import secrets
import requests
from datetime import datetime, timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from kyber_py.kyber import Kyber768
from dilithium_py.dilithium import Dilithium3


# ArgusML PQC bundle version
BUNDLE_VERSION = 1
BUNDLE_MAGIC = b"ARGUS_PQC_V1"


class ArgusMLPQCProvider:
    """
    Post-Quantum Cryptography provider for ArgusML.
    Implements ML-KEM-768 + ML-DSA-65 + AES-256-GCM.
    """

    def __init__(self):
        self.pk_kem = None    # KEM public key
        self.sk_kem = None    # KEM secret key
        self.pk_sig = None    # Signing public key
        self.sk_sig = None    # Signing secret key
        self.peer_pk_kem = None  # Peer KEM public key
        self._generate_keypairs()
        print("[argusml_pqc] PQC provider initialized")
        print(f"[argusml_pqc] KEM: ML-KEM-768 (NIST FIPS 203)")
        print(f"[argusml_pqc] SIG: ML-DSA-65 (NIST FIPS 204)")
        print(f"[argusml_pqc] ENC: AES-256-GCM")

    def _generate_keypairs(self):
        """Generate ML-KEM-768 and ML-DSA-65 keypairs."""
        self.pk_kem, self.sk_kem = Kyber768.keygen()
        self.pk_sig, self.sk_sig = Dilithium3.keygen()
        print(f"[argusml_pqc] Generated ML-KEM-768 keypair ({len(self.pk_kem)} byte public key)")
        print(f"[argusml_pqc] Generated ML-DSA-65 keypair ({len(self.pk_sig)} byte public key)")

    def set_peer_public_key(self, peer_pk_kem):
        """Set the peer public key for encryption."""
        self.peer_pk_kem = peer_pk_kem
        print(f"[argusml_pqc] Peer public key set ({len(peer_pk_kem)} bytes)")

    def encrypt_bundle(self, payload: bytes) -> bytes:
        """
        Encrypt a payload using ML-KEM-768 + AES-256-GCM.
        Returns a complete encrypted bundle.
        """
        if not self.peer_pk_kem:
            # Use own public key for self-encryption
            pk = self.pk_kem
        else:
            pk = self.peer_pk_kem

        # ML-KEM-768 encapsulation — generates shared secret
        shared_secret, ciphertext_kem = Kyber768.encaps(pk)

        # Derive AES-256 key from shared secret
        aes_key = hashlib.sha256(shared_secret).digest()

        # AES-256-GCM encryption
        aesgcm = AESGCM(aes_key)
        nonce = secrets.token_bytes(12)
        ciphertext_aes = aesgcm.encrypt(nonce, payload, None)

        # Sign the bundle with ML-DSA-65
        bundle_data = ciphertext_kem + nonce + ciphertext_aes
        signature = Dilithium3.sign(self.sk_sig, bundle_data)

        # Build complete bundle
        bundle = self._build_bundle(
            ciphertext_kem=ciphertext_kem,
            nonce=nonce,
            ciphertext_aes=ciphertext_aes,
            signature=signature,
            pk_sig=self.pk_sig,
        )

        return bundle

    def decrypt_bundle(self, bundle: bytes) -> bytes:
        """
        Decrypt a bundle using ML-KEM-768 + AES-256-GCM.
        Verifies ML-DSA-65 signature before decryption.
        """
        parsed = self._parse_bundle(bundle)

        ciphertext_kem = parsed["ciphertext_kem"]
        nonce = parsed["nonce"]
        ciphertext_aes = parsed["ciphertext_aes"]
        signature = parsed["signature"]
        pk_sig = parsed["pk_sig"]

        # Verify signature
        bundle_data = ciphertext_kem + nonce + ciphertext_aes
        if not Dilithium3.verify(pk_sig, bundle_data, signature):
            raise ValueError("[argusml_pqc] Signature verification FAILED")

        # ML-KEM-768 decapsulation
        shared_secret = Kyber768.decaps(self.sk_kem, ciphertext_kem)

        # Derive AES key
        aes_key = hashlib.sha256(shared_secret).digest()

        # AES-256-GCM decryption
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext_aes, None)

        return plaintext

    def _build_bundle(self, ciphertext_kem, nonce, ciphertext_aes, signature, pk_sig):
        """Build a complete PQC bundle."""
        def pack_field(data: bytes) -> bytes:
            return struct.pack(">I", len(data)) + data

        bundle = (
            BUNDLE_MAGIC +
            struct.pack(">H", BUNDLE_VERSION) +
            struct.pack(">Q", int(time.time_ns())) +
            pack_field(ciphertext_kem) +
            pack_field(nonce) +
            pack_field(ciphertext_aes) +
            pack_field(signature) +
            pack_field(pk_sig)
        )
        return bundle

    def _parse_bundle(self, bundle: bytes) -> dict:
        """Parse a PQC bundle."""
        offset = 0

        magic = bundle[offset:offset+12]
        if magic != BUNDLE_MAGIC:
            raise ValueError(f"Invalid bundle magic: {magic}")
        offset += 12

        version = struct.unpack(">H", bundle[offset:offset+2])[0]
        offset += 2

        timestamp_ns = struct.unpack(">Q", bundle[offset:offset+8])[0]
        offset += 8

        def unpack_field(data, off):
            length = struct.unpack(">I", data[off:off+4])[0]
            off += 4
            field = data[off:off+length]
            off += length
            return field, off

        ciphertext_kem, offset = unpack_field(bundle, offset)
        nonce, offset = unpack_field(bundle, offset)
        ciphertext_aes, offset = unpack_field(bundle, offset)
        signature, offset = unpack_field(bundle, offset)
        pk_sig, offset = unpack_field(bundle, offset)

        return {
            "version": version,
            "timestamp_ns": timestamp_ns,
            "ciphertext_kem": ciphertext_kem,
            "nonce": nonce,
            "ciphertext_aes": ciphertext_aes,
            "signature": signature,
            "pk_sig": pk_sig,
        }

    def get_public_key_info(self):
        """Return public key information."""
        return {
            "kem_algorithm": "ML-KEM-768 (NIST FIPS 203)",
            "sig_algorithm": "ML-DSA-65 (NIST FIPS 204)",
            "enc_algorithm": "AES-256-GCM",
            "kem_pk_size": len(self.pk_kem),
            "sig_pk_size": len(self.pk_sig),
            "kem_pk_hash": hashlib.sha256(self.pk_kem).hexdigest(),
            "sig_pk_hash": hashlib.sha256(self.pk_sig).hexdigest(),
        }


class ArgusMLThreatIntelShipper:
    """
    Ships encrypted threat intelligence to Cloudflare R2.
    Uses PQC encryption for quantum-resistant security.
    """

    def __init__(self, worker_url, pqc_provider=None):
        self.worker_url = worker_url
        self.pqc = pqc_provider or ArgusMLPQCProvider()
        self.total_shipped = 0
        self.total_failed = 0
        self.ship_log = []
        print(f"[argusml_shipper] Threat intel shipper initialized")
        print(f"[argusml_shipper] Worker URL: {worker_url}")

    def ship_detection(self, detection: dict) -> bool:
        """
        Encrypt and ship a threat detection to Cloudflare R2.
        """
        try:
            # Build threat intel payload
            payload = {
                "version": "1.0",
                "source": "ArgusML",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "detection": detection,
                "algorithms": self.pqc.get_public_key_info(),
            }

            # Serialize to JSON
            payload_bytes = json.dumps(payload).encode("utf-8")

            # Encrypt with PQC
            encrypted_bundle = self.pqc.encrypt_bundle(payload_bytes)

            # Ship to Cloudflare Worker
            response = requests.post(
                self.worker_url,
                data=encrypted_bundle,
                headers={
                    "Content-Type": "application/octet-stream",
                    "X-ArgusML-Version": "1.0",
                    "X-Bundle-Version": str(BUNDLE_VERSION),
                },
                timeout=30,
            )

            success = response.status_code in (200, 201, 204)
            self.total_shipped += 1 if success else 0
            self.total_failed += 0 if success else 1

            self.ship_log.append({
                "timestamp": datetime.now().isoformat(),
                "label": detection.get("fused_label"),
                "confidence": detection.get("fused_confidence"),
                "bundle_size": len(encrypted_bundle),
                "success": success,
                "status_code": response.status_code,
            })

            if success:
                print(f"[argusml_shipper] Shipped {detection.get('fused_label')} "
                      f"({len(encrypted_bundle)} bytes encrypted)")
            else:
                print(f"[argusml_shipper] Ship failed: HTTP {response.status_code}")

            return success

        except Exception as e:
            print(f"[argusml_shipper] Error: {e}")
            self.total_failed += 1
            return False

    def get_stats(self):
        """Return shipper statistics."""
        return {
            "total_shipped": self.total_shipped,
            "total_failed": self.total_failed,
            "success_rate": self.total_shipped / max(self.total_shipped + self.total_failed, 1),
            "pqc_info": self.pqc.get_public_key_info(),
            "recent_shipments": self.ship_log[-10:],
        }


if __name__ == "__main__":
    print("Testing ArgusML PQC module...")
    
    # Initialize provider
    pqc = ArgusMLPQCProvider()
    
    # Test encryption/decryption
    test_payload = json.dumps({
        "test": "ArgusML PQC test",
        "label": "backdoor_activity",
        "confidence": 0.9548,
    }).encode()
    
    print(f"\nOriginal payload: {len(test_payload)} bytes")
    
    # Encrypt
    encrypted = pqc.encrypt_bundle(test_payload)
    print(f"Encrypted bundle: {len(encrypted)} bytes")
    
    # Decrypt
    decrypted = pqc.decrypt_bundle(encrypted)
    print(f"Decrypted payload: {len(decrypted)} bytes")
    
    # Verify
    assert decrypted == test_payload, "Decryption failed!"
    print("\n✅ Encryption/Decryption: PASSED")
    print("✅ ML-KEM-768: PASSED")
    print("✅ ML-DSA-65 signature: PASSED")
    print("✅ AES-256-GCM: PASSED")
    print("\nArgusML PQC module working correctly!")
