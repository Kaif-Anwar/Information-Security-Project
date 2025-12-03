#!/usr/bin/env python3
"""
MITM Attack Demonstration Script (Requirement 7)

This script is SELF-CONTAINED and runs entirely in Python.
It does NOT depend on your backend, so you can run it even if the server is down.

It demonstrates two scenarios:
 1) **Vulnerable DH/ECDH without signatures**:
    - Alice and Bob perform a naïve ECDH key exchange.
    - Mallory (MITM) intercepts and replaces public keys.
    - Result: Mallory establishes two shared secrets (with Alice and Bob) and can decrypt.

 2) **Secure DH/ECDH with digital signatures (like your final system)**:
    - Alice and Bob each have long‑term ECDSA signing keys.
    - They sign their ECDH ephemeral public keys + metadata.
    - Mallory again tries to intercept and replace keys.
    - Result: Signature verification fails; MITM is detected and blocked.

You can run this script with:
  python attackerscript.py

Use the console output + diagrams in your report to satisfy Requirement 7.
"""

import os
import time
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

# Utility helpers -----------------------------------------------------------

class Colors:
    reset = '\033[0m'
    green = '\033[32m'
    red = '\033[31m'
    yellow = '\033[33m'
    blue = '\033[34m'
    cyan = '\033[36m'
    magenta = '\033[35m'

def log(message, color=Colors.reset):
    print(f"{color}{message}{Colors.reset}")

def section(title):
    log('\n' + '=' * 70, Colors.cyan)
    log(title, Colors.cyan)
    log('=' * 70, Colors.cyan)

def sub_section(title):
    log('\n' + '-' * 70, Colors.blue)
    log(title, Colors.blue)
    log('-' * 70, Colors.blue)

def to_hex(buf, max_len=32):
    hex_str = buf.hex()
    if len(hex_str) <= max_len:
        return hex_str
    return f"{hex_str[:max_len]}... ({len(buf)} bytes)"

# Cryptographic primitives --------------------------------------------------

def generate_ecdh_key_pair():
    """Generate an ECDH key pair using NIST P-256 curve."""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def derive_shared_secret(our_private_key, other_public_key):
    """Derive shared secret using ECDH."""
    shared_secret = our_private_key.exchange(ec.ECDH(), other_public_key)
    return shared_secret

def generate_ecdsa_key_pair():
    """Generate an ECDSA key pair for signing (NIST P-256)."""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return public_key, private_key

def sign_message(private_key, message):
    """Sign a message using ECDSA with SHA256."""
    if isinstance(message, str):
        message = message.encode('utf-8')
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(public_key, message, signature_base64):
    """Verify a signature using ECDSA with SHA256."""
    if isinstance(message, str):
        message = message.encode('utf-8')
    try:
        signature = base64.b64decode(signature_base64)
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False

def hkdf_sha256(ikm, info=b'e2ee-session-key', salt=None):
    """Derive a key using HKDF-SHA256."""
    # Use deterministic salt derived from IKM if not provided (for demo purposes)
    # In real system, salt would be exchanged or derived deterministically
    if salt is None:
        # Use first 32 bytes of SHA256(ikm) as deterministic salt for demo
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(ikm)
        salt = digest.finalize()[:32]
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
        backend=default_backend()
    )
    key = hkdf.derive(ikm)
    return {'key': key, 'salt': salt}

def public_key_to_base64(public_key):
    """Serialize public key to base64 string."""
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(public_bytes).decode('utf-8')

# Scenario 1: DH/ECDH without signatures (vulnerable) ----------------------

def scenario_without_signatures():
    section('Scenario 1: MITM Attack on ECDH WITHOUT Signatures (VULNERABLE)')

    # Honest keys
    alice_private, alice_public = generate_ecdh_key_pair()
    bob_private, bob_public = generate_ecdh_key_pair()

    sub_section('Honest ECDH (no attacker)')
    honest_secret_alice = derive_shared_secret(alice_private, bob_public)
    honest_secret_bob = derive_shared_secret(bob_private, alice_public)

    log(f"Alice secret: {to_hex(honest_secret_alice)}", Colors.green)
    log(f"Bob   secret: {to_hex(honest_secret_bob)}", Colors.green)
    log(f"Shared secret equal: {honest_secret_alice == honest_secret_bob}", Colors.green)

    # MITM: Mallory intercepts and replaces public keys
    sub_section('Introducing Mallory (MITM) – No Signatures')
    mallory_to_alice_private, mallory_to_alice_public = generate_ecdh_key_pair()
    mallory_to_bob_private, mallory_to_bob_public = generate_ecdh_key_pair()

    # Alice thinks she's using Bob's pub, but it's actually Mallory's
    alice_shared_with_mallory = derive_shared_secret(alice_private, mallory_to_alice_public)
    # Bob thinks he's using Alice's pub, but it's actually Mallory's
    bob_shared_with_mallory = derive_shared_secret(bob_private, mallory_to_bob_public)

    # Mallory computes both secrets
    mallory_shared_with_alice = derive_shared_secret(
        mallory_to_alice_private,
        alice_public,
    )
    mallory_shared_with_bob = derive_shared_secret(
        mallory_to_bob_private,
        bob_public,
    )

    log('\nAlice <-> Mallory shared secret:', Colors.yellow)
    log(f"  Alice side  : {to_hex(alice_shared_with_mallory)}", Colors.yellow)
    log(f"  Mallory side: {to_hex(mallory_shared_with_alice)}", Colors.yellow)
    log(
        f"  Equal: {alice_shared_with_mallory == mallory_shared_with_alice}",
        Colors.yellow,
    )

    log('\nBob ↔ Mallory shared secret:', Colors.yellow)
    log(f"  Bob side    : {to_hex(bob_shared_with_mallory)}", Colors.yellow)
    log(f"  Mallory side: {to_hex(mallory_shared_with_bob)}", Colors.yellow)
    log(
        f"  Equal: {bob_shared_with_mallory == mallory_shared_with_bob}",
        Colors.yellow,
    )

    log(
        '\nResult: Alice and Bob do NOT share the same key, but Mallory shares a key with each.',
        Colors.red,
    )
    log(
        '=> Mallory can decrypt, read, and re‑encrypt messages between them. DH without signatures is vulnerable to MITM.',
        Colors.red,
    )

# Scenario 2: DH/ECDH with digital signatures (secure) ---------------------

def scenario_with_signatures():
    section('Scenario 2: ECDH WITH Digital Signatures (MITM Prevented)')

    # Long‑term signing keys (like your User.publicKey.signing)
    alice_sign_public, alice_sign_private = generate_ecdsa_key_pair()
    bob_sign_public, bob_sign_private = generate_ecdsa_key_pair()
    mallory_sign_public, mallory_sign_private = generate_ecdsa_key_pair()  # attacker's own identity

    # Ephemeral ECDH keys for this session
    alice_ecdh_private, alice_ecdh_public = generate_ecdh_key_pair()
    bob_ecdh_private, bob_ecdh_public = generate_ecdh_key_pair()
    mallory_to_alice_private, mallory_to_alice_public = generate_ecdh_key_pair()
    mallory_to_bob_private, mallory_to_bob_public = generate_ecdh_key_pair()

    alice_id = 'Alice'
    bob_id = 'Bob'
    mallory_id = 'Mallory'

    sub_section('Honest Signed Key Exchange (No MITM)')

    ts1 = int(time.time() * 1000)
    nonce1 = os.urandom(16).hex()
    alice_ephemeral_pub_b64 = public_key_to_base64(alice_ecdh_public)
    msg_alice_to_bob = f"{alice_id}:{bob_id}:{alice_ephemeral_pub_b64}:{ts1}:{nonce1}"
    sig_alice = sign_message(alice_sign_private, msg_alice_to_bob)

    # Bob verifies Alice's signature using Alice's known public signing key
    valid_alice = verify_signature(alice_sign_public, msg_alice_to_bob, sig_alice)

    ts2 = int(time.time() * 1000)
    nonce2 = os.urandom(16).hex()
    bob_ephemeral_pub_b64 = public_key_to_base64(bob_ecdh_public)
    msg_bob_to_alice = f"{bob_id}:{alice_id}:{bob_ephemeral_pub_b64}:{ts2}:{nonce2}"
    sig_bob = sign_message(bob_sign_private, msg_bob_to_alice)

    valid_bob = verify_signature(bob_sign_public, msg_bob_to_alice, sig_bob)

    log(f"Alice's signed message valid? {valid_alice}", Colors.green)
    log(f"Bob's signed message valid?   {valid_bob}", Colors.green)

    honest_secret_alice = derive_shared_secret(alice_ecdh_private, bob_ecdh_public)
    honest_secret_bob = derive_shared_secret(bob_ecdh_private, alice_ecdh_public)
    honest_key_alice = hkdf_sha256(honest_secret_alice)['key']
    honest_key_bob = hkdf_sha256(honest_secret_bob)['key']

    log(f"\nHonest derived key (Alice): {to_hex(honest_key_alice)}", Colors.green)
    log(f"Honest derived key (Bob)  : {to_hex(honest_key_bob)}", Colors.green)
    log(
        f"Shared session key equal: {honest_key_alice == honest_key_bob}",
        Colors.green,
    )

    sub_section('Mallory Attempts MITM but Cannot Forge Signatures')

    # Mallory tries to replace Alice's ephemeral key with her own when sending to Bob
    mallory_ephemeral_for_bob_b64 = public_key_to_base64(mallory_to_bob_public)
    forged_msg_alice_to_bob = f"{alice_id}:{bob_id}:{mallory_ephemeral_for_bob_b64}:{ts1}:{nonce1}"

    # Mallory only knows her own private key; she cannot access Alice's private signing key
    forged_sig_alice_by_mallory = sign_message(
        mallory_sign_private,
        forged_msg_alice_to_bob,
    )

    # Bob still verifies using Alice's *real* public signing key
    valid_forged_alice = verify_signature(
        alice_sign_public,
        forged_msg_alice_to_bob,
        forged_sig_alice_by_mallory,
    )

    log(
        f"Bob verifies forged \"Alice\" message signed by Mallory: {valid_forged_alice}",
        Colors.red if valid_forged_alice else Colors.green,
    )

    if not valid_forged_alice:
        log(
            '\n✅ MITM detected: Bob rejects the message because the signature does not match Alice\'s public key.',
            Colors.green,
        )
        log(
            '=> Mallory cannot replace keys without breaking the signature, so the attack fails in the signed protocol.',
            Colors.green,
        )
    else:
        log(
            '\n❌ (Unexpected) Forged message was accepted; check signature logic.',
            Colors.red,
        )

# Main runner ---------------------------------------------------------------

def main():
    section('MITM Attack Demonstration – DH/ECDH Without vs With Signatures')

    scenario_without_signatures()
    scenario_with_signatures()

    log('\nDemo complete.\n', Colors.cyan)

if __name__ == '__main__':
    try:
        main()
    except Exception as err:
        print(f'Fatal error in MITM demo: {err}')
        import traceback
        traceback.print_exc()
        exit(1)

