# Secure E2EE Messaging & File-Sharing – Architecture

## Requirements Synthesis
- Client: React + Web Crypto API for RSA/ECC key gen, ECDH, AES-256-GCM messaging & file chunk encryption, IndexedDB storage, replay protection, Gemini helper via `LLMManager`.
- Server: Node.js + Express + MongoDB for auth metadata, message/file metadata, logging, optional Socket.io, no plaintext handling.
- Security: Custom DH/ECDH key exchange with digital signatures, HKDF, key confirmation, nonce/timestamp/counter replay defense, logging/auditing, STRIDE threat modeling, MITM/replay demos, Wireshark/Burp evidence.

## High-Level Architecture

```
┌────────────┐      HTTPS (REST/WebSocket, metadata only)       ┌─────────────┐
│ React App  │ <───────────────────────────────────────────────> │ Express API │
│ (WebCrypto)│         Ciphertext + IV + tags + metadata        │  + Socket.io│
└────┬───────┘                                                 └────┬────────┘
     │ Client-side crypto/storage                                     │ Metadata persistence
     │                                                                ▼
     │                                                         ┌────────────┐
     │                                                         │ MongoDB     │
     │                                                         │ (ciphertext │
     │                                                         │  metadata,  │
     │                                                         │  logs)      │
     │                                                         └────────────┘
```

## Components
- **Auth Service**: Registration/login, bcrypt/argon2 hashing, JWT session tokens, log attempts.
- **Key Management Service**: Client generates RSA-2048 or P-256 pair, stores private key in IndexedDB protected by passphrase-derived AES key. Public key + signed key descriptors stored server-side.
- **Key Exchange Protocol**:
  1. Initiator requests receiver public bundle.
  2. Both sides sign ephemeral DH/ECDH shares with long-term private keys.
  3. Server relays signed messages; clients verify, derive shared secret via ECDH.
  4. HKDF -> session keys (enc + auth). Final confirmation message includes nonce, timestamp, signature.
- **Messaging Flow**: Message composer -> derive fresh IV -> encrypt payload via AES-256-GCM -> attach metadata (seq, timestamp, nonce, signature) -> send via WebSocket/REST. Receiver validates metadata, checks replay cache, decrypts.
- **File Flow**: File chunker -> AES-256-GCM per chunk -> upload encrypted chunks + IV/tags. Download reverses process and reassembles file.
- **Logging & Auditing**: Central service capturing auth, key exchange, invalid sigs, replay detections, failed decrypts, metadata API access. Stored in MongoDB capped collections and exposed via admin endpoint.
- **Attack Simulation Tooling**:
  - MITM script intercepting DH before signatures to demonstrate vulnerability.
  - Replay injector script using captured ciphertext + metadata to test defenses.
  - Wireshark/Burp capture scripts for evidence.
- **LLM Integration**: `LLMManager` exposes Gemini free API for contextual helper prompts (on-device). Keys stored in config but excluded from repo via `.env`.

## Deployment Overview
- Local dev: `pnpm` workspaces hosting `client/` (Vite React) and `server/` (Express).
- Production: HTTPS reverse proxy (e.g., Nginx) terminating TLS and forwarding to Node backend; static React build served via CDN.
- Secrets: `.env` for Mongo URI, JWT secret, Gemini key. Client uses secure configuration injection at build time without bundling raw secret when possible.

## Next Steps
1. Scaffold `client/` and `server/` using pnpm workspaces.
2. Define TypeScript interfaces for messages, keys, logs.
3. Implement cryptographic utilities and storage adapters.
4. Build APIs/WebSocket channels with validation and logging.
5. Implement attack scripts, STRIDE model, and documentation assets.

