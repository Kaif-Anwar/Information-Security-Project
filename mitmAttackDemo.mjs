/**
 * MITM Attack Demonstration Script (Requirement 7)
 *
 * This script is SELF-CONTAINED and runs entirely in Node.js.
 * It does NOT depend on your backend, so you can run it even if the server is down.
 *
 * It demonstrates two scenarios:
 *  1) **Vulnerable DH/ECDH without signatures**:
 *     - Alice and Bob perform a naïve ECDH key exchange.
 *     - Mallory (MITM) intercepts and replaces public keys.
 *     - Result: Mallory establishes two shared secrets (with Alice and Bob) and can decrypt.
 *
 *  2) **Secure DH/ECDH with digital signatures (like your final system)**:
 *     - Alice and Bob each have long‑term ECDSA signing keys.
 *     - They sign their ECDH ephemeral public keys + metadata.
 *     - Mallory again tries to intercept and replace keys.
 *     - Result: Signature verification fails; MITM is detected and blocked.
 *
 * You can run this script with:
 *   node scripts/mitmAttackDemo.mjs
 *
 * Use the console output + diagrams in your report to satisfy Requirement 7.
 */

import crypto from 'crypto';

// Utility helpers -----------------------------------------------------------

const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  magenta: '\x1b[35m',
};

function log(message, color = colors.reset) {
  console.log(`${color}${message}${colors.reset}`);
}

function section(title) {
  log('\n' + '='.repeat(70), colors.cyan);
  log(title, colors.cyan);
  log('='.repeat(70), colors.cyan);
}

function subSection(title) {
  log('\n' + '-'.repeat(70), colors.blue);
  log(title, colors.blue);
  log('-'.repeat(70), colors.blue);
}

function toHex(buf, maxLen = 32) {
  const hex = buf.toString('hex');
  if (hex.length <= maxLen) return hex;
  return `${hex.slice(0, maxLen)}... (${hex.length / 2} bytes)`;
}

// Cryptographic primitives --------------------------------------------------

function generateECDHKeyPair() {
  const ecdh = crypto.createECDH('prime256v1'); // NIST P‑256
  ecdh.generateKeys();
  return ecdh;
}

function deriveSharedSecret(ourECDH, otherPublicKey) {
  return ourECDH.computeSecret(otherPublicKey);
}

function generateECDSAKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1', // P‑256
  });
  return { publicKey, privateKey };
}

function signMessage(privateKey, message) {
  const signer = crypto.createSign('SHA256');
  signer.update(message);
  signer.end();
  const sig = signer.sign(privateKey);
  return sig.toString('base64');
}

function verifySignature(publicKey, message, signatureBase64) {
  const verifier = crypto.createVerify('SHA256');
  verifier.update(message);
  verifier.end();
  const sig = Buffer.from(signatureBase64, 'base64');
  return verifier.verify(publicKey, sig);
}

function hkdfSha256(ikm, info = 'e2ee-session-key') {
  // Simple HKDF implementation using crypto.hkdfSync
  const salt = crypto.randomBytes(32);
  const key = crypto.hkdfSync('sha256', ikm, salt, Buffer.from(info, 'utf8'), 32);
  return { key, salt };
}

// Scenario 1: DH/ECDH without signatures (vulnerable) ----------------------

function scenarioWithoutSignatures() {
  section('Scenario 1: MITM Attack on ECDH WITHOUT Signatures (VULNERABLE)');

  // Honest keys
  const aliceECDH = generateECDHKeyPair();
  const bobECDH = generateECDHKeyPair();

  const alicePub = aliceECDH.getPublicKey();
  const bobPub = bobECDH.getPublicKey();

  subSection('Honest ECDH (no attacker)');
  const honestSecretAlice = deriveSharedSecret(aliceECDH, bobPub);
  const honestSecretBob = deriveSharedSecret(bobECDH, alicePub);

  log(`Alice secret: ${toHex(honestSecretAlice)}`, colors.green);
  log(`Bob   secret: ${toHex(honestSecretBob)}`, colors.green);
  log(`Shared secret equal: ${honestSecretAlice.equals(honestSecretBob)}`, colors.green);

  // MITM: Mallory intercepts and replaces public keys
  subSection('Introducing Mallory (MITM) – No Signatures');
  const malloryToAliceECDH = generateECDHKeyPair();
  const malloryToBobECDH = generateECDHKeyPair();

  const malloryPubForAlice = malloryToAliceECDH.getPublicKey();
  const malloryPubForBob = malloryToBobECDH.getPublicKey();

  // Alice thinks she's using Bob's pub, but it's actually Mallory's
  const aliceSharedWithMallory = deriveSharedSecret(aliceECDH, malloryPubForAlice);
  // Bob thinks he's using Alice's pub, but it's actually Mallory's
  const bobSharedWithMallory = deriveSharedSecret(bobECDH, malloryPubForBob);

  // Mallory computes both secrets
  const mallorySharedWithAlice = deriveSharedSecret(
    malloryToAliceECDH,
    alicePub,
  );
  const mallorySharedWithBob = deriveSharedSecret(
    malloryToBobECDH,
    bobPub,
  );

  log('\nAlice ↔ Mallory shared secret:', colors.yellow);
  log(`  Alice side  : ${toHex(aliceSharedWithMallory)}`, colors.yellow);
  log(`  Mallory side: ${toHex(mallorySharedWithAlice)}`, colors.yellow);
  log(
    `  Equal: ${aliceSharedWithMallory.equals(mallorySharedWithAlice)}`,
    colors.yellow,
  );

  log('\nBob ↔ Mallory shared secret:', colors.yellow);
  log(`  Bob side    : ${toHex(bobSharedWithMallory)}`, colors.yellow);
  log(`  Mallory side: ${toHex(mallorySharedWithBob)}`, colors.yellow);
  log(
    `  Equal: ${bobSharedWithMallory.equals(mallorySharedWithBob)}`,
    colors.yellow,
  );

  log(
    '\nResult: Alice and Bob do NOT share the same key, but Mallory shares a key with each.',
    colors.red,
  );
  log(
    '=> Mallory can decrypt, read, and re‑encrypt messages between them. DH without signatures is vulnerable to MITM.',
    colors.red,
  );
}

// Scenario 2: DH/ECDH with digital signatures (secure) ---------------------

function scenarioWithSignatures() {
  section('Scenario 2: ECDH WITH Digital Signatures (MITM Prevented)');

  // Long‑term signing keys (like your User.publicKey.signing)
  const aliceSign = generateECDSAKeyPair();
  const bobSign = generateECDSAKeyPair();
  const mallorySign = generateECDSAKeyPair(); // attacker’s own identity

  // Ephemeral ECDH keys for this session
  const aliceECDH = generateECDHKeyPair();
  const bobECDH = generateECDHKeyPair();
  const malloryToAliceECDH = generateECDHKeyPair();
  const malloryToBobECDH = generateECDHKeyPair();

  const aliceEphemeralPub = aliceECDH.getPublicKey();
  const bobEphemeralPub = bobECDH.getPublicKey();

  const aliceId = 'Alice';
  const bobId = 'Bob';
  const malloryId = 'Mallory';

  subSection('Honest Signed Key Exchange (No MITM)');

  const ts1 = Date.now();
  const nonce1 = crypto.randomBytes(16).toString('hex');
  const msgAliceToBob = `${aliceId}:${bobId}:${aliceEphemeralPub.toString(
    'base64',
  )}:${ts1}:${nonce1}`;
  const sigAlice = signMessage(aliceSign.privateKey, msgAliceToBob);

  // Bob verifies Alice's signature using Alice's known public signing key
  const validAlice = verifySignature(aliceSign.publicKey, msgAliceToBob, sigAlice);

  const ts2 = Date.now();
  const nonce2 = crypto.randomBytes(16).toString('hex');
  const msgBobToAlice = `${bobId}:${aliceId}:${bobEphemeralPub.toString(
    'base64',
  )}:${ts2}:${nonce2}`;
  const sigBob = signMessage(bobSign.privateKey, msgBobToAlice);

  const validBob = verifySignature(bobSign.publicKey, msgBobToAlice, sigBob);

  log(`Alice's signed message valid? ${validAlice}`, colors.green);
  log(`Bob's signed message valid?   ${validBob}`, colors.green);

  const honestSecretAlice = deriveSharedSecret(aliceECDH, bobEphemeralPub);
  const honestSecretBob = deriveSharedSecret(bobECDH, aliceEphemeralPub);
  const { key: honestKeyAlice } = hkdfSha256(honestSecretAlice);
  const { key: honestKeyBob } = hkdfSha256(honestSecretBob);

  log(`\nHonest derived key (Alice): ${toHex(honestKeyAlice)}`, colors.green);
  log(`Honest derived key (Bob)  : ${toHex(honestKeyBob)}`, colors.green);
  log(
    `Shared session key equal: ${honestKeyAlice.equals(honestKeyBob)}`,
    colors.green,
  );

  subSection('Mallory Attempts MITM but Cannot Forge Signatures');

  // Mallory tries to replace Alice's ephemeral key with her own when sending to Bob
  const malloryEphemeralForBob = malloryToBobECDH.getPublicKey();
  const forgedMsgAliceToBob = `${aliceId}:${bobId}:${malloryEphemeralForBob.toString(
    'base64',
  )}:${ts1}:${nonce1}`;

  // Mallory only knows her own private key; she cannot access Alice's private signing key
  const forgedSigAliceByMallory = signMessage(
    mallorySign.privateKey,
    forgedMsgAliceToBob,
  );

  // Bob still verifies using Alice's *real* public signing key
  const validForgedAlice = verifySignature(
    aliceSign.publicKey,
    forgedMsgAliceToBob,
    forgedSigAliceByMallory,
  );

  log(
    `Bob verifies forged "Alice" message signed by Mallory: ${validForgedAlice}`,
    validForgedAlice ? colors.red : colors.green,
  );

  if (!validForgedAlice) {
    log(
      '\n✅ MITM detected: Bob rejects the message because the signature does not match Alice’s public key.',
      colors.green,
    );
    log(
      '=> Mallory cannot replace keys without breaking the signature, so the attack fails in the signed protocol.',
      colors.green,
    );
  } else {
    log(
      '\n❌ (Unexpected) Forged message was accepted; check signature logic.',
      colors.red,
    );
  }
}

// Main runner ---------------------------------------------------------------

async function run() {
  section('MITM Attack Demonstration – DH/ECDH Without vs With Signatures');

  scenarioWithoutSignatures();
  scenarioWithSignatures();

  log('\nDemo complete.\n', colors.cyan);
}

run().catch((err) => {
  console.error('Fatal error in MITM demo:', err);
  process.exit(1);
});


