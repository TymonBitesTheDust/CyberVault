// vault-crypto.js
// All encryption happens here, in your browser, before anything is sent to Firebase.
//
// How it works
// - A random 256-bit "data key" encrypts every item and photo (AES-256-GCM).
// - Your master password is stretched with PBKDF2-SHA256 (600,000 rounds) into a
//   "key-encryption key", which encrypts ("wraps") the data key.
// - Firebase only ever stores the wrapped data key, the salt, and ciphertext.
//   Without your master password none of it can be read, including by Google.
// - Changing the master password only re-wraps the data key, so items don't need
//   to be re-encrypted.
// - Recovery: the same data key can also be wrapped by a random recovery key and,
//   optionally, by the answers to the user's own security questions. Each one is an
//   independent way to unwrap the data key and set a new master password.

const enc = new TextEncoder();
const dec = new TextDecoder();

export const KDF_ITERATIONS = 600_000;
// The recovery key is 150 random bits, so it needs far less stretching than a password.
export const RECOVERY_ITERATIONS = 100_000;
const VAULT_AAD = enc.encode('vault-key-v1');
const RECOVERY_AAD = enc.encode('vault-key-recovery-v1');
const QUESTIONS_AAD = enc.encode('vault-key-questions-v1');
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'; // no I, L, O, U: easy to read and type

export class WrongPasswordError extends Error {
  constructor() {
    super('Wrong master password');
    this.name = 'WrongPasswordError';
  }
}

export class WrongRecoveryError extends Error {
  constructor(kind) {
    super(kind === 'questions' ? 'The answers don\'t match' : 'The recovery key doesn\'t match');
    this.name = 'WrongRecoveryError';
    this.kind = kind;
  }
}

// ---------- encoding helpers ----------

export function b64encode(bytes) {
  let s = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return btoa(s);
}

export function b64decode(str) {
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

// ---------- keys ----------

async function deriveKek(password, salt, iterations) {
  const base = await crypto.subtle.importKey(
    'raw', enc.encode(password.normalize('NFKC')), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']);
}

function importDataKey(raw) {
  // Non-extractable: once imported, page scripts can use the key but not read it out.
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function wrap(password, raw) {
  const salt = randomBytes(16);
  const kek = await deriveKek(password, salt, KDF_ITERATIONS);
  const iv = randomBytes(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: VAULT_AAD }, kek, raw));
  return {
    kdf: { name: 'PBKDF2-SHA256', iterations: KDF_ITERATIONS, salt: b64encode(salt) },
    wrappedKey: { iv: b64encode(iv), ct: b64encode(ct) },
  };
}

async function unwrapRaw(password, meta) {
  if (!meta || !meta.kdf || !meta.wrappedKey) throw new Error('Vault data is missing or damaged');
  const kek = await deriveKek(password, b64decode(meta.kdf.salt), meta.kdf.iterations);
  try {
    return new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64decode(meta.wrappedKey.iv), additionalData: VAULT_AAD },
      kek, b64decode(meta.wrappedKey.ct)));
  } catch {
    // AES-GCM authentication failed, so the password is wrong.
    throw new WrongPasswordError();
  }
}

async function wrapWith(secret, raw, iterations, aad) {
  const salt = randomBytes(16);
  const kek = await deriveKek(secret, salt, iterations);
  const iv = randomBytes(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, kek, raw));
  return {
    kdf: { name: 'PBKDF2-SHA256', iterations, salt: b64encode(salt) },
    wrappedKey: { iv: b64encode(iv), ct: b64encode(ct) },
    createdAt: Date.now(),
  };
}

async function unwrapWith(secret, w, aad, kind) {
  if (!w || !w.kdf || !w.wrappedKey) throw new Error(kind === 'questions' ? 'Security questions aren\'t set up' : 'No recovery key is set up');
  const kek = await deriveKek(secret, b64decode(w.kdf.salt), w.kdf.iterations);
  try {
    return new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64decode(w.wrappedKey.iv), additionalData: aad }, kek, b64decode(w.wrappedKey.ct)));
  } catch {
    throw new WrongRecoveryError(kind);
  }
}

/** Create a brand-new vault. Returns the document to store and the unlocked key. */
export async function createVault(password, { recoveryKey } = {}) {
  const raw = randomBytes(32);
  const meta = { v: 1, ...(await wrap(password, raw)), createdAt: Date.now() };
  if (recoveryKey) meta.recovery = await wrapWith(normalizeRecoveryKey(recoveryKey), raw, RECOVERY_ITERATIONS, RECOVERY_AAD);
  const key = await importDataKey(raw);
  raw.fill(0);
  meta.keyCheck = await makeKeyCheck(key);
  return { meta, key };
}

const KEY_CHECK_AAD = 'cybervault:key-check';

/**
 * A small value encrypted with the vault key and stored with the vault. Changing the master
 * password keeps it valid; erasing the vault and creating a new one doesn't, which is how a
 * device that's still unlocked can tell the vault was replaced. Reveals nothing about the key.
 */
export async function makeKeyCheck(key) {
  return encryptJSON(key, { check: 'cybervault' }, KEY_CHECK_AAD);
}

/** true: the vault still uses this key. false: it was replaced. null: can't tell (no check stored). */
export async function keyMatches(key, meta) {
  if (!meta?.keyCheck) return null;
  try {
    return (await decryptJSON(key, meta.keyCheck, KEY_CHECK_AAD))?.check === 'cybervault';
  } catch {
    return false;
  }
}

/** Unlock an existing vault. Throws WrongPasswordError if the password is wrong. */
export async function unlockVault(password, meta) {
  const raw = await unwrapRaw(password, meta);
  const key = await importDataKey(raw);
  raw.fill(0);
  return key;
}

/**
 * Open a backup file's key. A backup keeps the vault key wrapped exactly as it was when the
 * backup was made, so the master password from that time works, and so does the recovery key
 * from that time. Throws WrongPasswordError if neither matches.
 */
export async function unlockBackup(secret, meta) {
  try {
    return await unlockVault(secret, meta);
  } catch (e) {
    if (!(e instanceof WrongPasswordError) || !meta?.recovery) throw e;
    let rk;
    try { rk = normalizeRecoveryKey(secret); } catch { throw e; }
    try {
      const raw = await unwrapWith(rk, meta.recovery, RECOVERY_AAD, 'key');
      const key = await importDataKey(raw);
      raw.fill(0);
      return key;
    } catch {
      throw new WrongPasswordError();
    }
  }
}

/** Re-wrap the data key with a new master password. Returns the new vault document. */
export async function rewrapVault(oldPassword, newPassword, meta) {
  const raw = await unwrapRaw(oldPassword, meta);
  const wrapped = await wrap(newPassword, raw);
  raw.fill(0);
  return { ...meta, ...wrapped, updatedAt: Date.now() };
}

// ---------- recovery ----------

/** 30 random characters (150 bits) as XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX. */
export function generateRecoveryKey() {
  let s = '';
  for (const b of randomBytes(30)) s += CROCKFORD[b & 31];
  return s.match(/.{5}/g).join('-');
}

/** Accepts any spacing, dashes or capitals, and look-alikes (O→0, I/L→1). */
export function normalizeRecoveryKey(input) {
  const s = String(input || '').toUpperCase().replace(/O/g, '0').replace(/[IL]/g, '1').replace(/[^0-9A-HJKMNP-TV-Z]/g, '');
  if (s.length !== 30) throw new Error('A recovery key has 30 letters and numbers. Check it and try again.');
  return s;
}

/** Answers ignore capitals, spaces and punctuation: "Melbourne!" = "melbourne". */
export function normalizeAnswer(answer) {
  return String(answer || '').normalize('NFKC').toLowerCase().replace(/[^\p{L}\p{N}]+/gu, ' ').trim();
}

const answersSecret = (answers) => answers.map(normalizeAnswer).join('\n');

/** Wrap the data key with a (new) recovery key. Needs the master password. */
export async function setRecoveryKey(password, meta, recoveryKey) {
  const raw = await unwrapRaw(password, meta);
  try {
    return { ...meta, recovery: await wrapWith(normalizeRecoveryKey(recoveryKey), raw, RECOVERY_ITERATIONS, RECOVERY_AAD) };
  } finally {
    raw.fill(0);
  }
}

/** Wrap the data key with the answers to the user's own questions. Needs the master password. */
export async function setSecurityQuestions(password, meta, questions, answers) {
  const raw = await unwrapRaw(password, meta);
  try {
    const w = await wrapWith(answersSecret(answers), raw, KDF_ITERATIONS, QUESTIONS_AAD);
    return { ...meta, questions: { list: questions.map((q) => q.trim()), ...w } };
  } finally {
    raw.fill(0);
  }
}

export function removeRecovery(meta, which) {
  const out = { ...meta };
  delete out[which];
  return out;
}

async function finishReset(raw, newPassword, meta) {
  try {
    const wrapped = await wrap(newPassword, raw);
    const key = await importDataKey(raw);
    return { meta: { ...meta, ...wrapped, updatedAt: Date.now() }, key };
  } finally {
    raw.fill(0);
  }
}

/** Forgot the master password: set a new one using the recovery key. */
export async function resetWithRecoveryKey(recoveryKey, newPassword, meta) {
  const raw = await unwrapWith(normalizeRecoveryKey(recoveryKey), meta.recovery, RECOVERY_AAD, 'key');
  return finishReset(raw, newPassword, meta);
}

/** Forgot the master password: set a new one using the security-question answers. */
export async function resetWithAnswers(answers, newPassword, meta) {
  const raw = await unwrapWith(answersSecret(answers), meta.questions, QUESTIONS_AAD, 'questions');
  return finishReset(raw, newPassword, meta);
}

// ---------- data ----------
// `aad` (additional authenticated data) ties each ciphertext to its document id,
// so encrypted records can't be silently swapped between documents.

export async function encryptJSON(key, obj, aad) {
  const iv = randomBytes(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: enc.encode(aad) }, key, enc.encode(JSON.stringify(obj))));
  return { v: 1, iv: b64encode(iv), ct: b64encode(ct) };
}

export async function decryptJSON(key, record, aad) {
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64decode(record.iv), additionalData: enc.encode(aad) },
    key, b64decode(record.ct));
  return JSON.parse(dec.decode(pt));
}

/** Encrypt raw bytes (photos). Output is iv (12 bytes) followed by ciphertext. */
export async function encryptBytes(key, bytes, aad) {
  const iv = randomBytes(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: enc.encode(aad) }, key, bytes));
  const out = new Uint8Array(12 + ct.length);
  out.set(iv, 0);
  out.set(ct, 12);
  return out;
}

export async function decryptBytes(key, packed, aad) {
  return new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: packed.subarray(0, 12), additionalData: enc.encode(aad) },
    key, packed.subarray(12)));
}

// ---------- passwords ----------

function randInt(n) {
  // Unbiased random integer in [0, n)
  const limit = Math.floor(0x100000000 / n) * n;
  const buf = new Uint32Array(1);
  let x;
  do {
    crypto.getRandomValues(buf);
    x = buf[0];
  } while (x >= limit);
  return x % n;
}

export function generatePassword(length = 20, { symbols = true, digits = true } = {}) {
  // Look-alike characters (l, I, O, 0, 1) are left out.
  const sets = ['abcdefghijkmnopqrstuvwxyz', 'ABCDEFGHJKLMNPQRSTUVWXYZ'];
  if (digits) sets.push('23456789');
  if (symbols) sets.push('!@#$%^&*-_=+?');
  const all = sets.join('');
  for (;;) {
    const out = Array.from({ length }, () => all[randInt(all.length)]);
    if (sets.every((s) => out.some((c) => s.includes(c)))) return out.join('');
  }
}

export function passwordStrength(pw) {
  if (!pw) return { score: 0, bits: 0, label: '' };
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^A-Za-z0-9]/.test(pw)) pool += 33;
  let bits = Math.log2(Math.max(pool, 2)) * [...pw].length;
  if (new Set(pw).size < pw.length / 2) bits *= 0.6;
  if (/(.)\1{2,}/.test(pw)) bits *= 0.85;
  if (/0123|1234|2345|3456|4567|5678|6789|abcd|bcde|qwer|asdf|zxcv/i.test(pw)) bits *= 0.8;
  if (/(19|20)\d{2}/.test(pw)) bits *= 0.85; // years are easy to guess
  if (/^(password|passw0rd|qwerty|letmein|123456|abc123|iloveyou|admin|welcome|monkey|dragon)/i.test(pw)) {
    bits = Math.min(bits, 10);
  }
  const score = bits < 35 ? 0 : bits < 50 ? 1 : bits < 65 ? 2 : bits < 80 ? 3 : 4;
  return { score, bits: Math.round(bits), label: ['Very weak', 'Weak', 'Fair', 'Strong', 'Very strong'][score] };
}
