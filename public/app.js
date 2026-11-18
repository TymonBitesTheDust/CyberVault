// app.js: CyberVault, a personal encrypted vault backed by Firebase.
// Everything is encrypted in this browser (see vault-crypto.js) before upload.

import { initializeApp } from 'https://www.gstatic.com/firebasejs/13.3.0/firebase-app.js';
import {
  getAuth, onAuthStateChanged, GoogleAuthProvider, signInWithPopup,
  signInWithEmailAndPassword, createUserWithEmailAndPassword, signOut, sendPasswordResetEmail,
  RecaptchaVerifier, signInWithPhoneNumber, linkWithPhoneNumber, unlink, getAdditionalUserInfo, deleteUser, reload,
} from 'https://www.gstatic.com/firebasejs/13.3.0/firebase-auth.js';
import {
  initializeFirestore, getFirestore, persistentLocalCache, persistentMultipleTabManager,
  doc, getDoc, getDocFromCache, setDoc, collection, getDocs, getDocsFromServer, writeBatch, query, limit,
  onSnapshot, runTransaction, waitForPendingWrites, terminate, clearIndexedDbPersistence,
} from 'https://www.gstatic.com/firebasejs/13.3.0/firebase-firestore.js';
import { firebaseConfig } from './firebase-config.js';
import * as vc from './vault-crypto.js';
import { qrSvg, wifiQrText } from './qr.js';

const APP_VERSION = '2.0.0';

// =====================================================================
// Item types
// =====================================================================

// Field specs: [label, kind, placeholder, hidden?]. Kinds: text, secret (hidden text), url,
// date (DD/MM/YYYY), month (MM/YY or MM/YYYY), bsb (000-000) and cardnum (a card number).
const TYPES = {
  login: {
    label: 'Login', plural: 'Logins', icon: 'key', color: 'blue',
    blurb: 'Website or app account',
    titleHint: 'e.g. Google, myGov, Netflix',
    history: true,
    fields: [
      ['Username / email', 'text', 'name@example.com'],
      ['Password', 'secret', ''],
      ['Website', 'url', 'example.com'],
    ],
  },
  id: {
    label: 'ID number', plural: 'IDs', icon: 'hash', color: 'amber',
    blurb: 'TFN, ABN, USI, Medicare…',
    titleHint: 'e.g. TFN',
    presets: ['TFN', 'ABN', 'USI', 'Medicare', 'Centrelink CRN', 'Student ID'],
    presetFields: {
      Medicare: [
        ['Card number', 'secret', '0000 00000 0'],
        ['Individual reference number', 'text', 'e.g. 1'],
        ['Valid to', 'month', 'MM/YYYY'],
      ],
    },
    fields: [['Number', 'secret', '']],
  },
  passport: {
    label: 'Passport', plural: 'Passports', icon: 'passport', color: 'violet',
    blurb: 'Details and photo page',
    titleHint: 'e.g. Australian passport',
    photoHint: 'Add a photo of the photo page',
    fields: [
      ['Full name', 'text', ''],
      ['Passport number', 'secret', ''],
      ['Nationality', 'text', ''],
      ['Date of birth', 'date', 'DD/MM/YYYY'],
      ['Date of issue', 'date', 'DD/MM/YYYY'],
      ['Date of expiry', 'date', 'DD/MM/YYYY'],
    ],
  },
  licence: {
    label: 'Driver licence', plural: 'Licences', icon: 'card', color: 'teal',
    blurb: 'Details, front and back',
    titleHint: 'e.g. VIC driver licence',
    photoHint: 'Add the front and back',
    fields: [
      ['Full name', 'text', ''],
      ['Licence number', 'secret', ''],
      ['Card number', 'secret', ''],
      ['State', 'text', 'VIC'],
      ['Expiry date', 'date', 'DD/MM/YYYY'],
    ],
  },
  bankcard: {
    label: 'Bank card', plural: 'Cards', icon: 'creditcard', color: 'rose',
    blurb: 'Debit or credit card',
    titleHint: 'e.g. Everyday debit card',
    photoHint: 'Optional: the front and back',
    fields: [
      ['Name on card', 'text', ''],
      ['Card number', 'cardnum', '0000 0000 0000 0000', true],
      ['Expiry', 'month', 'MM/YY'],
      ['CVV', 'secret', '3 or 4 digits'],
      ['PIN', 'secret', ''],
    ],
  },
  bankaccount: {
    label: 'Bank account', plural: 'Accounts', icon: 'bank', color: 'lime',
    blurb: 'BSB and account number',
    titleHint: 'e.g. Everyday account',
    fields: [
      ['Bank', 'text', 'e.g. CommBank'],
      ['Account name', 'text', ''],
      ['BSB', 'bsb', '000-000'],
      ['Account number', 'text', '12345678', true],
    ],
  },
  wifi: {
    label: 'Wi-Fi', plural: 'Wi-Fi', icon: 'wifi', color: 'sky',
    blurb: 'Network, password and a QR code',
    titleHint: 'e.g. Home Wi-Fi',
    history: true,
    fields: [
      ['Network name', 'text', 'The name you see in Wi-Fi settings'],
      ['Password', 'secret', ''],
      ['Security', 'text', 'WPA (or WEP, or none)'],
    ],
  },
  note: {
    label: 'Secure note', plural: 'Notes', icon: 'note', color: 'slate',
    blurb: 'Anything else',
    titleHint: 'e.g. Recovery codes',
    fields: [],
  },
};

/** A new, empty field from a spec in TYPES. */
function fieldFromSpec([label, kind, , hidden]) {
  return {
    label,
    value: '',
    secret: kind === 'secret' || !!hidden,
    kind: kind === 'secret' ? 'text' : kind,
  };
}

// =====================================================================
// Firebase connection
// Like Checkmate, each device can be connected inside the app: paste the
// firebaseConfig block (or a setup code from another device) on first open.
// Filling in firebase-config.js instead connects every device automatically.
// None of these values are secret.
// =====================================================================

const CONFIG_KEY = 'cybervault.firebaseConfig';
const CONFIG_REQUIRED = ['apiKey', 'authDomain', 'projectId', 'appId'];
const CONFIG_KEEP = ['apiKey', 'authDomain', 'projectId', 'storageBucket', 'messagingSenderId', 'appId'];
const isRealConfig = (c) => !!(c && typeof c.apiKey === 'string' && typeof c.projectId === 'string' &&
  c.apiKey && c.projectId && !/YOUR_|PASTE/i.test(c.apiKey + c.projectId));

function savedConfig() {
  try {
    const c = JSON.parse(localStorage.getItem(CONFIG_KEY) || 'null');
    return isRealConfig(c) ? c : null;
  } catch {
    return null;
  }
}

// The single-file build (dist/cybervault.html) keeps its optional config in a
// <script type="text/plain" id="firebase-config"> block instead of firebase-config.js.
function embeddedConfig() {
  const el = document.getElementById('firebase-config');
  if (!el) return null;
  try { return parseConfig(el.textContent); } catch { return null; }
}

const fileConfig = isRealConfig(firebaseConfig) ? firebaseConfig : embeddedConfig();
const configSource = fileConfig ? 'file' : 'device';
let activeConfig = fileConfig || savedConfig();

let auth = null;
let db = null;
function startFirebase(cfg) {
  const fbApp = initializeApp(cfg);
  auth = getAuth(fbApp);
  // Offline access: Firestore keeps a copy of the (encrypted) vault on this device, and holds
  // changes made offline until it can reach the server again.
  try {
    db = initializeFirestore(fbApp, {
      localCache: persistentLocalCache({ tabManager: persistentMultipleTabManager(), cacheSizeBytes: 200 * 1024 * 1024 }),
    });
  } catch {
    db = getFirestore(fbApp);
  }
}

/** Accepts a setup code (CV1-…, or a whole setup link) or the firebaseConfig block as the console shows it. */
function parseConfig(text) {
  const raw = (text || '').trim();
  if (!raw) throw new Error('Paste a setup code or your Firebase config first.');
  let obj;
  const code = /CV1-[A-Za-z0-9_-]+/.exec(raw);
  if (code) {
    try {
      const b64 = code[0].slice(4).replace(/-/g, '+').replace(/_/g, '/');
      obj = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(b64), (ch) => ch.charCodeAt(0))));
    } catch {
      throw new Error('That setup code is incomplete. Copy it again from your other device.');
    }
  } else {
    // Prefer the object after "firebaseConfig =", so pasting the whole snippet
    // (which starts with `import { initializeApp } …`) still works.
    const named = /firebaseConfig\s*=\s*\{/.exec(raw);
    const start = named ? named.index + named[0].length - 1 : raw.indexOf('{');
    const end = start < 0 ? -1 : matchingBrace(raw, start);
    if (start < 0 || end < 0) {
      throw new Error('Couldn\'t find the { … } block. Copy the firebaseConfig object from Firebase → Project settings → Your apps.');
    }
    let body = raw.slice(start, end + 1);
    try {
      obj = JSON.parse(body);
    } catch {
      body = stripComments(body)
        .replace(/([{,]\s*)([A-Za-z_$][\w$]*)\s*:/g, '$1"$2":')
        .replace(/'([^'\\\n]*)'/g, '"$1"')
        .replace(/,(\s*})/g, '$1');
      try {
        obj = JSON.parse(body);
      } catch {
        throw new Error('The config couldn\'t be read. Copy the whole firebaseConfig = { … } block again.');
      }
    }
  }
  if (!obj || typeof obj !== 'object') throw new Error('The config couldn\'t be read.');
  for (const k of CONFIG_REQUIRED) {
    if (!obj[k] || typeof obj[k] !== 'string') {
      throw new Error(`The config is missing “${k}”. Copy it again from Firebase → Project settings → Your apps.`);
    }
  }
  if (!isRealConfig(obj)) throw new Error('That still has the placeholder values. Copy your real config from the Firebase console.');
  const out = {};
  for (const k of CONFIG_KEEP) if (typeof obj[k] === 'string' && obj[k].trim()) out[k] = obj[k].trim();
  return out;
}

// Removes line and block comments that are not inside strings.
function stripComments(text) {
  let out = '';
  let quote = '';
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quote) {
      out += c;
      if (c === '\\') out += text[++i] || '';
      else if (c === quote) quote = '';
    } else if (c === '/' && text[i + 1] === '/') {
      while (i < text.length && text[i] !== '\n') i++;
      out += '\n';
    } else if (c === '/' && text[i + 1] === '*') {
      const close = text.indexOf('*/', i + 2);
      i = close < 0 ? text.length : close + 1;
    } else {
      if (c === '"' || c === "'" || c === '`') quote = c;
      out += c;
    }
  }
  return out;
}

/** Index of the } that closes the { at `open`, skipping braces inside strings. */
function matchingBrace(text, open) {
  let depth = 0;
  let quote = '';
  for (let i = open; i < text.length; i++) {
    const c = text[i];
    if (quote) {
      if (c === '\\') i++;
      else if (c === quote) quote = '';
    } else if (c === '"' || c === "'" || c === '`') quote = c;
    else if (c === '{') depth++;
    else if (c === '}' && --depth === 0) return i;
  }
  return -1;
}

function makeSetupCode(cfg) {
  let bin = '';
  for (const b of new TextEncoder().encode(JSON.stringify(cfg))) bin += String.fromCharCode(b);
  return `CV1-${btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')}`;
}

const setupLink = (cfg) => `${location.origin}${location.pathname}#connect=${makeSetupCode(cfg)}`;

/** Firestore rules for CyberVault. With a uid, the database is locked to that one account. */
function rulesText(lockUid = '') {
  return `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // ${lockUid ? 'Locked to one account: only this User ID can read or write.' : 'Put your User ID between the quotes to lock the database to your account.'}
    function allowedUid() {
      return "${lockUid}";
    }
    function isOwner(uid) {
      return request.auth != null
        && request.auth.uid == uid
        && (allowedUid() == "" || uid == allowedUid());
    }
    match /users/{uid} {
      allow read, write: if isOwner(uid);
      match /{document=**} {
        allow read, write: if isOwner(uid);
      }
    }
  }
}
`;
}

const uid = () => S.user.uid;
const vaultRef = () => doc(db, 'users', uid());
const itemsCol = () => collection(db, 'users', uid(), 'items');
const itemRef = (id) => doc(db, 'users', uid(), 'items', id);
const blobsCol = () => collection(db, 'users', uid(), 'blobs');
const blobRef = (id, i) => doc(db, 'users', uid(), 'blobs', `${id}_${i}`);
const aadItem = (id) => `item:${id}`;
const aadBlob = (id) => `blob:${id}`;

// Encrypted photos are split across documents (Firestore's limit is 1 MiB per document).
const CHUNK_CHARS = 700_000;

// =====================================================================
// State and settings
// =====================================================================

const S = {
  user: null,
  meta: null,             // vault document (salt + wrapped key), not secret
  key: null,              // the unlocked data key, kept only in memory
  items: new Map(),       // id -> decrypted item, as shown (server copy + changes not yet synced)
  server: new Map(),      // id -> decrypted item, as the server (or its offline copy) has it
  local: new Map(),       // id -> item (or null if deleted) changed on this device, not yet synced
  revs: new Map(),        // id -> revision the server has; edits are checked against it
  mine: new Set(),        // revisions written by this device
  superseded: new Set(),  // "id:rev" this device replaced; a late snapshot carrying one is stale
  unsub: null,            // stops the live listener
  chain: Promise.resolve(),
  synced: false,
  fromCache: false,
  fromCacheAt: 0,
  pendingWrites: false,
  flushing: false,
  editing: null,          // the item open in the editor, to warn about changes from other devices
  repaint: null,          // refreshes the current list screen in place
  onBack: null,           // what the Android back button does on this screen, if special
  photoCache: new Map(),  // photo id -> { url, blob }
  photoLoads: new Map(),
  tempUrls: new Set(),
  revealed: new Set(),
  overlays: new Set(),
  nav: [],
  filter: 'all',
  query: '',
  lastActivity: Date.now(),
  hiddenAt: null,
  clipTimer: null,
  authHold: false,        // true while a phone sign-in is being checked
  ignoreUid: null,        // a throwaway account from an unlinked phone number
  loadingUid: null,
  view: '',
};

const DEFAULT_SETTINGS = { autoLockMin: 5, bgLockSec: 30, clearClipSec: 30, sort: 'name', pinFav: true, pinRecent: true, lastBackupAt: 0 };
const settings = (() => {
  try { return { ...DEFAULT_SETTINGS, ...JSON.parse(localStorage.getItem('vault.settings') || '{}') }; }
  catch { return { ...DEFAULT_SETTINGS }; }
})();
// Inside the CyberVault Android app (android/), the native side provides window.CyberVaultAndroid.
const android = typeof window.CyberVaultAndroid === 'object' && window.CyberVaultAndroid ? window.CyberVaultAndroid : null;
if (android) document.documentElement.classList.add('in-android');

function saveSettings() {
  try { localStorage.setItem('vault.settings', JSON.stringify(settings)); } catch { /* private mode */ }
}

// =====================================================================
// DOM helpers
// =====================================================================

const app = document.getElementById('app');

function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  let value;
  if (props) {
    for (const [k, v] of Object.entries(props)) {
      if (v === undefined || v === null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'value') value = v;
      else if (k === 'checked') el.checked = !!v;
      else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? '' : String(v));
    }
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid === undefined || kid === null || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  if (value !== undefined) el.value = value;
  return el;
}

const ICONS = {
  shield: '<path d="M12 3l8 3v6c0 5-3.4 8.3-8 9-4.6-.7-8-4-8-9V6l8-3z"/><path d="M9.5 12.5l1.8 1.8 3.6-3.8"/>',
  lock: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
  unlock: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 7.6-1.7"/>',
  settings: '<path d="M4 7h9M17 7h3M4 17h3M11 17h9"/><circle cx="15" cy="7" r="2"/><circle cx="9" cy="17" r="2"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h8"/>',
  eye: '<path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z"/><circle cx="12" cy="12" r="3"/>',
  eyeOff: '<path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z"/><circle cx="12" cy="12" r="3"/><path d="M4 20L20 4"/>',
  search: '<circle cx="11" cy="11" r="6.5"/><path d="M20 20l-4.2-4.2"/>',
  trash: '<path d="M4 7h16M10 7V4.5h4V7M6.5 7l1 13h9l1-13M10 11v5M14 11v5"/>',
  edit: '<path d="M4 20h4L19.5 8.5a2.1 2.1 0 0 0-3-3L5 17v3z"/><path d="M14.5 7.5l3 3"/>',
  back: '<path d="M15 18l-6-6 6-6"/>',
  forward: '<path d="M9 18l6-6-6-6"/>',
  close: '<path d="M6 6l12 12M18 6L6 18"/>',
  image: '<rect x="3" y="4.5" width="18" height="15" rx="2"/><circle cx="9" cy="10" r="1.8"/><path d="M21 16l-5-5-9 8.5"/>',
  camera: '<path d="M4 8h3l2-2.5h6L17 8h3v11H4z"/><circle cx="12" cy="13" r="3.5"/>',
  key: '<circle cx="8" cy="15" r="4"/><path d="M11 12l8.5-8.5M16 7l2.5 2.5M14 9l2 2"/>',
  hash: '<path d="M5 9h15M4 15h15M10 4L8 20M16 4l-2 16"/>',
  passport: '<rect x="5" y="2.5" width="14" height="19" rx="2"/><circle cx="12" cy="10" r="3.2"/><path d="M9 17h6"/>',
  card: '<rect x="2.5" y="5" width="19" height="14" rx="2"/><circle cx="8" cy="11" r="2.2"/><path d="M5 16c.6-1.5 1.7-2.2 3-2.2s2.4.7 3 2.2M14 10h4.5M14 13.5h3"/>',
  note: '<path d="M6 3h8.5L19 7.5V21H6z"/><path d="M14 3v5h5M9 13h7M9 17h5"/>',
  external: '<path d="M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/>',
  download: '<path d="M12 4v11M7 10.5l5 5 5-5M5 20h14"/>',
  upload: '<path d="M12 20V9M7 13.5l5-5 5 5M5 4h14"/>',
  phone: '<rect x="7" y="2.5" width="10" height="19" rx="2"/><path d="M11 18h2"/>',
  mail: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3.5 6.5l8.5 6 8.5-6"/>',
  check: '<path d="M5 12.5l4.5 4.5L19 7.5"/>',
  plug: '<path d="M9 3v5M15 3v5M6 8h12v3a6 6 0 0 1-12 0V8zM12 17v4"/>',
  help: '<circle cx="12" cy="12" r="9"/><path d="M9.5 9.5a2.5 2.5 0 0 1 4.8.9c0 1.7-2.3 2.1-2.3 3.6M12 17.2v.1"/>',
  refresh: '<path d="M19.5 12a7.5 7.5 0 1 1-2.2-5.3L20 9.5"/><path d="M20 4v5.5h-5.5"/>',
  dice: '<rect x="4" y="4" width="16" height="16" rx="3"/><circle cx="9" cy="9" r="1.2" fill="currentColor"/><circle cx="15" cy="15" r="1.2" fill="currentColor"/><circle cx="15" cy="9" r="1.2" fill="currentColor"/><circle cx="9" cy="15" r="1.2" fill="currentColor"/>',
  alert: '<path d="M12 4l9 16H3z"/><path d="M12 10v4M12 17.2v.1"/>',
  user: '<circle cx="12" cy="8.5" r="3.5"/><path d="M5 20c1-3.5 3.8-5.5 7-5.5s6 2 7 5.5"/>',
  logout: '<path d="M14 4h5v16h-5M10 8l-4 4 4 4M6 12h10"/>',
  creditcard: '<rect x="2.5" y="5" width="19" height="14" rx="2"/><path d="M2.5 9.5h19M6 15h4.5"/>',
  bank: '<path d="M3 9.5L12 4l9 5.5M4.5 9.5h15M6 10.5v6.5M10 10.5v6.5M14 10.5v6.5M18 10.5v6.5M3.5 20h17"/>',
  wifi: '<path d="M2.5 9a14 14 0 0 1 19 0M5.5 12.3a9.5 9.5 0 0 1 13 0M8.6 15.5a5 5 0 0 1 6.8 0"/><circle cx="12" cy="19" r="1.3" fill="currentColor"/>',
  qr: '<rect x="3.5" y="3.5" width="6.5" height="6.5" rx="1"/><rect x="14" y="3.5" width="6.5" height="6.5" rx="1"/><rect x="3.5" y="14" width="6.5" height="6.5" rx="1"/><path d="M14 14h2.5v2.5H14zM18 18h2.5v2.5H18zM14 20.5h1M20.5 14v1"/>',
  star: '<path d="M12 3.6l2.6 5.3 5.8.8-4.2 4.1 1 5.8-5.2-2.7-5.2 2.7 1-5.8-4.2-4.1 5.8-.8z"/>',
  starFill: '<path d="M12 3.6l2.6 5.3 5.8.8-4.2 4.1 1 5.8-5.2-2.7-5.2 2.7 1-5.8-4.2-4.1 5.8-.8z" fill="currentColor"/>',
  sort: '<path d="M7 4v16M3.5 16.5L7 20l3.5-3.5M13.5 6H21M13.5 11h5.5M13.5 16h3"/>',
  cloud: '<path d="M7 18.5h10.5a4 4 0 0 0 .6-7.95A6 6 0 0 0 6.6 9.1 4.75 4.75 0 0 0 7 18.5z"/><path d="M9.6 13.6l1.8 1.8 3.2-3.3"/>',
  cloudOff: '<path d="M7 18.5h10.5a4 4 0 0 0 .6-7.95A6 6 0 0 0 6.6 9.1 4.75 4.75 0 0 0 7 18.5z"/><path d="M3.5 3.5l17 17"/>',
  cloudUp: '<path d="M7 18.5h10.5a4 4 0 0 0 .6-7.95A6 6 0 0 0 6.6 9.1 4.75 4.75 0 0 0 7 18.5z"/><path d="M12 16.2v-4.6M9.9 13.6l2.1-2.1 2.1 2.1"/>',
  restore: '<path d="M8.5 13.5L4 9l4.5-4.5"/><path d="M4 9h10.5a5.5 5.5 0 0 1 0 11H10"/>',
  history: '<path d="M4 12a8 8 0 1 0 2.4-5.7L4 8.7"/><path d="M4 4v4.7h4.7M12 8v4.2l2.8 1.8"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.4 2.6 3.7 5.6 3.7 9s-1.3 6.4-3.7 9c-2.4-2.6-3.7-5.6-3.7-9S9.6 5.6 12 3z"/>',
  code: '<path d="M8.5 7.5L4 12l4.5 4.5M15.5 7.5L20 12l-4.5 4.5M13.6 5l-3.2 14"/>',
  sparkle: '<path d="M12 3.5c.7 4.4 2.3 6 6.5 6.6-4.2.6-5.8 2.2-6.5 6.6-.7-4.4-2.3-6-6.5-6.6 4.2-.6 5.8-2.2 6.5-6.6z"/><path d="M18.5 15.5c.3 1.6.9 2.2 2.5 2.5-1.6.3-2.2.9-2.5 2.5-.3-1.6-.9-2.2-2.5-2.5 1.6-.3 2.2-.9 2.5-2.5z"/>',
  // The Southern Cross, as on the Australian flag
  southernCross: [[12, 19.2, 3.4], [4.9, 11, 3], [12, 4.6, 3], [19, 9.4, 2.6], [15.1, 13.6, 1.7]].map(([cx, cy, r]) => {
    const pts = [];
    for (let i = 0; i < 10; i++) {
      const a = -Math.PI / 2 + (i * Math.PI) / 5;
      const rr = i % 2 ? r * 0.45 : r;
      pts.push(`${(cx + rr * Math.cos(a)).toFixed(2)},${(cy + rr * Math.sin(a)).toFixed(2)}`);
    }
    return `<polygon points="${pts.join(' ')}" fill="currentColor" stroke="none"/>`;
  }).join(''),
};

function icon(name, cls = '') {
  const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  s.setAttribute('viewBox', '0 0 24 24');
  s.setAttribute('class', `ic ${cls}`.trim());
  s.setAttribute('aria-hidden', 'true');
  s.innerHTML = ICONS[name] || '';
  return s;
}

function btn(label, { kind = 'primary', icon: ic, onClick, type = 'button', block, small, cls = '' } = {}) {
  return h('button', {
    type,
    class: ['btn', `btn-${kind}`, block && 'btn-block', small && 'btn-small', cls].filter(Boolean).join(' '),
    onclick: onClick,
  }, ic && icon(ic), label && h('span', { class: 'btn-label' }, label));
}

function iconBtn(name, label, onClick, cls = 'ghost') {
  return h('button', { type: 'button', class: `icon-btn ${cls}`, 'aria-label': label, title: label, onclick: onClick }, icon(name));
}

function setBusy(button, on, text) {
  button.disabled = on;
  button.classList.toggle('loading', on);
  const span = button.querySelector('.btn-label');
  if (span && text) span.textContent = text;
}

function field(labelText, control, hint) {
  return h('label', { class: 'field' },
    h('span', { class: 'field-label' }, labelText),
    control,
    hint && h('span', { class: 'field-hint' }, hint));
}

const noAssist = { autocapitalize: 'off', autocorrect: 'off', spellcheck: 'false' };

function pwInput(props = {}) {
  const input = h('input', { class: 'input', type: 'password', ...noAssist, ...props });
  let shown = false;
  const toggle = h('button', {
    type: 'button', class: 'input-adorn', 'aria-label': 'Show password',
    onclick: () => {
      shown = !shown;
      input.type = shown ? 'text' : 'password';
      toggle.replaceChildren(icon(shown ? 'eyeOff' : 'eye'));
      toggle.setAttribute('aria-label', shown ? 'Hide password' : 'Show password');
      input.focus();
    },
  }, icon('eye'));
  return { input, wrap: h('div', { class: 'input-wrap' }, input, toggle) };
}

function strengthMeter() {
  const bar = h('div', { class: 'meter-bar' }, h('i'), h('i'), h('i'), h('i'));
  const text = h('span', { class: 'meter-text' });
  const el = h('div', { class: 'meter', 'data-score': '-1' }, bar, text);
  return {
    el,
    update(pw) {
      const st = vc.passwordStrength(pw);
      el.dataset.score = pw ? String(st.score) : '-1';
      text.textContent = pw ? st.label : '';
    },
  };
}

// Focus a field shortly after a screen opens, unless the user is already typing somewhere.
function focusSoon(el, ms = 60) {
  setTimeout(() => {
    const a = document.activeElement;
    if (el.isConnected && (!a || a === document.body)) el.focus();
  }, ms);
}

function screen(cls, ...kids) {
  S.view = cls;
  S.repaint = null;
  S.editing = null;
  S.onBack = null;
  closeOverlays();
  app.replaceChildren(h('main', { class: `screen ${cls}` }, ...kids));
  window.scrollTo(0, 0);
}

function topbar({ left, title, right }) {
  return h('header', { class: 'topbar' },
    h('div', { class: 'topbar-side' }, left),
    h('div', { class: 'topbar-title' }, title),
    h('div', { class: 'topbar-side right' }, right));
}

function typeTile(type, big = false) {
  const t = TYPES[type] || TYPES.note;
  return h('div', { class: `tile t-${t.color}${big ? ' tile-big' : ''}` }, icon(t.icon));
}

function brandMark(name) {
  if (!name) return h('img', { class: 'brand-logo', src: 'icons/logo.svg', alt: '', width: '64', height: '64' });
  return h('div', { class: 'brand-mark' }, icon(name));
}

function wordmark(cls = '') {
  return h('span', { class: `wordmark ${cls}`.trim() }, h('span', { class: 'wm-cyber' }, 'Cyber'), h('span', { class: 'wm-vault' }, 'Vault'));
}

// ---------- toasts, sheets, busy overlay ----------

function toast(msg, kind = '') {
  const host = document.getElementById('toasts');
  host.replaceChildren();
  const t = h('div', { class: `toast ${kind}`, role: kind === 'error' ? 'alert' : 'status' }, msg);
  host.append(t);
  void t.offsetWidth;
  t.classList.add('show');
  setTimeout(() => {
    t.classList.remove('show');
    setTimeout(() => t.remove(), 250);
  }, kind === 'error' ? 4500 : 2400);
}

function openSheet(build, { cls = '', onClose } = {}) {
  const backdrop = h('div', { class: `backdrop ${cls}` });
  const panel = h('div', { class: `sheet ${cls}`, role: 'dialog', 'aria-modal': 'true' });
  let closed = false;
  const onKey = (e) => { if (e.key === 'Escape') close(); };
  function close() {
    if (closed) return;
    closed = true;
    S.overlays.delete(close);
    document.removeEventListener('keydown', onKey);
    backdrop.classList.remove('show');
    panel.classList.remove('show');
    setTimeout(() => { backdrop.remove(); panel.remove(); }, 220);
    onClose?.();
  }
  backdrop.addEventListener('click', close);
  document.addEventListener('keydown', onKey);
  panel.append(...[].concat(build(close)).filter(Boolean));
  document.body.append(backdrop, panel);
  void panel.offsetWidth;
  backdrop.classList.add('show');
  panel.classList.add('show');
  S.overlays.add(close);
  return close;
}

function closeOverlays() {
  for (const close of [...S.overlays]) close();
}

function confirmSheet({ title, message, confirmLabel = 'Confirm', danger = false }) {
  return new Promise((resolve) => {
    let answer = false;
    openSheet((close) => [
      h('h3', { class: 'sheet-title' }, title),
      message && h('p', { class: 'muted' }, message),
      h('div', { class: 'sheet-actions' },
        btn('Cancel', { kind: 'secondary', onClick: close }),
        btn(confirmLabel, { kind: danger ? 'danger' : 'primary', onClick: () => { answer = true; close(); } })),
    ], { onClose: () => resolve(answer) });
  });
}

function busy(text) {
  const el = h('div', { class: 'busy', role: 'status' }, h('div', { class: 'spinner' }), h('p', null, text));
  document.body.append(el);
  return (next) => {
    if (typeof next === 'string') el.querySelector('p').textContent = next;
    else el.remove();
  };
}

// =====================================================================
// Copy and long-press
// =====================================================================

function legacyCopy(text) {
  const ta = h('textarea', { class: 'clip-helper', readonly: true });
  ta.value = text;
  document.body.append(ta);
  ta.select();
  ta.setSelectionRange(0, text.length);
  let ok = false;
  try { ok = document.execCommand('copy'); } catch { ok = false; }
  ta.remove();
  return ok;
}

async function copyText(text, label = 'Copied', { sensitive = true } = {}) {
  if (!text) return;
  const sec = sensitive ? settings.clearClipSec : 0;
  let ok = false;
  if (android) {
    // Native: marks secrets as sensitive (hidden in Android's copy preview) and clears them later.
    try { ok = !!android.copyText(String(text), !!sensitive, sec); } catch { ok = false; }
  } else {
    try {
      await navigator.clipboard.writeText(text);
      ok = true;
    } catch {
      ok = legacyCopy(text);
    }
  }
  if (!ok) return toast('Your browser blocked copying. Try the copy button.', 'error');
  navigator.vibrate?.(15);
  toast(sec ? `${label} · clears in ${sec}s` : label);
  if (!sensitive || android) return;
  clearTimeout(S.clipTimer);
  if (sec > 0) S.clipTimer = setTimeout(clearClipboard, sec * 1000);
}

function clearClipboard() {
  // Best effort: browsers only allow this while the app is open and focused.
  try { navigator.clipboard?.writeText(' ').catch(() => {}); } catch { /* ignore */ }
}

/**
 * Tap and long-press on the same element.
 * The copy runs when the finger lifts after a long press. That release counts as
 * a user gesture, which iPhone Safari requires before it allows clipboard access.
 */
function onPress(el, { onTap, onLong, ms = 450 } = {}) {
  let timer = null;
  let armed = false;
  let suppressClick = false;
  let sx = 0;
  let sy = 0;
  const reset = () => {
    clearTimeout(timer);
    timer = null;
    armed = false;
    el.classList.remove('pressing', 'armed');
  };
  el.addEventListener('pointerdown', (e) => {
    if (e.button > 0 || !onLong) return;
    const inner = e.target.closest('button, a, input');
    if (inner && inner !== el) return;
    reset();
    sx = e.clientX;
    sy = e.clientY;
    el.classList.add('pressing');
    timer = setTimeout(() => {
      armed = true;
      el.classList.remove('pressing');
      el.classList.add('armed');
      navigator.vibrate?.(10);
    }, ms);
  });
  el.addEventListener('pointermove', (e) => {
    if ((timer || armed) && Math.hypot(e.clientX - sx, e.clientY - sy) > 12) reset();
  });
  el.addEventListener('pointerup', () => {
    const fire = armed;
    reset();
    if (fire) {
      suppressClick = true;
      setTimeout(() => { suppressClick = false; }, 450);
      onLong();
    }
  });
  el.addEventListener('pointercancel', reset);
  el.addEventListener('contextmenu', (e) => { if (onLong) e.preventDefault(); });
  el.addEventListener('click', (e) => {
    if (suppressClick) {
      suppressClick = false;
      e.preventDefault();
      e.stopPropagation();
      return;
    }
    if (e.target.closest('button, a, input') && e.target.closest('button, a, input') !== el) return;
    onTap?.(e);
  });
}

// =====================================================================
// Navigation
// =====================================================================

const curHash = () => location.hash || '#/';

function go(hash) {
  S.nav.push(curHash());
  location.hash = hash;
}

function back(fallback = '#/') {
  if (S.nav.length) history.back();
  else location.replace(fallback);
}

window.addEventListener('hashchange', () => {
  if (S.nav.length && S.nav[S.nav.length - 1] === curHash()) S.nav.pop();
  render();
});

function render() {
  if (!S.key) return;
  const m = curHash().match(/^#\/([^/]*)\/?(.*)$/) || [];
  const view = m[1] || '';
  const arg = decodeURIComponent(m[2] || '');
  if (view !== 'item') S.revealed.clear();
  switch (view) {
    case 'item': return renderDetail(arg);
    case 'edit': return renderEditor(arg, null);
    case 'new': return renderEditor(null, arg);
    case 'settings': return renderSettings();
    case 'bin': return renderBin();
    default: return renderList();
  }
}

// =====================================================================
// Errors
// =====================================================================

function authMessage(e) {
  const code = e?.code || '';
  const map = {
    'auth/invalid-credential': 'Email or password is incorrect.',
    'auth/wrong-password': 'Email or password is incorrect.',
    'auth/user-not-found': 'Email or password is incorrect.',
    'auth/invalid-email': 'That email address doesn\'t look right.',
    'auth/missing-password': 'Enter your account password.',
    'auth/email-already-in-use': 'An account with this email already exists. Sign in instead.',
    'auth/weak-password': 'Account password must be at least 6 characters.',
    'auth/too-many-requests': 'Too many attempts. Wait a few minutes and try again.',
    'auth/network-request-failed': 'Network error. Check your internet connection.',
    'auth/popup-blocked': 'The sign-in popup was blocked. Allow popups for this site and try again.',
    'auth/operation-not-allowed': 'This sign-in method is turned off. Turn it on in Firebase → Authentication → Sign-in method.',
    'auth/invalid-login-credentials': 'Email or password is incorrect.',
    'auth/configuration-not-found': 'Sign-in isn\'t set up in this Firebase project yet. Open Authentication → Get started, then turn on Google and/or Email/Password.',
    'auth/invalid-api-key': 'The apiKey in your Firebase config isn\'t valid. Use a different project and paste the config again.',
    'auth/api-key-not-valid': 'The apiKey in your Firebase config isn\'t valid. Use a different project and paste the config again.',
    'auth/api-key-not-valid.-please-pass-a-valid-api-key.': 'The apiKey in your Firebase config isn\'t valid. Use a different project and paste the config again.',
    'auth/invalid-phone-number': 'That phone number doesn\'t look right. Check the country code.',
    'auth/missing-phone-number': 'Enter your phone number.',
    'auth/invalid-verification-code': 'That code isn\'t right. Check the text message and try again.',
    'auth/missing-verification-code': 'Enter the 6-digit code from the text message.',
    'auth/code-expired': 'That code has expired. Send a new one.',
    'auth/captcha-check-failed': 'The security check failed. Reload the page and try again.',
    'auth/quota-exceeded': 'Too many text messages were sent today. Try again later.',
    'auth/billing-not-enabled': 'Text-message codes need Firebase\'s Blaze (pay-as-you-go) plan. Upgrade the project in the Firebase console, then try again.',
    'auth/credential-already-in-use': 'That phone number is already linked to another account.',
    'auth/provider-already-linked': 'A phone number is already linked. Remove it first.',
    'auth/requires-recent-login': 'For security, sign out and sign in again, then try once more.',
    'auth/unauthorized-domain': `This website (${location.hostname}) isn't authorised. Add it in Firebase → Authentication → Settings → Authorized domains.`,
  };
  if (code === 'auth/popup-closed-by-user' || code === 'auth/cancelled-popup-request') return '';
  return map[code] || e?.message || 'Something went wrong.';
}

function dbMessage(e) {
  const code = e?.code || '';
  if (code === 'permission-denied') {
    return 'Firestore rules are blocking access. Publish the CyberVault rules in Firebase → Firestore Database → Rules.';
  }
  if (code === 'unavailable') {
    return navigator.onLine
      ? 'Can\'t reach Firebase. Check your internet connection.'
      : 'You\'re offline, and this device doesn\'t have a saved copy of the vault yet. Connect to the internet once to set it up for offline use.';
  }
  if (code === 'not-found' || code === 'failed-precondition') {
    return 'There\'s no Firestore database in this project yet. In the Firebase console open Firestore Database → Create database.';
  }
  if (code === 'resource-exhausted') return 'Firebase\'s free daily limit was reached. Try again tomorrow.';
  return e?.message || 'Something went wrong.';
}

/** For things that need the server (creating a vault, changing the master password…). */
function onlineOr(errEl) {
  if (navigator.onLine) return true;
  const msg = 'You\'re offline. Connect to the internet and try again.';
  if (errEl) errEl.textContent = msg;
  else toast(msg, 'error');
  return false;
}

// =====================================================================
// Lock / unlock
// =====================================================================

function lock(show = true) {
  stopSync();
  S.key = null;
  S.items = new Map();
  S.server = new Map();
  S.local = new Map();
  S.revs = new Map();
  S.synced = false;
  S.editing = null;
  S.repaint = null;
  for (const { url } of S.photoCache.values()) URL.revokeObjectURL(url);
  S.photoCache.clear();
  S.photoLoads.clear();
  for (const url of S.tempUrls) URL.revokeObjectURL(url);
  S.tempUrls.clear();
  S.revealed.clear();
  S.nav = [];
  S.query = '';
  closeOverlays();
  document.getElementById('toasts').replaceChildren();
  document.body.classList.remove('veiled');
  if (show && S.user && S.meta) {
    history.replaceState(null, '', '#/');
    renderUnlock();
  }
}

for (const ev of ['pointerdown', 'keydown', 'wheel', 'touchstart']) {
  window.addEventListener(ev, () => { S.lastActivity = Date.now(); }, { passive: true, capture: true });
}

function idleExpired() {
  return settings.autoLockMin > 0 && Date.now() - S.lastActivity > settings.autoLockMin * 60_000;
}

setInterval(() => { if (S.key && idleExpired()) lock(); }, 5000);

function onAppHidden() {
  if (S.hiddenAt) return; // already hidden (the Android app and the page can both report it)
  S.hiddenAt = Date.now();
  if (S.key) document.body.classList.add('veiled'); // hides content in the app switcher
  if (S.key && settings.bgLockSec === 0) lock();
}

function onAppShown() {
  const away = S.hiddenAt ? Date.now() - S.hiddenAt : 0;
  S.hiddenAt = null;
  document.body.classList.remove('veiled');
  if (S.key && ((settings.bgLockSec >= 0 && away >= settings.bgLockSec * 1000) || idleExpired())) lock();
}

document.addEventListener('visibilitychange', () => (document.hidden ? onAppHidden() : onAppShown()));

// Called by the Android app (MainActivity): lifecycle and the back button.
window.__cvAppState = (state) => (state === 'background' ? onAppHidden() : onAppShown());
window.__cvBack = () => {
  if (S.overlays.size) { closeOverlays(); return 'handled'; }
  if (S.onBack) { S.onBack(); return 'handled'; } // e.g. the editor asks before discarding changes
  if (S.key && curHash().startsWith('#/bin')) { back('#/settings'); return 'handled'; }
  if (S.key && curHash() !== '#/') { back('#/'); return 'handled'; }
  if (!S.key && S.view.includes('recover')) { renderUnlock(); return 'handled'; }
  return 'exit';
};

// =====================================================================
// Data: live sync, offline changes and edit conflicts
//
// Every item document carries a random `rev` (not secret) next to its ciphertext. A save
// only goes through if the server still has the revision the edit started from, so a newer
// change from another device is never silently overwritten. Offline, changes wait in an
// "outbox" on this device (ciphertext only) and are sent, with the same check, once the
// connection is back. Photos are written through Firestore's own offline queue.
// =====================================================================

const BIN_DAYS = 30;
const DAY = 86_400_000;
const HISTORY_MAX = 20;

class ConflictError extends Error {
  constructor(server) {
    super('This item was changed on another device.');
    this.name = 'ConflictError';
    this.server = server; // the server's record, or null if it was deleted
  }
}

class OfflineError extends Error {
  constructor() {
    super('You\'re offline.');
    this.name = 'OfflineError';
    this.code = 'unavailable';
  }
}

function newId() {
  return [...crypto.getRandomValues(new Uint8Array(12))].map((b) => b.toString(16).padStart(2, '0')).join('');
}
const newRev = () => newId().slice(0, 16);
const baseOf = (id) => S.revs.get(id) ?? 'none';
const isOffline = (e) => e instanceof OfflineError || e?.code === 'unavailable' || e?.code === 'deadline-exceeded' || !navigator.onLine;

function withTimeout(promise, ms) {
  let t;
  const timer = new Promise((_, reject) => { t = setTimeout(() => reject(new OfflineError()), ms); });
  return Promise.race([promise, timer]).finally(() => clearTimeout(t));
}

/** getDoc that falls back to this device's copy quickly when offline. */
async function getDocFast(ref) {
  if (!navigator.onLine) {
    try { return await getDocFromCache(ref); } catch { /* not saved on this device */ }
  }
  try {
    return await withTimeout(getDoc(ref), 6000);
  } catch (e) {
    if (!isOffline(e)) throw e;
    try { return await getDocFromCache(ref); } catch { throw new OfflineError(); }
  }
}

/**
 * Commit a batch through Firestore's offline queue. Once committed it is kept on this device
 * until it reaches the server, so when offline there's no need to wait for that.
 */
function commitQueued(batch) {
  const p = batch.commit();
  p.catch((e) => { if (!isOffline(e)) toast(dbMessage(e), 'error'); });
  if (!navigator.onLine) return Promise.resolve();
  return withTimeout(p, 30_000).catch((e) => { if (!isOffline(e)) throw e; });
}

function normalizeItem(it, id) {
  it.id = id;
  it.fields = Array.isArray(it.fields) ? it.fields : [];
  it.photos = Array.isArray(it.photos) ? it.photos : [];
  return it;
}

function rebuildItems() {
  const items = new Map(S.server);
  for (const [id, it] of S.local) {
    if (it) items.set(id, it);
    else items.delete(id);
  }
  S.items = items;
}

const liveItems = () => [...S.items.values()].filter((it) => !it.deletedAt);
const binItems = () => [...S.items.values()].filter((it) => it.deletedAt);

// ---------- the outbox: changes made offline, waiting to sync ----------

const outboxKey = () => `cybervault.outbox.${activeConfig?.projectId}.${uid()}`;

function readOutbox() {
  try {
    const v = JSON.parse(localStorage.getItem(outboxKey()) || '[]');
    return Array.isArray(v) ? v : [];
  } catch {
    return [];
  }
}

function writeOutbox(list) {
  if (list.length) localStorage.setItem(outboxKey(), JSON.stringify(list));
  else localStorage.removeItem(outboxKey());
}

const pendingIds = () => new Set(readOutbox().map((e) => e.id));

/** Keep a change on this device until it can be sent. One entry per item. */
function queueChange(entry, item) {
  const list = readOutbox();
  const i = list.findIndex((e) => e.id === entry.id);
  if (i >= 0) {
    const prev = list[i];
    if (entry.op === 'delete' && prev.base === 'none') {
      // Created and then deleted while offline: the server never needs to hear about it.
      list.splice(i, 1);
      writeOutbox(list);
      S.local.delete(entry.id);
      deleteBlobs([...(prev.drop || []), ...(entry.drop || [])], entry.id);
      return;
    }
    entry.base = prev.base; // still checked against the version the server last had
    entry.chain = [...(prev.chain || []), ...(prev.rev ? [prev.rev] : [])];
    entry.drop = [...(prev.drop || []), ...(entry.drop || [])];
    list[i] = entry;
  } else {
    list.push(entry);
  }
  try {
    writeOutbox(list);
  } catch {
    throw new Error('This device has no room left to keep offline changes. Connect to the internet and try again.');
  }
  S.local.set(entry.id, item);
}

function dropFromOutbox(entry) {
  writeOutbox(readOutbox().filter((e) => !(e.id === entry.id && e.at === entry.at)));
  S.local.delete(entry.id);
}

/** Decrypt the changes waiting in the outbox, so they show while offline and after a restart. */
async function loadLocalChanges(key) {
  S.local = new Map();
  for (const e of readOutbox()) {
    if (e.op === 'delete') { S.local.set(e.id, null); continue; }
    try {
      S.local.set(e.id, normalizeItem(await vc.decryptJSON(key, e.rec, aadItem(e.id)), e.id));
    } catch { /* from another vault key: leave it */ }
  }
}

/**
 * Write (rec) or delete (rec = null) one item, but only if the server still has `base`.
 * `chain` lists earlier revisions of the same change from this device, which are fine to replace.
 */
function txWrite(id, rec, base, chain = []) {
  return runTransaction(db, async (tx) => {
    const snap = await tx.get(itemRef(id));
    const cur = snap.exists() ? (snap.data().rev || 'legacy') : 'none';
    if (rec ? cur === rec.rev : cur === 'none') return 'already'; // an earlier attempt already landed
    if (cur !== base && !chain.includes(cur)) throw new ConflictError(snap.exists() ? snap.data() : null);
    if (rec) tx.set(itemRef(id), rec);
    else tx.delete(itemRef(id));
    return 'done';
  });
}

/**
 * Save an item. Online, it is checked against the server first and throws ConflictError if
 * another device changed it since `base`. Offline, it is kept on this device and synced later.
 * Returns 'saved' or 'queued'.
 */
async function putItem(id, item, { base = baseOf(id), drop = [] } = {}) {
  const key = S.key;
  const { id: _omit, ...payload } = item;
  const rev = newRev();
  const rec = { ...(await vc.encryptJSON(key, payload, aadItem(id))), rev };
  if (S.key !== key) throw new Error('The vault was locked.');
  S.mine.add(rev);
  const saved = normalizeItem({ ...payload }, id);
  if (navigator.onLine && !pendingIds().has(id)) {
    try {
      await withTimeout(txWrite(id, rec, base), 12_000);
      S.superseded.add(`${id}:${base}`);
      S.server.set(id, saved);
      S.revs.set(id, rev);
      rebuildItems();
      deleteBlobs(drop, id);
      return 'saved';
    } catch (e) {
      if (!isOffline(e)) throw e;
    }
  }
  queueChange({ op: 'set', id, base, rev, rec, drop, at: Date.now() }, saved);
  rebuildItems();
  scheduleFlush();
  updateSyncStatus();
  return 'queued';
}

/** Delete an item for good (from Recently deleted). */
async function purgeItem(it) {
  const base = baseOf(it.id);
  if (navigator.onLine && !pendingIds().has(it.id)) {
    try {
      await withTimeout(txWrite(it.id, null, base), 12_000);
      S.superseded.add(`${it.id}:${base}`);
      S.server.delete(it.id);
      S.revs.delete(it.id);
      rebuildItems();
      deleteBlobs(it.photos, it.id);
      return 'deleted';
    } catch (e) {
      if (e instanceof ConflictError) {
        await adoptServer(it.id, e.server);
        throw e;
      }
      if (!isOffline(e)) throw e;
    }
  }
  queueChange({ op: 'delete', id: it.id, base, drop: it.photos, at: Date.now() }, null);
  rebuildItems();
  scheduleFlush();
  updateSyncStatus();
  return 'queued';
}

/** Use the server's version of an item (after a conflict). */
async function adoptServer(id, data) {
  if (!data) {
    S.server.delete(id);
    S.revs.delete(id);
  } else {
    S.server.set(id, normalizeItem(await vc.decryptJSON(S.key, data, aadItem(id)), id));
    S.revs.set(id, data.rev || 'legacy');
  }
  rebuildItems();
}

/** A small change (favourite, move to bin, restore…) applied on top of the newest version. */
async function updateItem(id, change) {
  for (let attempt = 0; attempt < 3; attempt++) {
    const cur = S.items.get(id);
    if (!cur) throw new Error('This item no longer exists.');
    const next = change(structuredClone(cur));
    try {
      return await putItem(id, next);
    } catch (e) {
      if (!(e instanceof ConflictError)) throw e;
      await adoptServer(id, e.server);
    }
  }
  throw new Error('This item keeps changing on another device. Try again in a moment.');
}

// ---------- sending the outbox ----------

let flushTimer = null;
function scheduleFlush(ms = 1500) {
  clearTimeout(flushTimer);
  flushTimer = setTimeout(() => { flushOutbox().catch(() => {}); }, ms);
}

async function flushOutbox() {
  if (S.flushing || !S.key || !navigator.onLine || !readOutbox().length) return;
  const key = S.key;
  S.flushing = true;
  updateSyncStatus();
  const notes = [];
  try {
    // Photos saved offline go first, so other devices don't see an item before its photos.
    await withTimeout(waitForPendingWrites(db), 20_000).catch(() => {});
    for (const e of readOutbox()) {
      if (S.key !== key) return;
      try {
        await withTimeout(txWrite(e.id, e.op === 'set' ? e.rec : null, e.base, e.chain), 12_000);
        for (const r of [e.base, ...(e.chain || [])]) S.superseded.add(`${e.id}:${r}`);
        if (e.op === 'set') {
          const it = S.local.get(e.id);
          if (it) S.server.set(e.id, it);
          S.revs.set(e.id, e.rec.rev);
        } else {
          S.server.delete(e.id);
          S.revs.delete(e.id);
        }
        dropFromOutbox(e);
        deleteBlobs(e.drop || [], e.id);
      } catch (err) {
        if (err instanceof ConflictError) {
          notes.push(await resolveOfflineConflict(e, err, key));
          dropFromOutbox(e);
        } else if (isOffline(err)) {
          break;
        } else {
          toast(`Couldn't sync a change: ${dbMessage(err)}`, 'error');
          break;
        }
      }
    }
  } finally {
    S.flushing = false;
    rebuildItems();
    updateSyncStatus();
    refreshView();
  }
  const msg = notes.filter(Boolean);
  if (msg.length) infoSheet('Synced, with a clash', msg.join(' '));
  else if (!readOutbox().length) toast('Offline changes synced');
}

/** Another device changed an item that was also changed here while offline: keep both. */
async function resolveOfflineConflict(e, err, key) {
  await adoptServer(e.id, err.server);
  const theirs = S.server.get(e.id);
  if (e.op === 'delete') {
    return `“${theirs?.title || 'An item'}” was changed on another device after you deleted it here, so it was kept.`;
  }
  const mine = normalizeItem(await vc.decryptJSON(key, e.rec, aadItem(e.id)), e.id);
  if (!theirs) {
    // Deleted for good on the other device: put this device's version back.
    await putItem(e.id, mine, { base: 'none' });
    return `“${mine.title}” was deleted on another device, but you'd changed it here, so your version was kept.`;
  }
  const copy = { ...mine, title: `${mine.title} (offline copy)` };
  await putItem(newId(), copy, { base: 'none' });
  return `“${theirs.title}” was changed on another device while you were offline. Both versions were kept: yours is “${copy.title}”.`;
}

window.addEventListener('online', () => { updateSyncStatus(); scheduleFlush(500); });
window.addEventListener('offline', () => updateSyncStatus());
setInterval(() => { if (S.key && navigator.onLine && readOutbox().length) flushOutbox().catch(() => {}); }, 30_000);

// ---------- the live listener ----------

function stopSync() {
  S.unsub?.();
  S.unsub = null;
}

/** Listen to the vault. Resolves after the first snapshot (from this device's copy if offline). */
function startSync() {
  stopSync();
  const key = S.key;
  S.server = new Map();
  S.local = new Map();
  S.revs = new Map();
  S.superseded = new Set();
  S.synced = false;
  S.chain = Promise.resolve();
  return new Promise((resolve, reject) => {
    let first = true;
    S.unsub = onSnapshot(itemsCol(), { includeMetadataChanges: true }, (snap) => {
      S.chain = S.chain.then(async () => {
        if (S.key !== key) return;
        const { remote, failed } = await applySnapshot(snap, key);
        if (S.key !== key) return;
        if (first) {
          first = false;
          await loadLocalChanges(key);
          rebuildItems();
          S.synced = true;
          if (failed) toast(`${failed} item(s) couldn't be decrypted`, 'error');
          resolve();
          afterUnlock(key);
        } else {
          onSnapshotApplied(remote);
        }
      }).catch(() => {});
    }, (err) => {
      if (first) { first = false; reject(err); } else toast(dbMessage(err), 'error');
    });
  });
}

async function applySnapshot(snap, key) {
  const wasCache = S.fromCache;
  S.fromCache = snap.metadata.fromCache;
  if (S.fromCache && !wasCache) {
    S.fromCacheAt = Date.now();
    setTimeout(updateSyncStatus, 3000);
  }
  S.pendingWrites = snap.metadata.hasPendingWrites;
  const remote = [];
  let failed = 0;
  for (const ch of snap.docChanges()) {
    const id = ch.doc.id;
    if (ch.type === 'removed') {
      if (S.server.delete(id)) remote.push(id);
      S.revs.delete(id);
      continue;
    }
    const data = ch.doc.data();
    const rev = data.rev || 'legacy';
    if (S.revs.get(id) === rev && S.server.has(id)) continue;
    if (S.superseded.has(`${id}:${rev}`)) continue; // an older version this device already replaced
    try {
      const it = normalizeItem(await vc.decryptJSON(key, data, aadItem(id)), id);
      if (S.key !== key) return { remote, failed };
      S.server.set(id, it);
      S.revs.set(id, rev);
      if (!S.mine.has(rev)) remote.push(id);
    } catch {
      failed++;
    }
  }
  rebuildItems();
  return { remote, failed };
}

const route = () => {
  const m = curHash().match(/^#\/([^/]*)\/?(.*)$/) || [];
  return { view: m[1] || '', arg: decodeURIComponent(m[2] || '') };
};

/** Show changes that arrived from another device. */
function onSnapshotApplied(remote) {
  const r = route();
  if (S.editing) {
    if (remote.includes(S.editing.id)) S.editing.onRemote();
  } else if (r.view === 'item' && remote.includes(r.arg)) {
    if (!S.items.has(r.arg)) {
      toast('Deleted on another device');
      location.replace('#/');
    } else {
      renderDetail(r.arg);
      toast('Updated on another device');
    }
  }
  refreshView();
}

/** Repaint the list / bin / settings in place, without losing what the user is typing. */
function refreshView() {
  S.repaint?.();
}

function updateSyncStatus() {
  S.repaint?.();
}

function syncState() {
  const pending = S.user ? readOutbox().length : 0;
  const offline = !navigator.onLine || (S.fromCache && Date.now() - S.fromCacheAt > 2500);
  return { offline, pending, busy: S.flushing || S.pendingWrites };
}

// ---------- after unlocking: sync, tidy up, and keep photos for offline use ----------

function afterUnlock(key) {
  flushOutbox().catch(() => {}).then(async () => {
    if (S.key !== key || !navigator.onLine) return;
    // Recently deleted items are removed for good after 30 days.
    for (const it of binItems()) {
      if (Date.now() - it.deletedAt > BIN_DAYS * DAY) {
        try { await purgeItem(it); } catch { /* try again next time */ }
      }
    }
    refreshView();
    await prefetchPhotos(key);
  });
}

/** Download photos this device doesn't have yet, so they can be opened offline. */
async function prefetchPhotos(key) {
  for (const it of liveItems()) {
    for (const p of it.photos) {
      for (let i = 0; i < p.n; i++) {
        if (S.key !== key || !navigator.onLine) return;
        try {
          await getDocFromCache(blobRef(p.id, i));
        } catch {
          try { await withTimeout(getDoc(blobRef(p.id, i)), 30_000); } catch { /* next time */ }
        }
      }
    }
  }
}

// ---------- photos ----------

async function prepareImage(file) {
  let bmp;
  try {
    bmp = await createImageBitmap(file, { imageOrientation: 'from-image' });
  } catch {
    throw new Error(`Can't read "${file.name}". Try a JPG or PNG photo.`);
  }
  const max = 2000;
  const scale = Math.min(1, max / Math.max(bmp.width, bmp.height));
  const w = Math.round(bmp.width * scale);
  const hgt = Math.round(bmp.height * scale);
  const canvas = document.createElement('canvas');
  canvas.width = w;
  canvas.height = hgt;
  canvas.getContext('2d').drawImage(bmp, 0, 0, w, hgt);
  bmp.close?.();
  // Re-encoding also strips EXIF metadata, such as GPS location.
  const blob = await new Promise((res) => canvas.toBlob(res, 'image/jpeg', 0.85));
  if (!blob) throw new Error('Couldn\'t process the photo.');
  return { blob, w, h: hgt, mime: 'image/jpeg' };
}

async function uploadPhoto(img) {
  const id = newId();
  const bytes = new Uint8Array(await img.blob.arrayBuffer());
  const packed = await vc.encryptBytes(S.key, bytes, aadBlob(id));
  const b64 = vc.b64encode(packed);
  const n = Math.ceil(b64.length / CHUNK_CHARS);
  const batch = writeBatch(db);
  for (let i = 0; i < n; i++) batch.set(blobRef(id, i), { d: b64.slice(i * CHUNK_CHARS, (i + 1) * CHUNK_CHARS) });
  await commitQueued(batch);
  S.photoCache.set(id, { url: URL.createObjectURL(img.blob), blob: img.blob });
  return { id, n, w: img.w, h: img.h, mime: img.mime };
}

/** A photo chunk: from this device's copy if it has one (photos never change), else the server. */
async function getChunk(ref) {
  try {
    const s = await getDocFromCache(ref);
    if (s.exists()) return s;
  } catch { /* not on this device yet */ }
  return withTimeout(getDoc(ref), 30_000);
}

function loadPhoto(p) {
  const hit = S.photoCache.get(p.id);
  if (hit) return Promise.resolve(hit);
  if (S.photoLoads.has(p.id)) return S.photoLoads.get(p.id);
  const key = S.key;
  const pr = (async () => {
    const snaps = await Promise.all(Array.from({ length: p.n }, (_, i) => getChunk(blobRef(p.id, i))));
    if (snaps.some((s) => !s.exists())) throw new Error('Photo data is missing');
    const packed = vc.b64decode(snaps.map((s) => s.data().d).join(''));
    const bytes = await vc.decryptBytes(key, packed, aadBlob(p.id));
    if (S.key !== key) throw new Error('Locked');
    const blob = new Blob([bytes], { type: p.mime || 'image/jpeg' });
    const entry = { url: URL.createObjectURL(blob), blob };
    S.photoCache.set(p.id, entry);
    return entry;
  })().finally(() => S.photoLoads.delete(p.id));
  S.photoLoads.set(p.id, pr);
  return pr;
}

function dropFromCache(photos) {
  for (const p of photos || []) {
    const hit = S.photoCache.get(p.id);
    if (hit) URL.revokeObjectURL(hit.url);
    S.photoCache.delete(p.id);
  }
}

/**
 * Delete photos' encrypted data, except photos another item still uses
 * (an "offline copy" shares its photos with the original).
 */
function deleteBlobs(photos, exceptId) {
  const used = new Set();
  for (const it of [...S.items.values(), ...S.server.values()]) {
    if (it.id !== exceptId) for (const p of it.photos) used.add(p.id);
  }
  const gone = (photos || []).filter((p) => p && !used.has(p.id));
  if (!gone.length) return;
  const batch = writeBatch(db);
  for (const p of gone) for (let i = 0; i < p.n; i++) batch.delete(blobRef(p.id, i));
  commitQueued(batch).catch(() => {});
  dropFromCache(gone);
}

// =====================================================================
// Item helpers
// =====================================================================

const byTitle = (a, b) => (a.title || '').localeCompare(b.title || '', undefined, { sensitivity: 'base' });
const pad2 = (n) => String(n).padStart(2, '0');
const digitsOf = (v) => String(v || '').replace(/\D/g, '');
/** Today's date on this device (not UTC), as YYYY-MM-DD, for file names. */
const localDay = (d = new Date()) => `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`;

function primaryField(it) {
  return it.fields.find((f) => f.secret && f.value) || null;
}

const fieldMatching = (it, re) => it.fields.find((f) => re.test(f.label || '') && f.value);

function cardBrand(num) {
  const d = digitsOf(num);
  if (/^4/.test(d)) return 'Visa';
  if (/^(5[1-5]|2(2[2-9]|[3-6]\d|7[01]|720))/.test(d)) return 'Mastercard';
  if (/^3[47]/.test(d)) return 'Amex';
  if (/^62/.test(d)) return 'UnionPay';
  if (/^35/.test(d)) return 'JCB';
  if (/^3(0[0-5]|[689])/.test(d)) return 'Diners';
  if (/^(6011|65|64[4-9])/.test(d)) return 'Discover';
  return '';
}

function luhnOk(num) {
  const d = digitsOf(num);
  if (d.length < 12 || d.length > 19) return false;
  let sum = 0;
  for (let i = 0; i < d.length; i++) {
    let x = +d[d.length - 1 - i];
    if (i % 2) { x *= 2; if (x > 9) x -= 9; }
    sum += x;
  }
  return sum % 10 === 0;
}

function subtitle(it) {
  const t = TYPES[it.type] || TYPES.note;
  if (it.type === 'bankcard') {
    const n = fieldMatching(it, /card number/i)?.value;
    if (n) return `${cardBrand(n) || 'Card'} •••• ${digitsOf(n).slice(-4)}`;
  }
  if (it.type === 'bankaccount') {
    const bsb = fieldMatching(it, /^bsb$/i)?.value;
    const bank = fieldMatching(it, /^bank$/i)?.value;
    if (bsb) return [bank, `BSB ${bsb}`].filter(Boolean).join(' · ');
  }
  const f = it.fields.find((x) => !x.secret && x.kind !== 'url' && (x.value || '').trim().length > 2 && kindOf(x) === 'text');
  if (f) return f.value;
  if (it.photos.length) return `${t.label} · ${it.photos.length} photo${it.photos.length > 1 ? 's' : ''}`;
  return t.label;
}

function searchText(it) {
  const t = TYPES[it.type] || TYPES.note;
  const brand = it.type === 'bankcard' ? cardBrand(fieldMatching(it, /card number/i)?.value) : '';
  return [it.title, t.label, brand, ...it.fields.filter((f) => !f.secret).map((f) => `${f.label} ${f.value}`), it.notes]
    .join(' ').toLowerCase();
}

// ---------- dates ----------

const DATE_LABEL = /\b(date|expir\w*|expires|valid\s*(to|until|thru)|birth|dob)\b/i;
const EXPIRY_LABEL = /expir|expires|valid\s*(to|until|thru)/i;

function makeDate(y, mo, d) {
  if (y < 1900 || y > 2100 || mo < 1 || mo > 12) return null;
  const date = new Date(y, mo - 1, d);
  if (date.getMonth() !== mo - 1 || date.getDate() !== d) return null; // e.g. 31/02
  return { date, month: false, text: `${pad2(d)}/${pad2(mo)}/${y}` };
}

/**
 * Understands DD/MM/YYYY (also with - . or spaces), YYYY-MM-DD, and month-and-year dates
 * as printed on cards: MM/YYYY and MM/YY. A month-and-year date means the end of that month.
 */
function parseDateValue(s) {
  const v = String(s || '').trim();
  let m = /^(\d{1,2})\s*[/.\- ]\s*(\d{1,2})\s*[/.\- ]\s*(\d{4})$/.exec(v);
  if (m) return makeDate(+m[3], +m[2], +m[1]);
  m = /^(\d{4})-(\d{1,2})-(\d{1,2})$/.exec(v);
  if (m) return makeDate(+m[1], +m[2], +m[3]);
  m = /^(\d{1,2})\s*[/.\-]\s*(\d{4}|\d{2})$/.exec(v);
  if (m) {
    const mo = +m[1];
    const y = m[2].length === 2 ? 2000 + +m[2] : +m[2];
    if (mo < 1 || mo > 12 || y < 1900 || y > 2100) return null;
    return { date: new Date(y, mo, 0), month: true, text: `${pad2(mo)}/${m[2]}` };
  }
  return null;
}

/** The kind of a field. Older items stored dates as plain text, so it's worked out from the label. */
function kindOf(f) {
  if (f.kind && f.kind !== 'text') return f.kind;
  if (f.secret || !DATE_LABEL.test(f.label || '')) return 'text';
  const v = (f.value || '').trim();
  if (!v) return 'date';
  const d = parseDateValue(v);
  if (!d) return 'text'; // something like "N/A": leave it alone
  return d.month ? 'month' : 'date';
}

const KIND_INFO = {
  date: { inputmode: 'numeric', placeholder: 'DD/MM/YYYY' },
  month: { inputmode: 'numeric', placeholder: 'MM/YY' },
  bsb: { inputmode: 'numeric', placeholder: '000-000' },
  cardnum: { inputmode: 'numeric', placeholder: '0000 0000 0000 0000' },
  url: { inputmode: 'url' },
};

/**
 * Check a field's value. Returns { value (tidied), error (blocks saving), warning }.
 * Empty values are always fine.
 */
function checkField(f) {
  const kind = kindOf(f);
  const v = (f.value || '').trim();
  const name = f.label || 'This field';
  if (!v) return { value: '' };
  if (kind === 'date') {
    const d = parseDateValue(v);
    if (!d) return { value: v, error: `${name}: enter a real date as DD/MM/YYYY, e.g. 25/12/2030.` };
    return { value: d.text };
  }
  if (kind === 'month') {
    const d = parseDateValue(v);
    if (!d || !d.month) return { value: v, error: `${name}: enter the month and year as MM/YY or MM/YYYY, e.g. 11/28.` };
    return { value: d.text };
  }
  if (kind === 'bsb') {
    const d = digitsOf(v);
    if (d.length !== 6 || /[^\d\s-]/.test(v)) return { value: v, error: `${name}: a BSB has 6 digits, e.g. 063-000.` };
    return { value: `${d.slice(0, 3)}-${d.slice(3)}` };
  }
  if (kind === 'cardnum') {
    const d = digitsOf(v);
    if (/[^\d\s-]/.test(v) || d.length < 12 || d.length > 19) return { value: v, error: `${name}: a card number has 12 to 19 digits.` };
    const tidy = cardBrand(d) === 'Amex' && d.length === 15
      ? `${d.slice(0, 4)} ${d.slice(4, 10)} ${d.slice(10)}`
      : d.replace(/(\d{4})(?=\d)/g, '$1 ');
    return { value: tidy, warning: luhnOk(d) ? '' : 'This card number doesn\'t add up. Check it for a typo.' };
  }
  return { value: v };
}

/** Typing help: adds the / in dates and the - in a BSB as digits are typed. */
function autoFormat(kind, input, e) {
  if (!e.inputType?.startsWith('insert')) return;
  const v = input.value;
  let out = v;
  if (kind === 'date' && (/^\d{2}$/.test(v) || /^\d{2}\/\d{2}$/.test(v))) out = `${v}/`;
  else if (kind === 'month' && /^\d{2}$/.test(v)) out = `${v}/`;
  else if (kind === 'bsb' && /^\d{3}$/.test(v)) out = `${v}-`;
  else if (kind === 'cardnum' && /^[\d ]+$/.test(v)) out = digitsOf(v).slice(0, 19).replace(/(\d{4})(?=\d)/g, '$1 ');
  if (out !== v) input.value = out;
}

function expiryInfo(it) {
  const f = it.fields.find((x) => EXPIRY_LABEL.test(x.label || '') && x.value);
  const p = f && parseDateValue(f.value);
  if (!p) return null;
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const days = Math.round((p.date - today) / DAY);
  if (days < 0) return { cls: 'bad', text: 'Expired', days };
  if (days <= 183) {
    const when = days < 45 ? `${days} day${days === 1 ? '' : 's'}` : `${Math.round(days / 30.4)} months`;
    return { cls: 'warn', text: days === 0 ? 'Expires today' : `Expires in ${when}`, days };
  }
  return null;
}

function safeUrl(v) {
  try {
    const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(v) ? v : `https://${v}`);
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.href : null;
  } catch {
    return null;
  }
}

// ---------- recently used (kept on this device only) ----------

const usedKey = () => `cybervault.used.${uid()}`;
let usedCache = null;
function usedMap() {
  if (!usedCache || usedCache.key !== usedKey()) {
    let map = {};
    try { map = JSON.parse(localStorage.getItem(usedKey()) || '{}') || {}; } catch { /* ignore */ }
    usedCache = { key: usedKey(), map };
  }
  return usedCache.map;
}
const usedAt = (it) => usedMap()[it.id] || 0;
function markUsed(id) {
  const map = usedMap();
  map[id] = Date.now();
  const keep = Object.entries(map).sort((a, b) => b[1] - a[1]).slice(0, 200);
  usedCache.map = Object.fromEntries(keep);
  try { localStorage.setItem(usedKey(), JSON.stringify(usedCache.map)); } catch { /* ignore */ }
}

// ---------- sorting ----------

const TYPE_ORDER = Object.keys(TYPES);
const SORTS = {
  name: { label: 'Name (A–Z)', short: 'A–Z', fn: byTitle },
  nameDesc: { label: 'Name (Z–A)', short: 'Z–A', fn: (a, b) => byTitle(b, a) },
  used: { label: 'Recently used', short: 'Recently used', fn: (a, b) => (usedAt(b) - usedAt(a)) || byTitle(a, b) },
  updated: { label: 'Recently changed', short: 'Recently changed', fn: (a, b) => ((b.updatedAt || 0) - (a.updatedAt || 0)) || byTitle(a, b) },
  newest: { label: 'Newest first', short: 'Newest', fn: (a, b) => ((b.createdAt || 0) - (a.createdAt || 0)) || byTitle(a, b) },
  oldest: { label: 'Oldest first', short: 'Oldest', fn: (a, b) => ((a.createdAt || 0) - (b.createdAt || 0)) || byTitle(a, b) },
  type: { label: 'Type', short: 'By type', fn: (a, b) => (TYPE_ORDER.indexOf(a.type) - TYPE_ORDER.indexOf(b.type)) || byTitle(a, b) },
};
const sortFn = () => (SORTS[settings.sort] || SORTS.name).fn;

// ---------- password history ----------

/** Old values of hidden fields that changed, newest first, kept inside the encrypted item. */
function nextHistory(prev, next, now = Date.now()) {
  const hist = [...(prev?.history || next.history || [])];
  if (!TYPES[next.type]?.history || !prev) return hist;
  for (const pf of prev.fields) {
    if (!pf.secret || !pf.value) continue;
    const nf = next.fields.find((f) => f.secret && f.label === pf.label);
    if (nf && nf.value === pf.value) continue;
    if (hist.some((x) => x.label === pf.label && x.value === pf.value)) continue;
    hist.unshift({ label: pf.label || 'Password', value: pf.value, until: now });
  }
  return hist.slice(0, HISTORY_MAX);
}

const fmtDate = (ts) => new Date(ts).toLocaleString('en-AU', {
  day: 'numeric', month: 'short', year: 'numeric', hour: 'numeric', minute: '2-digit',
});

const slug = (s) => (s || 'photo').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'photo';

// =====================================================================
// Screens: before unlock
// =====================================================================

function renderLoading(text = 'Loading…') {
  screen('center', h('div', { class: 'auth-card loading-card' }, h('div', { class: 'spinner' }), h('p', { class: 'muted' }, text)));
}

function setupGuide() {
  const zh = (t) => h('span', { class: 'zh' }, `（${t}）`);
  const rules = rulesText();
  const hosted = location.hostname === 'localhost' || /\.(web\.app|firebaseapp\.com)$/.test(location.hostname);
  return h('ol', { class: 'steps' },
    h('li', null, 'Go to ', h('a', { href: 'https://console.firebase.google.com/', target: '_blank', rel: 'noopener noreferrer' }, 'console.firebase.google.com'),
      ' and choose ', h('b', null, 'Create a project'), zh('建立專案'), '. Any name works. Google Analytics can stay off.'),
    h('li', null, 'Open ', h('b', null, 'Build → Authentication'), zh('建構 → Authentication'), ', click ', h('b', null, 'Get started'), zh('開始使用'),
      ' and turn on ', h('b', null, 'Google'), ' and/or ', h('b', null, 'Email/Password'), zh('電子郵件/密碼'), '.'),
    h('li', null, 'Open ', h('b', null, 'Build → Firestore Database'), ', click ', h('b', null, 'Create database'), zh('建立資料庫'),
      ', pick a location near you (e.g. australia-southeast1) and start in ', h('b', null, 'production mode'), zh('正式版模式'), '.'),
    h('li', null, 'In Firestore open the ', h('b', null, 'Rules'), zh('規則'), ' tab, replace everything with these rules and click ',
      h('b', null, 'Publish'), zh('發布'), '.',
      h('pre', { class: 'code' }, rules),
      btn('Copy rules', { kind: 'secondary', small: true, icon: 'copy', onClick: () => copyText(rules, 'Rules copied', { sensitive: false }) })),
    h('li', null, 'Click the gear next to ', h('b', null, 'Project overview'), zh('專案總覽'), ' → ', h('b', null, 'Project settings'), zh('專案設定'),
      '. Under ', h('b', null, 'Your apps'), zh('你的應用程式'), ' click the web icon ', h('code', null, '</>'),
      ', give it any nickname and register it. No hosting needed.'),
    h('li', null, 'Copy the ', h('code', null, 'firebaseConfig = { … }'), ' block it shows, paste it above and tap ', h('b', null, 'Connect'), '.'),
    android ? h('li', null, 'Using text-message codes in this Android app? In ', h('b', null, 'Authentication → Settings → Authorized domains'), ' add ',
      h('code', null, location.hostname), '.')
      : hosted ? null : h('li', null, 'Signing in with Google? In ', h('b', null, 'Authentication → Settings → Authorized domains'), ' add ',
        h('code', null, location.hostname), '.'));
}

function renderConnect(prefill = '', note = '') {
  const text = h('textarea', {
    class: 'input textarea mono connect-input', rows: '6', value: prefill, ...noAssist,
    placeholder: 'CV1-…\n\nor\n\nconst firebaseConfig = {\n  apiKey: "…",\n  …\n};',
    'aria-label': 'Setup code or Firebase config',
  });
  const err = h('p', { class: 'form-error', role: 'alert' });
  text.addEventListener('input', () => { err.textContent = ''; });
  const guide = h('div', { class: 'guide', hidden: true }, setupGuide());
  const toggle = btn('How do I get a config?', {
    kind: 'ghost', small: true, icon: 'help',
    onClick: () => {
      guide.hidden = !guide.hidden;
      toggle.querySelector('.btn-label').textContent = guide.hidden ? 'How do I get a config?' : 'Hide setup steps';
      toggle.setAttribute('aria-expanded', String(!guide.hidden));
    },
  });
  toggle.setAttribute('aria-expanded', 'false');
  const form = h('form', {
    class: 'stack',
    onsubmit: (e) => {
      e.preventDefault();
      let cfg;
      try {
        cfg = parseConfig(text.value);
      } catch (x) {
        err.textContent = x.message;
        return;
      }
      connectWith(cfg);
    },
  },
  field('Setup code or Firebase config', text,
    'Set up on another device already? Use its setup link or code (Settings → Add another device). First time? Paste the firebaseConfig block from the Firebase console.'),
  err,
  btn('Connect', { type: 'submit', block: true, icon: 'plug' }));

  screen('center', h('div', { class: 'auth-card' },
    brandMark(),
    h('h1', null, 'Connect Firebase'),
    h('p', { class: 'muted' }, 'CyberVault keeps your encrypted vault in your own free Firebase project. Connect it once on each device.'),
    h('div', { class: 'term-lines', 'aria-hidden': 'true' },
      note ? h('span', { class: 'ok' }, note) : h('span', null, 'status: no firebase project linked')),
    form,
    toggle,
    guide));
  if (!prefill) focusSoon(text);
}

function connectWith(cfg) {
  try { localStorage.setItem(CONFIG_KEY, JSON.stringify(cfg)); } catch { /* private browsing: connected for this visit only */ }
  activeConfig = cfg;
  startFirebase(cfg);
  listenAuth();
  toast(`Connected to ${cfg.projectId}`);
}

async function forgetProject() {
  const ok = await confirmSheet({
    title: 'Use a different Firebase project?',
    message: 'This device forgets the current project. Your vault stays safe in it, and you can reconnect any time with its config or setup code.',
    confirmLabel: 'Forget project',
    danger: true,
  });
  if (!ok) return;
  lock(false);
  try { if (auth?.currentUser) await signOut(auth); } catch { /* ignore */ }
  try { localStorage.removeItem(CONFIG_KEY); } catch { /* ignore */ }
  try {
    // Remove this device's offline copy of the old project too.
    for (const k of Object.keys(localStorage)) if (k.startsWith(`cybervault.outbox.${activeConfig?.projectId}.`)) localStorage.removeItem(k);
    await terminate(db);
    await clearIndexedDbPersistence(db);
  } catch { /* ignore */ }
  history.replaceState(null, '', location.pathname + location.search);
  location.reload();
}

function renderSignIn(message = '') {
  let mode = 'signin';
  const err = h('p', { class: 'form-error', role: 'alert' }, message);
  const email = h('input', {
    class: 'input', type: 'email', autocomplete: 'username', inputmode: 'email',
    placeholder: 'you@example.com', required: true, ...noAssist,
  });
  const pw = pwInput({ autocomplete: 'current-password', placeholder: 'Account password', required: true });
  const submit = btn('Sign in', { type: 'submit', block: true });
  const toggleMode = h('button', { type: 'button', class: 'link', onclick: () => { mode = mode === 'signin' ? 'signup' : 'signin'; sync(); } });
  const help = h('button', { type: 'button', class: 'link', onclick: () => openSignInHelp(email.value.trim()) }, 'Can\'t sign in?');

  function sync() {
    submit.querySelector('.btn-label').textContent = mode === 'signin' ? 'Sign in' : 'Create account';
    toggleMode.textContent = mode === 'signin' ? 'New here? Create an account' : 'Already have an account? Sign in';
    pw.input.setAttribute('autocomplete', mode === 'signin' ? 'current-password' : 'new-password');
    err.textContent = '';
  }

  const google = btn('Continue with Google', {
    kind: 'secondary', block: true, cls: 'btn-google',
    onClick: async () => {
      err.textContent = '';
      try {
        await signInWithPopup(auth, new GoogleAuthProvider());
      } catch (e) {
        err.textContent = authMessage(e);
      }
    },
  });
  google.prepend(h('span', { class: 'g-mark', 'aria-hidden': 'true' }, 'G'));
  const googleNote = android ? h('p', { class: 'muted small' },
    'Google sign-in isn\'t available in the Android app, because Google blocks it inside apps like this. Use email and password, or a text-message code under Can\'t sign in? (Signed up with Google? Use CyberVault in your browser instead.)') : null;

  const form = h('form', {
    class: 'stack',
    onsubmit: async (e) => {
      e.preventDefault();
      err.textContent = '';
      setBusy(submit, true);
      try {
        if (mode === 'signin') await signInWithEmailAndPassword(auth, email.value.trim(), pw.input.value);
        else await createUserWithEmailAndPassword(auth, email.value.trim(), pw.input.value);
      } catch (e2) {
        err.textContent = authMessage(e2);
        setBusy(submit, false);
      }
    },
  }, field('Email', email), field('Account password', pw.wrap), err, submit);

  screen('center signin', h('div', { class: 'auth-card' },
    brandMark(),
    h('h1', { 'aria-label': 'CyberVault' }, wordmark()),
    h('p', { class: 'muted' }, 'Your passwords, ID numbers and documents, encrypted on this device.'),
    h('div', { class: 'term-lines' },
      h('span', null, `firebase project: ${activeConfig.projectId}`),
      h('span', { class: 'ok' }, 'aes-256-gcm on-device · server sees ciphertext only')),
    android ? googleNote : google,
    android ? null : h('div', { class: 'divider' }, h('span', null, 'or use email')),
    form,
    h('div', { class: 'auth-links' }, toggleMode, help),
    configSource === 'device' ? h('div', { class: 'auth-links' },
      h('button', { type: 'button', class: 'link', onclick: forgetProject }, 'Use a different Firebase project')) : null));
  sync();
  if (message) err.textContent = message;
}

function renderFatal(e) {
  const denied = e?.code === 'permission-denied';
  const rules = rulesText();
  screen('center', h('div', { class: 'auth-card' },
    brandMark('alert'),
    h('h1', null, denied ? 'Database rules needed' : 'Can\'t open the vault'),
    h('p', { class: 'form-error' }, dbMessage(e)),
    denied ? h('div', { class: 'stack-sm' },
      h('p', { class: 'muted small' }, 'Firebase console → Firestore Database → Rules: replace everything with these rules, click Publish, then tap Try again. If you locked the rules to one account, sign in with that account instead.'),
      h('pre', { class: 'code' }, rules),
      btn('Copy rules', { kind: 'secondary', small: true, icon: 'copy', onClick: () => copyText(rules, 'Rules copied', { sensitive: false }) })) : null,
    h('div', { class: 'stack' },
      btn('Try again', { block: true, icon: 'refresh', onClick: () => location.reload() }),
      btn('Sign out', { kind: 'secondary', block: true, onClick: doSignOut })),
    configSource === 'device' ? h('div', { class: 'auth-links' },
      h('button', { type: 'button', class: 'link', onclick: forgetProject }, 'Use a different Firebase project')) : null));
}

function renderCreateVault() {
  const pw = pwInput({ autocomplete: 'new-password', placeholder: 'At least 10 characters' });
  const pw2 = pwInput({ autocomplete: 'new-password', placeholder: 'Type it again' });
  const meter = strengthMeter();
  pw.input.addEventListener('input', () => meter.update(pw.input.value));
  const ack = h('input', { type: 'checkbox' });
  const err = h('p', { class: 'form-error', role: 'alert' });
  const submit = btn('Create vault', { type: 'submit', block: true, icon: 'lock' });
  for (const el of [pw.input, pw2.input, ack]) el.addEventListener('input', () => { err.textContent = ''; });

  const form = h('form', {
    class: 'stack',
    onsubmit: async (e) => {
      e.preventDefault();
      err.textContent = '';
      const p = pw.input.value;
      if (p.length < 10) { err.textContent = 'Use at least 10 characters.'; return; }
      if (vc.passwordStrength(p).score < 2) {
        err.textContent = 'That password is too easy to guess. A passphrase of 4 or more random words works well.';
        return;
      }
      if (p !== pw2.input.value) { err.textContent = 'The two passwords don\'t match.'; return; }
      if (!ack.checked) { err.textContent = 'Tick the box to confirm you understand.'; return; }
      if (!onlineOr(err)) return;
      setBusy(submit, true, 'Creating…');
      try {
        const existing = await getDoc(vaultRef());
        if (existing.exists()) {
          S.meta = existing.data();
          toast('This account already has a vault');
          renderUnlock();
          return;
        }
        const recoveryKey = vc.generateRecoveryKey();
        const { meta, key } = await vc.createVault(p, { recoveryKey });
        await setDoc(vaultRef(), meta);
        S.meta = meta;
        S.key = key;
        S.lastActivity = Date.now();
        await startSync();
        renderRecoveryKeyOnboarding(recoveryKey, p);
      } catch (e2) {
        err.textContent = dbMessage(e2);
        setBusy(submit, false, 'Create vault');
      }
    },
  },
  field('Master password', pw.wrap),
  meter.el,
  field('Confirm master password', pw2.wrap),
  h('label', { class: 'check-row' }, ack,
    h('span', null, 'I understand that if I forget my master password, nobody can recover my data, including me.')),
  err,
  submit);

  screen('center', h('div', { class: 'auth-card' },
    brandMark('lock'),
    h('h1', null, 'Create your master password'),
    h('p', { class: 'muted' },
      'It encrypts everything on this device before upload, and it is never sent to Firebase. You\'ll enter it every time you open the vault.'),
    form,
    h('div', { class: 'auth-links' }, h('span', { class: 'muted small' }, S.user.email || ''),
      h('button', { type: 'button', class: 'link', onclick: doSignOut }, 'Sign out'))));
  focusSoon(pw.input);
}

function renderUnlock() {
  const pw = pwInput({ autocomplete: 'off', placeholder: 'Master password', name: 'vault-master' });
  const err = h('p', { class: 'form-error', role: 'alert' });
  const submit = btn('Unlock', { type: 'submit', block: true, icon: 'unlock' });
  const card = h('div', { class: 'auth-card' });

  const form = h('form', {
    class: 'stack',
    onsubmit: async (e) => {
      e.preventDefault();
      const p = pw.input.value;
      if (!p) return;
      err.textContent = '';
      setBusy(submit, true, 'Decrypting…');
      try {
        // Pick up a master-password change made on another device.
        try {
          const snap = await getDocFast(vaultRef());
          if (snap.exists()) S.meta = snap.data();
        } catch { /* offline: use the copy we have */ }
        S.key = await vc.unlockVault(p, S.meta);
        S.lastActivity = Date.now();
        await startSync();
        S.nav = [];
        history.replaceState(null, '', '#/');
        render();
      } catch (e2) {
        S.key = null;
        if (e2 instanceof vc.WrongPasswordError) {
          err.textContent = 'Wrong master password.';
          card.classList.remove('shake');
          void card.offsetWidth;
          card.classList.add('shake');
          pw.input.select();
        } else {
          err.textContent = dbMessage(e2);
        }
        setBusy(submit, false, 'Unlock');
      }
    },
  }, field('Master password', pw.wrap), err, submit);

  card.append(
    brandMark('lock'),
    h('h1', null, 'Vault locked'),
    h('p', { class: 'muted' }, 'Signed in as ', h('strong', null, S.user.email || 'your account')),
    h('div', { class: 'term-lines', 'aria-hidden': 'true' },
      h('span', null, 'session locked · key wiped'),
      navigator.onLine
        ? h('span', { class: 'ok' }, 'aes-256-gcm · zero-knowledge')
        : h('span', { class: 'ok' }, 'offline · opening the copy on this device')),
    form,
    h('div', { class: 'auth-links' },
      h('button', { type: 'button', class: 'link', onclick: renderRecover }, 'Forgot master password?'),
      h('button', { type: 'button', class: 'link', onclick: doSignOut }, 'Sign out')));
  screen('center', card);
  focusSoon(pw.input);
}

async function doSignOut() {
  const waiting = S.user ? readOutbox().length : 0;
  if (waiting && !(await confirmSheet({
    title: 'Sign out?',
    message: `${waiting} change${waiting > 1 ? 's' : ''} made offline ${waiting > 1 ? 'haven\'t' : 'hasn\'t'} synced yet. ${waiting > 1 ? 'They stay' : 'It stays'} on this device and sync${waiting > 1 ? '' : 's'} the next time you unlock here while online.`,
    confirmLabel: 'Sign out',
  }))) return;
  lock(false);
  S.meta = null;
  try { await signOut(auth); } catch (e) { toast(authMessage(e), 'error'); }
}

// =====================================================================
// Screens: list
// =====================================================================

function syncButton() {
  const b = h('button', { type: 'button', class: 'icon-btn ghost sync-btn', onclick: openSyncSheet });
  const paint = () => {
    const st = syncState();
    const [ic, label] = st.offline ? ['cloudOff', 'Offline']
      : st.pending || st.busy ? ['cloudUp', st.pending ? `${st.pending} change${st.pending > 1 ? 's' : ''} waiting to sync` : 'Syncing…']
        : ['cloud', 'Synced'];
    b.replaceChildren(icon(ic));
    b.classList.toggle('is-offline', st.offline);
    b.classList.toggle('is-pending', !st.offline && !!(st.pending || st.busy));
    b.setAttribute('aria-label', label);
    b.title = label;
  };
  paint();
  return { el: b, paint };
}

function syncBanner() {
  const st = syncState();
  if (!st.offline && !st.pending) return null;
  const waiting = st.pending ? ` ${st.pending} change${st.pending > 1 ? 's' : ''} waiting to sync.` : '';
  return h('button', { type: 'button', class: 'banner info', onclick: openSyncSheet },
    icon(st.offline ? 'cloudOff' : 'cloudUp'),
    h('span', null, st.offline
      ? h('strong', null, 'Offline. ')
      : h('strong', null, 'Syncing. '),
    st.offline ? `You can still view and edit. Changes sync when you're back online.${waiting}` : waiting.trim()),
    icon('forward'));
}

function openSyncSheet() {
  const st = syncState();
  const status = st.offline ? 'Offline' : st.pending || st.busy ? 'Waiting to sync' : 'Up to date';
  openSheet((close) => [
    h('div', { class: 'sheet-handle' }),
    h('h3', { class: 'sheet-title' }, `Sync: ${status.toLowerCase()}`),
    h('p', { class: 'muted' }, 'Your vault updates live across your devices. An encrypted copy is kept on this device, so it opens and works without internet. Changes made offline sync by themselves when you\'re back online.'),
    st.pending ? h('p', { class: 'muted small' }, `${st.pending} change${st.pending > 1 ? 's' : ''} made on this device ${st.pending > 1 ? 'are' : 'is'} waiting to sync.`) : null,
    h('p', { class: 'muted small' }, 'If an item is changed on two devices before they sync, both versions are kept.'),
    h('div', { class: 'sheet-actions' },
      btn('Close', { kind: 'secondary', onClick: close }),
      btn('Sync now', {
        icon: 'refresh',
        onClick: async () => {
          if (!onlineOr()) return;
          close();
          const done = busy('Syncing…');
          try { await flushOutbox(); } finally { done(); }
          if (!readOutbox().length) toast('Up to date');
        },
      })),
  ]);
}

function renderList() {
  const listEl = h('div', { class: 'list-sections' });
  const chipsEl = h('div', { class: 'chips', role: 'tablist' });
  const bannerEl = h('div', { class: 'banners' });
  const sync = syncButton();

  const search = h('input', {
    class: 'input search-input', type: 'search', placeholder: 'Search', value: S.query,
    'aria-label': 'Search vault', ...noAssist,
    oninput: (e) => { S.query = e.target.value; paint(); },
  });

  const listBox = (rows) => h('div', { class: 'list' }, rows.map(itemRow));
  const sectionEl = (title, rows, extra) => h('section', { class: 'list-section' },
    h('div', { class: 'section-row' }, h('h2', { class: 'section-title' }, title), extra),
    listBox(rows));

  function paint() {
    sync.paint();
    const all = liveItems();
    const counts = { all: all.length };
    for (const it of all) counts[it.type] = (counts[it.type] || 0) + 1;
    if (S.filter !== 'all' && !counts[S.filter]) S.filter = 'all';
    chipsEl.hidden = !all.length;
    chipsEl.replaceChildren(...[['all', 'All'], ...Object.entries(TYPES).map(([k, t]) => [k, t.plural])]
      .filter(([k]) => k === 'all' || counts[k] || S.filter === k)
      .map(([k, label]) => h('button', {
        type: 'button', role: 'tab', class: `chip${S.filter === k ? ' active' : ''}`,
        'aria-selected': String(S.filter === k),
        onclick: () => { S.filter = k; paint(); },
      }, label, h('span', { class: 'chip-count' }, counts[k] || 0))));

    const expiring = all.map((it) => ({ it, e: expiryInfo(it) })).filter((x) => x.e).sort((a, b) => a.e.days - b.e.days);
    bannerEl.replaceChildren(...[syncBanner(), ...expiring.slice(0, 2).map(({ it, e }) => h('button', {
      type: 'button', class: `banner ${e.cls}`, onclick: () => go(`#/item/${encodeURIComponent(it.id)}`),
    }, icon('alert'), h('span', null, h('strong', null, it.title), ` · ${e.text.toLowerCase()}`), icon('forward')))].filter(Boolean));

    const q = S.query.trim().toLowerCase();
    const shown = all.filter((it) => (S.filter === 'all' || it.type === S.filter) && (!q || searchText(it).includes(q)));
    const sort = sortFn();
    const sortBtn = h('button', { type: 'button', class: 'sort-btn', onclick: openSortSheet, 'aria-label': 'Change sort order' },
      icon('sort'), (SORTS[settings.sort] || SORTS.name).short);

    if (!all.length) {
      listEl.replaceChildren(h('div', { class: 'empty' },
        h('div', { class: 'empty-art' }, typeTile('login'), typeTile('id'), typeTile('passport')),
        h('h2', null, 'Your vault is empty'),
        h('p', { class: 'muted' }, 'Add a login, your TFN or ABN, a bank card or a photo of your passport. Everything is encrypted before it leaves this device.'),
        btn('Add your first item', { icon: 'plus', onClick: openTypePicker }),
        btn('Restore a backup', { kind: 'secondary', icon: 'upload', onClick: pickBackupFile }),
        h('button', { type: 'button', class: 'link', onclick: pickImportFile }, 'Import passwords from Google')));
      return;
    }
    if (!shown.length) {
      listEl.replaceChildren(h('p', { class: 'muted empty-search' }, 'No matches.'));
      return;
    }
    if (q) {
      // Searching: one list, favourites first.
      const rows = shown.sort((a, b) => (!!b.fav - !!a.fav) || sort(a, b));
      listEl.replaceChildren(sectionEl(`${rows.length} result${rows.length > 1 ? 's' : ''}`, rows, sortBtn));
      return;
    }
    const sections = [];
    const pinned = new Set();
    if (settings.pinFav) {
      const favs = shown.filter((it) => it.fav).sort(sort);
      favs.forEach((it) => pinned.add(it.id));
      if (favs.length) sections.push(sectionEl('Favourites', favs));
    }
    if (settings.pinRecent && settings.sort !== 'used') {
      const recent = shown.filter((it) => !pinned.has(it.id) && usedAt(it) > Date.now() - 30 * DAY)
        .sort((a, b) => usedAt(b) - usedAt(a)).slice(0, 3);
      recent.forEach((it) => pinned.add(it.id));
      if (recent.length) sections.push(sectionEl('Recently used', recent));
    }
    const rest = shown.filter((it) => !pinned.has(it.id)).sort(sort);
    if (rest.length || !sections.length) {
      sections.push(sectionEl(sections.length ? 'Everything else' : 'All items', rest, sortBtn));
    } else {
      sections[sections.length - 1].querySelector('.section-row').append(sortBtn);
    }
    listEl.replaceChildren(...sections);
  }

  screen('list-screen',
    topbar({
      left: h('div', { class: 'brand-inline' }, h('img', { src: 'icons/logo.svg', alt: '', width: '30', height: '30' }), wordmark()),
      right: [
        sync.el,
        iconBtn('settings', 'Settings', () => go('#/settings')),
        iconBtn('lock', 'Lock now', () => lock()),
      ],
    }),
    h('div', { class: 'content' },
      h('div', { class: 'search' }, icon('search'), search),
      chipsEl,
      bannerEl,
      listEl,
      S.items.size ? h('p', { class: 'hint' }, 'Tip: long-press an item to copy its password or number.') : null),
    h('button', { type: 'button', class: 'fab', 'aria-label': 'Add item', onclick: openTypePicker }, icon('plus'), h('span', null, 'Add')));
  paint();
  S.repaint = paint;
}

function openSortSheet() {
  openSheet((close) => {
    const opts = h('div', { class: 'type-list', role: 'radiogroup' });
    const paintOpts = () => opts.replaceChildren(...Object.entries(SORTS).map(([k, o]) => h('button', {
      type: 'button', role: 'radio', class: `type-option sort-option${settings.sort === k ? ' active' : ''}`,
      'aria-checked': String(settings.sort === k),
      onclick: () => { settings.sort = k; saveSettings(); paintOpts(); refreshView(); },
    }, h('span', { class: 'type-text' }, h('strong', null, o.label)), settings.sort === k ? icon('check') : null)));
    paintOpts();
    const pin = (key, label, hint) => h('label', { class: 'check-row' },
      h('input', { type: 'checkbox', checked: settings[key], onchange: (e) => { settings[key] = e.target.checked; saveSettings(); refreshView(); } }),
      h('span', null, label, hint && h('span', { class: 'muted small block' }, hint)));
    return [
      h('div', { class: 'sheet-handle' }),
      h('h3', { class: 'sheet-title' }, 'Sort and pin'),
      opts,
      h('div', { class: 'stack-sm' },
        pin('pinFav', 'Pin favourites to the top', 'Star an item to make it a favourite.'),
        pin('pinRecent', 'Pin the 3 most recently used', 'Remembered on this device only.')),
      btn('Done', { block: true, onClick: close }),
    ];
  });
}

function itemRow(it) {
  const t = TYPES[it.type] || TYPES.note;
  const primary = primaryField(it);
  const exp = expiryInfo(it);
  const copyPrimary = primary ? () => { markUsed(it.id); copyText(primary.value, `${primary.label || 'Value'} copied`); } : null;
  const row = h('div', { class: 'row', role: 'button', tabindex: '0', 'aria-label': `${it.title}, ${t.label}${it.fav ? ', favourite' : ''}` },
    typeTile(it.type),
    h('div', { class: 'row-main' },
      h('div', { class: 'row-title' }, it.fav ? h('span', { class: 'fav-star', 'aria-hidden': 'true' }, icon('starFill')) : null, h('span', null, it.title)),
      h('div', { class: 'row-sub' }, exp && h('span', { class: `badge ${exp.cls}` }, exp.text), h('span', null, subtitle(it)))),
    primary && iconBtn('copy', `Copy ${primary.label}`, (e) => { e.stopPropagation(); copyPrimary(); }));
  const open = () => go(`#/item/${encodeURIComponent(it.id)}`);
  onPress(row, { onTap: open, onLong: copyPrimary });
  row.addEventListener('keydown', (e) => { if (e.key === 'Enter') open(); });
  return row;
}

function openTypePicker() {
  openSheet((close) => [
    h('div', { class: 'sheet-handle' }),
    h('h3', { class: 'sheet-title' }, 'Add to vault'),
    h('div', { class: 'type-list' }, ...Object.entries(TYPES).map(([k, t]) => h('button', {
      type: 'button', class: 'type-option',
      onclick: () => { close(); go(`#/new/${k}`); },
    }, typeTile(k), h('span', { class: 'type-text' }, h('strong', null, t.label), h('span', null, t.blurb)), icon('forward')))),
  ]);
}

// =====================================================================
// Screens: detail
// =====================================================================

function renderDetail(id) {
  const it = S.items.get(id);
  if (!it) { location.replace('#/'); return; }
  const t = TYPES[it.type] || TYPES.note;
  const exp = expiryInfo(it);
  const fields = it.fields.map((f, i) => ({ f, i })).filter(({ f }) => f.value);
  const deleted = !!it.deletedAt;
  if (!deleted) markUsed(id);

  const favBtn = iconBtn(it.fav ? 'starFill' : 'star', it.fav ? 'Remove from favourites' : 'Add to favourites', async () => {
    try {
      await updateItem(id, (x) => ({ ...x, fav: !x.fav }));
      if (route().view === 'item' && route().arg === id) renderDetail(id);
      toast(S.items.get(id)?.fav ? 'Added to favourites' : 'Removed from favourites');
    } catch (e) {
      toast(e?.code ? dbMessage(e) : e.message, 'error');
    }
  }, `ghost fav-btn${it.fav ? ' on' : ''}`);

  const wifiQr = it.type === 'wifi' && fieldMatching(it, /network|ssid/i)
    ? h('div', { class: 'card pad' },
      h('p', { class: 'muted small' }, 'Guests can join by pointing their phone camera at a QR code. No need to read out the password.'),
      btn('Show QR code', { kind: 'secondary', icon: 'qr', onClick: () => openWifiQr(it) }))
    : null;

  screen('detail-screen',
    topbar({
      left: iconBtn('back', 'Back', () => back(deleted ? '#/bin' : '#/')),
      title: '',
      right: deleted ? null : [favBtn,
        btn('Edit', { kind: 'ghost', small: true, icon: 'edit', onClick: () => go(`#/edit/${encodeURIComponent(id)}`) })],
    }),
    h('div', { class: 'content' },
      deleted ? h('div', { class: 'banner bad static' }, icon('trash'),
        h('span', null, h('strong', null, 'In Recently deleted. '), `Removed for good in ${daysLeft(it)}.`)) : null,
      deleted ? h('div', { class: 'btn-row' },
        btn('Restore', { icon: 'restore', onClick: () => restoreItem(it) }),
        btn('Delete forever', { kind: 'danger-ghost', icon: 'trash', onClick: () => deleteForever(it) })) : null,
      h('div', { class: 'detail-head' },
        typeTile(it.type, true),
        h('div', null,
          h('h1', { class: 'detail-title' }, it.title),
          h('div', { class: 'detail-meta' }, t.label, it.fav ? h('span', { class: 'badge fav' }, 'Favourite') : null,
            exp && h('span', { class: `badge ${exp.cls}` }, exp.text)))),
      fields.length ? h('div', { class: 'card kv-list' }, fields.map(({ f, i }) => fieldRow(it, f, i))) : null,
      wifiQr,
      it.photos.length ? h('section', { class: 'section' },
        h('h2', { class: 'section-title' }, 'Photos'),
        h('div', { class: 'photo-grid' }, it.photos.map((p, idx) => photoThumb(it, p, idx)))) : null,
      it.notes ? notesCard(it) : null,
      it.history?.length ? historyCard(it) : null,
      !fields.length && !it.photos.length && !it.notes ? h('p', { class: 'muted' }, 'This item is empty. Tap Edit to add details.') : null,
      h('p', { class: 'hint' }, 'Tap a hidden value to show it. Long-press any value to copy it.'),
      h('div', { class: 'detail-foot' },
        h('span', { class: 'muted small' }, `Updated ${fmtDate(it.updatedAt || it.createdAt || Date.now())}`),
        deleted ? null : btn('Delete', { kind: 'danger-ghost', small: true, icon: 'trash', onClick: () => deleteItem(it) }))));
}

function daysLeft(it) {
  const d = Math.max(0, Math.ceil((it.deletedAt + BIN_DAYS * DAY - Date.now()) / DAY));
  return d <= 1 ? 'less than a day' : `${d} days`;
}

function historyCard(it) {
  const rows = it.history.map((x, i) => {
    const key = `${it.id}:h${i}`;
    const valueEl = h('div', { class: 'kv-value mono', tabindex: '0' });
    const eye = iconBtn('eye', 'Show', () => toggle());
    function paint() {
      const shown = S.revealed.has(key);
      valueEl.textContent = shown ? x.value : '**********';
      valueEl.classList.toggle('masked', !shown);
      eye.replaceChildren(icon(shown ? 'eyeOff' : 'eye'));
      eye.setAttribute('aria-label', shown ? 'Hide' : 'Show');
    }
    function toggle() {
      if (S.revealed.has(key)) S.revealed.delete(key);
      else S.revealed.add(key);
      paint();
    }
    paint();
    const copy = () => copyText(x.value, `Old ${(x.label || 'password').toLowerCase()} copied`);
    onPress(valueEl, { onTap: toggle, onLong: copy });
    return h('div', { class: 'kv' },
      h('div', { class: 'kv-text' }, h('div', { class: 'kv-label' }, `${x.label || 'Password'} · until ${fmtDay(x.until)}`), valueEl),
      h('div', { class: 'kv-actions' }, eye, iconBtn('copy', 'Copy', copy)));
  });
  return h('section', { class: 'section' },
    h('div', { class: 'section-row' },
      h('h2', { class: 'section-title' }, `Password history (${it.history.length})`),
      it.deletedAt ? null : h('button', { type: 'button', class: 'link small-link', onclick: () => clearHistory(it) }, 'Clear')),
    h('div', { class: 'card kv-list history' }, rows));
}

async function clearHistory(it) {
  const ok = await confirmSheet({
    title: 'Clear password history?',
    message: `This removes the ${it.history.length} old password${it.history.length > 1 ? 's' : ''} saved with “${it.title}”.`,
    confirmLabel: 'Clear', danger: true,
  });
  if (!ok) return;
  try {
    await updateItem(it.id, (x) => ({ ...x, history: [] }));
    renderDetail(it.id);
    toast('History cleared');
  } catch (e) {
    toast(e?.code ? dbMessage(e) : e.message, 'error');
  }
}

function openWifiQr(it) {
  const ssid = fieldMatching(it, /network|ssid/i)?.value || '';
  const password = it.fields.find((f) => f.secret && f.value)?.value || '';
  const security = fieldMatching(it, /security|encryption|type/i)?.value || 'WPA';
  const text = wifiQrText({ ssid, password, security });
  const svg = qrSvg(text);
  const box = h('div', { class: 'qr-box', role: 'img', 'aria-label': `QR code to join ${ssid}` });
  box.innerHTML = svg;
  openSheet((close) => [
    h('div', { class: 'sheet-handle' }),
    h('h3', { class: 'sheet-title' }, 'Scan to join'),
    box,
    h('p', { class: 'qr-ssid' }, ssid),
    h('p', { class: 'muted small center' }, 'Open the camera on an iPhone or Android phone and point it at the code, then tap the Wi-Fi notice. Anyone who sees this code can join, so show it only to guests you trust.'),
    h('div', { class: 'sheet-actions' },
      btn('Close', { kind: 'secondary', onClick: close }),
      btn('Save image', {
        icon: 'download',
        onClick: async () => {
          const blob = await svgToPng(svg, 900);
          saveImage(blob, `${slug(ssid || it.title)}-wifi-qr.png`);
        },
      })),
  ], { cls: 'qr-sheet' });
}

async function svgToPng(svg, px) {
  const img = new Image();
  const url = URL.createObjectURL(new Blob([svg], { type: 'image/svg+xml' }));
  try {
    img.src = url;
    await img.decode();
    const c = document.createElement('canvas');
    c.width = px;
    c.height = px;
    const ctx = c.getContext('2d');
    ctx.imageSmoothingEnabled = false;
    ctx.drawImage(img, 0, 0, px, px);
    return await new Promise((res, rej) => c.toBlob((b) => (b ? res(b) : rej(new Error('PNG failed'))), 'image/png'));
  } finally {
    URL.revokeObjectURL(url);
  }
}

function fieldRow(it, f, i) {
  const key = `${it.id}:${i}`;
  const valueEl = h('div', { class: `kv-value${f.secret ? ' mono' : ''}`, tabindex: '0' });
  const eye = f.secret ? iconBtn('eye', 'Show', () => toggle()) : null;
  function paint() {
    const shown = !f.secret || S.revealed.has(key);
    valueEl.textContent = shown ? f.value : '**********';
    valueEl.classList.toggle('masked', !shown);
    if (eye) {
      eye.replaceChildren(icon(shown ? 'eyeOff' : 'eye'));
      eye.setAttribute('aria-label', shown ? 'Hide' : 'Show');
      eye.title = shown ? 'Hide' : 'Show';
    }
  }
  function toggle() {
    if (S.revealed.has(key)) S.revealed.delete(key);
    else S.revealed.add(key);
    paint();
  }
  paint();
  const copy = () => { markUsed(it.id); copyText(f.value, `${f.label || 'Value'} copied`); };
  onPress(valueEl, { onTap: f.secret ? toggle : null, onLong: copy });
  const url = f.kind === 'url' ? safeUrl(f.value) : null;
  return h('div', { class: 'kv' },
    h('div', { class: 'kv-text' }, h('div', { class: 'kv-label' }, f.label || 'Field'), valueEl),
    h('div', { class: 'kv-actions' },
      eye,
      url && h('a', { class: 'icon-btn ghost', href: url, target: '_blank', rel: 'noopener noreferrer', 'aria-label': 'Open website', title: 'Open website' }, icon('external')),
      iconBtn('copy', `Copy ${f.label || 'value'}`, copy)));
}

function notesCard(it) {
  const body = h('div', { class: 'notes-body' }, it.notes);
  const copy = () => copyText(it.notes, 'Notes copied');
  onPress(body, { onLong: copy });
  return h('section', { class: 'section' },
    h('div', { class: 'section-row' }, h('h2', { class: 'section-title' }, 'Notes'), iconBtn('copy', 'Copy notes', copy)),
    h('div', { class: 'card notes' }, body));
}

function photoThumb(it, p, idx) {
  const img = h('img', { alt: `${it.title}, photo ${idx + 1}`, decoding: 'async' });
  const cell = h('button', { type: 'button', class: 'photo loading', 'aria-label': `Open photo ${idx + 1}` }, img);
  loadPhoto(p).then((entry) => {
    img.src = entry.url;
    cell.classList.remove('loading');
  }).catch(() => {
    cell.classList.remove('loading');
    cell.classList.add('failed');
    cell.replaceChildren(icon('image'), h('span', null, 'Couldn\'t load'));
  });
  cell.addEventListener('click', () => { if (S.photoCache.has(p.id)) openViewer(it, idx); });
  return cell;
}

function openViewer(it, start) {
  let i = start;
  const n = it.photos.length;
  const img = h('img', { class: 'viewer-img', alt: '' });
  const counter = h('span', { class: 'viewer-count' });
  const current = () => S.photoCache.get(it.photos[i].id);
  function show() {
    const p = it.photos[i];
    const entry = S.photoCache.get(p.id);
    img.src = entry ? entry.url : '';
    img.alt = `${it.title}, photo ${i + 1}`;
    counter.textContent = n > 1 ? `${i + 1} / ${n}` : '';
    if (!entry) loadPhoto(p).then((e) => { if (it.photos[i] === p) img.src = e.url; }).catch(() => {});
  }
  const step = (d) => { i = (i + d + n) % n; show(); };
  const stage = h('div', { class: 'viewer-stage' }, img);
  let sx = null;
  stage.addEventListener('pointerdown', (e) => { sx = e.clientX; });
  stage.addEventListener('pointerup', (e) => {
    if (sx !== null && n > 1 && Math.abs(e.clientX - sx) > 60) step(e.clientX < sx ? 1 : -1);
    sx = null;
  });
  openSheet((close) => [
    h('div', { class: 'viewer-bar' },
      iconBtn('close', 'Close', close, 'on-dark'),
      counter,
      h('div', { class: 'viewer-actions' },
        iconBtn('copy', 'Copy image', () => copyImage(current()?.blob), 'on-dark'),
        iconBtn('download', 'Save image', () => saveImage(current()?.blob, `${slug(it.title)}-${i + 1}.jpg`), 'on-dark'))),
    stage,
    n > 1 && h('div', { class: 'viewer-nav' },
      iconBtn('back', 'Previous photo', () => step(-1), 'on-dark'),
      iconBtn('forward', 'Next photo', () => step(1), 'on-dark')),
  ], { cls: 'viewer' });
  show();
}

async function toPng(blob) {
  const bmp = await createImageBitmap(blob);
  const c = document.createElement('canvas');
  c.width = bmp.width;
  c.height = bmp.height;
  c.getContext('2d').drawImage(bmp, 0, 0);
  return new Promise((res, rej) => c.toBlob((b) => (b ? res(b) : rej(new Error('PNG failed'))), 'image/png'));
}

async function copyImage(blob) {
  if (!blob) return;
  if (!navigator.clipboard?.write || typeof ClipboardItem === 'undefined') {
    toast('This browser can\'t copy images. Use Save instead.', 'error');
    return;
  }
  try {
    // Hand the clipboard a promise right away so Safari keeps the user gesture.
    clearTimeout(S.clipTimer);
    await navigator.clipboard.write([new ClipboardItem({ 'image/png': toPng(blob) })]);
    const sec = settings.clearClipSec;
    toast(sec ? `Image copied · clears in ${sec}s` : 'Image copied');
    if (sec > 0) S.clipTimer = setTimeout(clearClipboard, sec * 1000);
  } catch {
    toast('Couldn\'t copy the image. Use Save instead.', 'error');
  }
}

function blobToBase64(blob) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result).split(',')[1] || '');
    r.onerror = () => reject(r.error);
    r.readAsDataURL(blob);
  });
}

/** Saves a file: a download in the browser, Android's "save to" picker in the app. */
async function saveBlob(blob, name) {
  if (android) {
    android.saveFile(name, (blob.type || 'application/octet-stream').split(';')[0], await blobToBase64(blob));
    return;
  }
  const url = URL.createObjectURL(blob);
  const a = h('a', { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

async function saveImage(blob, name) {
  if (!blob) return;
  const file = new File([blob], name, { type: blob.type || 'image/jpeg' });
  const touch = matchMedia('(pointer: coarse)').matches;
  if (touch && navigator.canShare?.({ files: [file] })) {
    try {
      await navigator.share({ files: [file] });
      return;
    } catch (e) {
      if (e?.name === 'AbortError') return;
    }
  }
  await saveBlob(blob, name);
}

async function deleteItem(it) {
  const ok = await confirmSheet({
    title: `Delete “${it.title}”?`,
    message: `It moves to Recently deleted, where you can restore it for ${BIN_DAYS} days.`,
    confirmLabel: 'Delete',
    danger: true,
  });
  if (!ok) return;
  try {
    await updateItem(it.id, (x) => ({ ...x, deletedAt: Date.now() }));
    toast('Moved to Recently deleted');
    back('#/');
  } catch (e) {
    toast(e?.code ? dbMessage(e) : e.message, 'error');
  }
}

async function restoreItem(it) {
  try {
    await updateItem(it.id, (x) => {
      delete x.deletedAt;
      return x;
    });
    toast(`Restored “${it.title}”`);
    if (route().view === 'item') location.replace(`#/item/${encodeURIComponent(it.id)}`);
    refreshView();
  } catch (e) {
    toast(e?.code ? dbMessage(e) : e.message, 'error');
  }
}

async function deleteForever(it) {
  const ok = await confirmSheet({
    title: `Delete “${it.title}” forever?`,
    message: it.photos.length
      ? `This permanently removes it and its ${it.photos.length} photo${it.photos.length > 1 ? 's' : ''}. It can't be undone.`
      : 'This permanently removes it. It can\'t be undone.',
    confirmLabel: 'Delete forever',
    danger: true,
  });
  if (!ok) return;
  try {
    await purgeItem(it);
    toast('Deleted for good');
    if (route().view === 'item') location.replace('#/bin');
    else refreshView();
  } catch (e) {
    if (e instanceof ConflictError) toast(`“${it.title}” was just changed on another device, so it wasn't deleted.`, 'error');
    else toast(e?.code ? dbMessage(e) : e.message, 'error');
    refreshView();
  }
}

function renderBin() {
  const listEl = h('div', { class: 'list-sections' });
  const emptyBtn = btn('Empty', {
    kind: 'danger-ghost', small: true, icon: 'trash',
    onClick: async () => {
      const items = binItems();
      if (!items.length) return;
      const ok = await confirmSheet({
        title: 'Empty Recently deleted?',
        message: `This permanently removes ${items.length} item${items.length > 1 ? 's' : ''} and their photos. It can't be undone.`,
        confirmLabel: 'Delete forever', danger: true,
      });
      if (!ok) return;
      const done = busy('Deleting…');
      let kept = 0;
      for (const it of items) {
        try { await purgeItem(it); } catch { kept++; }
      }
      done();
      toast(kept ? `${kept} item(s) were changed on another device and were kept.` : 'Recently deleted is empty');
      paint();
    },
  });
  function paint() {
    const items = binItems().sort((a, b) => b.deletedAt - a.deletedAt);
    emptyBtn.hidden = !items.length;
    if (!items.length) {
      listEl.replaceChildren(h('div', { class: 'empty' },
        h('h2', null, 'Nothing here'),
        h('p', { class: 'muted' }, `Items you delete stay here for ${BIN_DAYS} days, so you can restore them. After that they're removed for good.`)));
      return;
    }
    listEl.replaceChildren(
      h('p', { class: 'muted small' }, `Items are removed for good ${BIN_DAYS} days after you delete them.`),
      h('div', { class: 'list' }, items.map((it) => {
        const row = h('div', { class: 'row', role: 'button', tabindex: '0' },
          typeTile(it.type),
          h('div', { class: 'row-main' },
            h('div', { class: 'row-title' }, it.title),
            h('div', { class: 'row-sub' }, h('span', null, `${TYPES[it.type]?.label || 'Item'} · ${daysLeft(it)} left`))),
          iconBtn('restore', `Restore ${it.title}`, (e) => { e.stopPropagation(); restoreItem(it); }));
        const open = () => go(`#/item/${encodeURIComponent(it.id)}`);
        onPress(row, { onTap: open });
        row.addEventListener('keydown', (e) => { if (e.key === 'Enter') open(); });
        return row;
      })));
  }
  screen('bin-screen',
    topbar({ left: iconBtn('back', 'Back', () => back('#/settings')), title: 'Recently deleted', right: emptyBtn }),
    h('div', { class: 'content' }, listEl));
  paint();
  S.repaint = paint;
}

// =====================================================================
// Screens: editor
// =====================================================================

function placeholderFor(type, label, kind) {
  const all = [...(TYPES[type]?.fields || []), ...Object.values(TYPES[type]?.presetFields || {}).flat()];
  const tf = all.find(([l]) => l === label);
  return (tf && tf[2]) || KIND_INFO[kind]?.placeholder || '';
}

/** Ask what to do when the item changed on another device during editing. */
function conflictSheet(title, deletedThere) {
  return new Promise((resolve) => {
    let answer = null;
    openSheet((close) => [
      h('div', { class: 'sheet-handle' }),
      h('h3', { class: 'sheet-title' }, deletedThere ? 'Deleted on another device' : 'Changed on another device'),
      h('p', { class: 'muted' }, deletedThere
        ? `“${title}” was deleted on another device while you were editing it here.`
        : `“${title}” was changed on another device after you started editing it here. Nothing has been overwritten yet.`),
      h('div', { class: 'stack-sm' },
        btn(deletedThere ? 'Save mine as a new item' : 'Keep both', { block: true, onClick: () => { answer = 'copy'; close(); } }),
        deletedThere ? null : btn('Replace theirs with mine', { kind: 'secondary', block: true, onClick: () => { answer = 'mine'; close(); } }),
        btn('Discard my changes', { kind: 'danger-ghost', block: true, onClick: () => { answer = 'discard'; close(); } })),
    ], { onClose: () => resolve(answer) });
  });
}

function renderEditor(id, typeKey) {
  const existing = id ? S.items.get(id) : null;
  if (id && (!existing || existing.deletedAt)) { location.replace(id && existing ? `#/item/${encodeURIComponent(id)}` : '#/'); return; }
  const type = existing ? existing.type : (TYPES[typeKey] ? typeKey : 'note');
  const t = TYPES[type];
  const base = existing ? baseOf(existing.id) : 'none';
  const draft = existing
    ? { ...structuredClone(existing), pending: [], removed: [] }
    : { type, title: '', notes: '', photos: [], pending: [], removed: [], fields: t.fields.map(fieldFromSpec) };
  // Dates saved by older versions were plain text: give them their proper kind.
  for (const f of draft.fields) f.kind = kindOf(f) === 'text' ? (f.kind || 'text') : kindOf(f);
  let dirty = false;
  const touch = () => { dirty = true; };

  const remoteBanner = h('div', { class: 'banners' });
  const titleInput = h('input', {
    class: 'input input-title', value: draft.title, placeholder: t.titleHint, 'aria-label': 'Name',
    oninput: (e) => { draft.title = e.target.value; touch(); },
  });
  const presets = t.presets ? h('div', { class: 'presets' }, t.presets.map((p) => h('button', {
    type: 'button', class: 'chip small',
    onclick: () => {
      titleInput.value = p;
      draft.title = p;
      const extra = t.presetFields?.[p];
      if (extra) {
        const blank = draft.fields.every((f) => !f.value.trim());
        if (blank) draft.fields = extra.map(fieldFromSpec);
        else for (const spec of extra) if (!draft.fields.some((f) => f.label === spec[0])) draft.fields.push(fieldFromSpec(spec));
        paintFields();
      }
      touch();
    },
  }, p))) : null;

  const fieldsEl = h('div', { class: 'stack-sm' });
  function paintFields() {
    fieldsEl.replaceChildren(...draft.fields.map((f, idx) => fieldEditor(f, idx)));
  }
  function fieldEditor(f, idx) {
    const msg = h('p', { class: 'field-msg', role: 'alert' });
    const showCheck = () => {
      const c = checkField(f);
      msg.textContent = c.error || c.warning || '';
      msg.classList.toggle('warn', !c.error && !!c.warning);
      valueInput.classList.toggle('invalid', !!c.error);
      return c;
    };
    const kind = kindOf(f);
    const valueInput = h('input', {
      class: `input${f.secret || ['cardnum', 'bsb'].includes(kind) ? ' mono' : ''}`,
      type: f.secret ? 'password' : 'text',
      inputmode: KIND_INFO[kind]?.inputmode,
      value: f.value, placeholder: placeholderFor(type, f.label, kind) || 'Value', autocomplete: 'off', ...noAssist,
      'aria-label': f.label || 'Value',
      oninput: (e) => {
        autoFormat(kindOf(f), valueInput, e);
        f.value = valueInput.value;
        touch();
        if (msg.textContent) showCheck();
      },
      onblur: () => {
        const c = showCheck();
        if (!c.error && c.value !== valueInput.value.trim() && c.value) { valueInput.value = c.value; f.value = c.value; }
      },
    });
    let shown = false;
    const eye = f.secret ? h('button', {
      type: 'button', class: 'input-adorn', 'aria-label': 'Show value',
      onclick: () => {
        shown = !shown;
        valueInput.type = shown ? 'text' : 'password';
        eye.replaceChildren(icon(shown ? 'eyeOff' : 'eye'));
      },
    }, icon('eye')) : null;
    const gen = (type === 'login' || type === 'wifi') && f.secret ? btn('Generate', {
      kind: 'secondary', small: true, icon: 'dice',
      onClick: () => openGenerator((pw) => {
        f.value = pw;
        valueInput.value = pw;
        valueInput.type = 'text';
        shown = true;
        eye?.replaceChildren(icon('eyeOff'));
        touch();
      }),
    }) : null;
    const labelInput = h('input', {
      class: 'input-label', value: f.label, placeholder: 'Label', 'aria-label': 'Field label', ...noAssist,
      oninput: (e) => { f.label = e.target.value; touch(); },
      onchange: () => {
        // A field renamed to something like "Expiry" becomes a date field.
        if (!f.kind || f.kind === 'text' || f.kind === 'date' || f.kind === 'month') {
          f.kind = 'text';
          f.kind = kindOf(f) === 'text' ? 'text' : kindOf(f);
          paintFields();
        }
      },
    });
    const card = h('div', { class: 'field-card' },
      h('div', { class: 'field-card-head' },
        labelInput,
        h('button', {
          type: 'button', class: `pill-toggle${f.secret ? ' on' : ''}`, 'aria-pressed': String(!!f.secret),
          title: f.secret ? 'Hidden until you tap it' : 'Always visible',
          onclick: () => { f.secret = !f.secret; touch(); paintFields(); },
        }, icon(f.secret ? 'lock' : 'eye'), h('span', null, f.secret ? 'Hidden' : 'Visible')),
        iconBtn('trash', 'Remove field', () => { draft.fields.splice(idx, 1); touch(); paintFields(); })),
      h('div', { class: 'input-wrap' }, valueInput, eye),
      msg,
      gen);
    if (f.value) showCheck();
    return card;
  }

  const fileInput = h('input', {
    type: 'file', accept: 'image/*', multiple: true, class: 'visually-hidden', tabindex: '-1',
    onchange: (e) => {
      for (const file of e.target.files) {
        const url = URL.createObjectURL(file);
        S.tempUrls.add(url);
        draft.pending.push({ file, url });
      }
      e.target.value = '';
      touch();
      paintPhotos();
    },
  });
  const photosEl = h('div', { class: 'photo-grid' });
  function paintPhotos() {
    const existingThumbs = draft.photos.map((p, i) => {
      const img = h('img', { alt: '' });
      loadPhoto(p).then((e) => { img.src = e.url; }).catch(() => {});
      return h('div', { class: 'photo' }, img,
        iconBtn('close', 'Remove photo', () => { draft.removed.push(p); draft.photos.splice(i, 1); touch(); paintPhotos(); }, 'photo-remove'));
    });
    const pendingThumbs = draft.pending.map((p, i) => h('div', { class: 'photo pending' },
      h('img', { alt: '', src: p.url }),
      iconBtn('close', 'Remove photo', () => {
        URL.revokeObjectURL(p.url);
        S.tempUrls.delete(p.url);
        draft.pending.splice(i, 1);
        paintPhotos();
      }, 'photo-remove')));
    photosEl.replaceChildren(...existingThumbs, ...pendingThumbs,
      h('button', { type: 'button', class: 'photo add', onclick: () => fileInput.click() }, icon('camera'), h('span', null, 'Add photo')));
  }

  const notes = h('textarea', {
    class: 'input textarea', rows: '4', placeholder: 'Anything else worth keeping, e.g. security questions or recovery codes', value: draft.notes || '',
    ...noAssist, 'aria-label': 'Notes',
    oninput: (e) => { draft.notes = e.target.value; touch(); },
  });

  const saveBtn = btn('Save', { small: true, onClick: () => save() });
  const formErr = h('p', { class: 'form-error', role: 'alert' });

  const leave = (toId) => {
    for (const p of draft.pending) { URL.revokeObjectURL(p.url); S.tempUrls.delete(p.url); }
    if (toId && existing) back(`#/item/${encodeURIComponent(toId)}`);
    else if (toId) location.replace(`#/item/${encodeURIComponent(toId)}`);
    else back(existing ? `#/item/${encodeURIComponent(existing.id)}` : '#/');
  };

  async function cancel() {
    if (dirty && !(await confirmSheet({ title: 'Discard changes?', confirmLabel: 'Discard', danger: true }))) return;
    leave();
  }

  // Live warning when this item changes on another device while it's open here.
  function onRemote() {
    if (!existing) return;
    const now = S.items.get(existing.id);
    const gone = !now || now.deletedAt;
    remoteBanner.replaceChildren(h('div', { class: 'banner warn static' }, icon('alert'),
      h('span', null, h('strong', null, gone ? 'Deleted on another device. ' : 'Changed on another device. '),
        gone ? 'Saving will ask what to do.' : 'Load their version, or keep editing and choose when you save.'),
      gone ? null : btn('Load', {
        kind: 'secondary', small: true,
        onClick: async () => {
          if (dirty && !(await confirmSheet({ title: 'Load the other device\'s version?', message: 'Your unsaved changes here will be lost.', confirmLabel: 'Load', danger: true }))) return;
          for (const p of draft.pending) { URL.revokeObjectURL(p.url); S.tempUrls.delete(p.url); }
          renderEditor(existing.id);
          toast('Loaded the latest version');
        },
      })));
  }

  async function save() {
    formErr.textContent = '';
    const key = S.key;
    const title = (draft.title || '').trim() || t.label;
    const checks = draft.fields.map((f) => ({ f, c: checkField(f) }));
    const bad = checks.find(({ c }) => c.error);
    if (bad) {
      formErr.textContent = bad.c.error;
      paintFields();
      fieldsEl.querySelector('.input.invalid')?.focus();
      return;
    }
    const fieldsOut = checks
      .filter(({ f }) => f.label.trim() || f.value.trim())
      .map(({ f, c }) => ({ label: f.label.trim(), value: c.value, secret: !!f.secret, kind: kindOf(f) }));
    const done = busy(draft.pending.length ? 'Encrypting photos…' : 'Encrypting and saving…');
    try {
      // Each photo is moved out of `pending` once uploaded, so a retry won't upload it twice.
      let k = 0;
      while (draft.pending.length) {
        const p = draft.pending[0];
        done(`Encrypting photo ${++k}…`);
        const img = await prepareImage(p.file);
        if (S.key !== key) return done();
        const ref = await uploadPhoto(img);
        draft.photos.push(ref);
        draft.pending.shift();
        URL.revokeObjectURL(p.url);
        S.tempUrls.delete(p.url);
      }
      done('Saving…');
      const now = Date.now();
      const itemId = existing ? existing.id : newId();
      const { pending: _p, removed: _r, id: _i, ...extras } = draft;
      const item = {
        ...extras, type, title, fields: fieldsOut, photos: draft.photos, notes: (draft.notes || '').trim(),
        createdAt: existing?.createdAt || now, updatedAt: now,
      };
      item.history = nextHistory(S.items.get(itemId) || existing, item, now);
      if (!item.history.length) delete item.history;
      let result;
      try {
        result = await putItem(itemId, item, { base, drop: draft.removed });
      } catch (e) {
        if (!(e instanceof ConflictError)) throw e;
        done();
        const theirsData = e.server;
        const choice = await conflictSheet(title, !theirsData);
        if (!choice) return;
        if (choice === 'discard') {
          await adoptServer(itemId, theirsData);
          dirty = false;
          if (theirsData) leave(itemId);
          else { leave(); }
          return;
        }
        const again = busy('Saving…');
        try {
          if (choice === 'copy') {
            const copyId = newId();
            const copy = { ...item, title: theirsData ? `${title} (copy)` : title, createdAt: now };
            await adoptServer(itemId, theirsData);
            result = await putItem(copyId, copy, { base: 'none' });
            again();
            dirty = false;
            toast(theirsData ? 'Saved yours as a copy' : 'Saved as a new item');
            leave(copyId);
            return;
          }
          // Replace theirs: their password (if it differs) goes into the history.
          await adoptServer(itemId, theirsData);
          item.history = nextHistory(S.items.get(itemId), item, now);
          result = await putItem(itemId, item, { base: baseOf(itemId), drop: draft.removed });
        } finally {
          again();
        }
      }
      dirty = false;
      done();
      toast(result === 'queued' ? 'Saved on this device · will sync when online' : 'Saved');
      leave(itemId);
    } catch (e) {
      done();
      paintPhotos();
      toast(e?.code ? dbMessage(e) : (e?.message || 'Couldn\'t save'), 'error');
    }
  }

  screen('editor-screen',
    topbar({
      left: btn('Cancel', { kind: 'ghost', small: true, onClick: cancel }),
      title: existing ? `Edit ${t.label.toLowerCase()}` : `New ${t.label.toLowerCase()}`,
      right: saveBtn,
    }),
    h('form', { class: 'content', onsubmit: (e) => { e.preventDefault(); save(); } },
      remoteBanner,
      h('div', { class: 'editor-head' }, typeTile(type, true), titleInput),
      presets,
      h('section', { class: 'section' },
        h('h2', { class: 'section-title' }, 'Details'),
        fieldsEl,
        btn('Add field', {
          kind: 'secondary', small: true, icon: 'plus',
          onClick: () => { draft.fields.push({ label: '', value: '', secret: false, kind: 'text' }); touch(); paintFields(); fieldsEl.lastChild?.querySelector('input')?.focus(); },
        })),
      h('section', { class: 'section' },
        h('h2', { class: 'section-title' }, 'Photos'),
        t.photoHint && h('p', { class: 'muted small' }, t.photoHint),
        photosEl,
        fileInput),
      h('section', { class: 'section' },
        h('h2', { class: 'section-title' }, 'Notes'),
        notes),
      formErr,
      btn('Save', { type: 'submit', block: true, icon: 'lock' }),
      h('p', { class: 'hint' }, 'Saved items are encrypted on this device before upload.')));
  paintFields();
  paintPhotos();
  S.editing = existing ? { id: existing.id, onRemote } : null;
  S.onBack = cancel;
  if (!existing) focusSoon(titleInput);
}

function openGenerator(onUse) {
  let len = 20;
  let symbols = true;
  const out = h('div', { class: 'gen-output mono' });
  const lenLabel = h('span', null);
  const regen = () => {
    out.textContent = vc.generatePassword(len, { symbols });
    lenLabel.textContent = `Length: ${len}`;
  };
  openSheet((close) => [
    h('div', { class: 'sheet-handle' }),
    h('h3', { class: 'sheet-title' }, 'Generate password'),
    out,
    h('label', { class: 'gen-row' }, lenLabel,
      h('input', { type: 'range', min: '12', max: '40', value: String(len), oninput: (e) => { len = Number(e.target.value); regen(); } })),
    h('label', { class: 'check-row' },
      h('input', { type: 'checkbox', checked: true, onchange: (e) => { symbols = e.target.checked; regen(); } }),
      h('span', null, 'Include symbols')),
    h('div', { class: 'sheet-actions' },
      btn('New one', { kind: 'secondary', icon: 'refresh', onClick: regen }),
      btn('Use password', { onClick: () => { onUse(out.textContent); close(); } })),
  ]);
  regen();
}

// =====================================================================
// Recovery
// Master password: a recovery key and/or the user's own security questions can set a
// new one (each is another wrap of the same data key, see vault-crypto.js).
// Sign-in account: an email reset link, or a text-message code to a linked phone.
// Neither email nor SMS can open the vault by itself.
// =====================================================================

const QUESTION_IDEAS = [
  'What was the name of your first pet?',
  'What street did you grow up on?',
  'What was your childhood nickname?',
  'What was the first concert you went to?',
  'What was the name of your primary school?',
  'What was the make of your first car?',
  'In what city did your parents meet?',
  'What is your favourite teacher\'s surname?',
];

const fmtDay = (ts) => new Date(ts).toLocaleDateString('en-AU', { day: 'numeric', month: 'short', year: 'numeric' });

function refreshSettings() {
  if (S.key && curHash() === '#/settings') renderSettings();
}

function downloadText(text, name) {
  saveBlob(new Blob([text], { type: 'text/plain;charset=utf-8' }), name);
}

function recoveryKitText(rk) {
  return [
    'CyberVault recovery key',
    '=======================',
    `Account: ${S.user?.email || S.user?.phoneNumber || ''}`,
    `Firebase project: ${activeConfig?.projectId || ''}`,
    `Created: ${fmtDate(Date.now())}`,
    '',
    'Recovery key:',
    rk,
    '',
    'Forgot your master password? Open CyberVault, sign in, tap "Forgot master password?"',
    'on the lock screen, choose "Recovery key" and type the key above.',
    '',
    'Keep this somewhere safe and offline, such as printed or in a password manager.',
    'Anyone with this key AND your sign-in can open your vault.',
    '',
  ].join('\n');
}

function recoveryKeyBox(rk) {
  return h('div', { class: 'stack-sm' },
    h('div', { class: 'recovery-key mono', 'aria-label': 'Recovery key' }, rk),
    h('div', { class: 'btn-row' },
      btn('Copy', { kind: 'secondary', small: true, icon: 'copy', onClick: () => copyText(rk, 'Recovery key copied') }),
      btn('Download', { kind: 'secondary', small: true, icon: 'download', onClick: () => downloadText(recoveryKitText(rk), 'cybervault-recovery-key.txt') })));
}

/** Three question + answer pairs. read() validates and returns { questions, answers }. */
function questionFields(existing = []) {
  const listId = `q-ideas-${Math.random().toString(36).slice(2, 8)}`;
  const rows = [0, 1, 2].map((i) => {
    const q = h('input', {
      class: 'input', list: listId, value: existing[i] || '', placeholder: QUESTION_IDEAS[i * 2],
      'aria-label': `Question ${i + 1}`, ...noAssist, autocapitalize: 'sentences',
    });
    const a = h('input', { class: 'input', autocomplete: 'off', placeholder: 'Your answer', 'aria-label': `Answer ${i + 1}`, ...noAssist });
    return { q, a, el: h('div', { class: 'qa' }, h('span', { class: 'qa-num' }, `Q${i + 1}`), h('div', { class: 'qa-fields' }, q, a)) };
  });
  const el = h('div', { class: 'stack-sm' },
    h('datalist', { id: listId }, QUESTION_IDEAS.map((t) => h('option', { value: t }))),
    rows.map((r) => r.el));
  function read() {
    const questions = rows.map((r) => r.q.value.trim());
    const answers = rows.map((r) => r.a.value);
    if (questions.some((x) => !x)) throw new Error('Write all three questions.');
    if (new Set(questions.map((x) => x.toLowerCase())).size < 3) throw new Error('Use three different questions.');
    if (answers.some((x) => vc.normalizeAnswer(x).length < 3)) throw new Error('Each answer needs at least 3 letters or numbers.');
    return { questions, answers };
  }
  return { el, read };
}

function newPasswordFields() {
  const pw = pwInput({ autocomplete: 'new-password', placeholder: 'At least 10 characters' });
  const pw2 = pwInput({ autocomplete: 'new-password', placeholder: 'Type it again' });
  const meter = strengthMeter();
  pw.input.addEventListener('input', () => meter.update(pw.input.value));
  return {
    el: [field('New master password', pw.wrap), meter.el, field('Confirm new master password', pw2.wrap)],
    read() {
      const p = pw.input.value;
      if (p.length < 10) throw new Error('Use at least 10 characters for the new master password.');
      if (vc.passwordStrength(p).score < 2) throw new Error('That master password is too easy to guess. A passphrase of 4 or more random words works well.');
      if (p !== pw2.input.value) throw new Error('The new passwords don\'t match.');
      return p;
    },
  };
}

// ---------- onboarding, right after the vault is created ----------

function renderRecoveryKeyOnboarding(rk, password) {
  const ack = h('input', { type: 'checkbox' });
  const err = h('p', { class: 'form-error', role: 'alert' });
  ack.addEventListener('change', () => { err.textContent = ''; });
  screen('center', h('div', { class: 'auth-card' },
    brandMark('key'),
    h('h1', null, 'Save your recovery key'),
    h('p', { class: 'muted' }, 'If you ever forget your master password, this key lets you set a new one. It\'s shown only now, so keep it somewhere safe away from this device: print it, write it down, or save it in a password manager.'),
    recoveryKeyBox(rk),
    h('label', { class: 'check-row' }, ack, h('span', null, 'I\'ve saved my recovery key somewhere safe.')),
    err,
    btn('Continue', {
      block: true, icon: 'forward',
      onClick: () => {
        if (!ack.checked) {
          err.textContent = 'Save the key first, then tick the box. You won\'t see this key again, though you can make a new one in Settings.';
          return;
        }
        renderQuestionsOnboarding(password);
      },
    })));
}

function renderQuestionsOnboarding(password) {
  const qf = questionFields();
  const err = h('p', { class: 'form-error', role: 'alert' });
  const save = btn('Save questions', { block: true, icon: 'lock' });
  const finish = (msg) => {
    S.nav = [];
    history.replaceState(null, '', '#/');
    render();
    toast(msg);
  };
  save.addEventListener('click', async () => {
    err.textContent = '';
    let v;
    try { v = qf.read(); } catch (x) { err.textContent = x.message; return; }
    if (!onlineOr(err)) return;
    setBusy(save, true, 'Saving…');
    try {
      const meta = await vc.setSecurityQuestions(password, S.meta, v.questions, v.answers);
      await setDoc(vaultRef(), meta);
      S.meta = meta;
      finish('Vault created, with recovery set up');
    } catch (x) {
      err.textContent = x.code ? dbMessage(x) : x.message;
      setBusy(save, false, 'Save questions');
    }
  });
  screen('center', h('div', { class: 'auth-card' },
    brandMark('help'),
    h('h1', null, 'Security questions'),
    h('p', { class: 'muted' }, 'Optional: a second way to reset your master password, by answering three questions you write yourself. Capitals and punctuation in answers are ignored.'),
    h('div', { class: 'term-lines warn-lines' },
      h('span', null, 'pick answers nobody could look up or guess'),
      h('span', null, 'they don\'t have to be true, just memorable')),
    qf.el,
    err,
    save,
    btn('Skip for now', { kind: 'ghost', block: true, onClick: () => finish('Vault created') })));
}

// ---------- forgot master password ----------

function renderRecover() {
  const m = S.meta || {};
  const methods = [m.recovery ? 'key' : null, m.questions ? 'questions' : null].filter(Boolean);
  let method = methods[0] || null;
  const err = h('p', { class: 'form-error', role: 'alert' });
  const tabs = h('div', { class: 'seg', role: 'tablist' });
  const body = h('div', { class: 'stack' });

  function paintTabs() {
    tabs.hidden = methods.length < 2;
    tabs.replaceChildren(...methods.map((k) => h('button', {
      type: 'button', role: 'tab', class: `seg-btn${k === method ? ' active' : ''}`, 'aria-selected': String(k === method),
      onclick: () => { method = k; err.textContent = ''; paintTabs(); paintBody(); },
    }, k === 'key' ? 'Recovery key' : 'Security questions')));
  }

  function paintBody() {
    if (!method) {
      body.replaceChildren(h('p', { class: 'muted' },
        'No recovery key or security questions were set up for this vault, so the master password can\'t be reset. If you remember it later, you can still unlock as usual.'));
      return;
    }
    const np = newPasswordFields();
    const submit = btn('Reset master password', { type: 'submit', block: true, icon: 'key' });
    let proof;
    if (method === 'key') {
      const input = h('input', {
        class: 'input mono', placeholder: 'XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX', autocomplete: 'off',
        ...noAssist, autocapitalize: 'characters', 'aria-label': 'Recovery key',
      });
      proof = { el: field('Recovery key', input), run: (pw) => vc.resetWithRecoveryKey(input.value, pw, S.meta) };
    } else {
      const inputs = m.questions.list.map((q, i) => h('input', { class: 'input', autocomplete: 'off', ...noAssist, 'aria-label': `Answer ${i + 1}` }));
      proof = { el: m.questions.list.map((q, i) => h('label', { class: 'field q-field' }, h('span', { class: 'field-label' }, q), inputs[i])), run: (pw) => vc.resetWithAnswers(inputs.map((x) => x.value), pw, S.meta) };
    }
    body.replaceChildren(h('form', {
      class: 'stack',
      onsubmit: async (e) => {
        e.preventDefault();
        err.textContent = '';
        let pw;
        try { pw = np.read(); } catch (x) { err.textContent = x.message; return; }
        if (!onlineOr(err)) return;
        setBusy(submit, true, 'Checking…');
        try {
          const { meta, key } = await proof.run(pw);
          await setDoc(vaultRef(), meta);
          S.meta = meta;
          S.key = key;
          S.lastActivity = Date.now();
          await startSync();
          S.nav = [];
          history.replaceState(null, '', '#/');
          render();
          toast('Master password reset. Use the new one on every device.');
        } catch (x) {
          S.key = null;
          if (x instanceof vc.WrongRecoveryError) {
            err.textContent = method === 'key' ? 'That recovery key doesn\'t match this vault.' : 'One or more answers don\'t match.';
          } else {
            err.textContent = x.code ? dbMessage(x) : x.message;
          }
          setBusy(submit, false, 'Reset master password');
        }
      },
    }, proof.el, np.el, err, submit));
  }

  paintTabs();
  paintBody();
  screen('center recover', h('div', { class: 'auth-card' },
    brandMark('key'),
    h('h1', null, 'Reset master password'),
    h('p', { class: 'muted' }, 'Prove it\'s you with your recovery key or security questions, then choose a new master password. Your items stay exactly as they are.'),
    tabs,
    body,
    h('div', { class: 'auth-links' },
      h('button', { type: 'button', class: 'link', onclick: renderUnlock }, '← Back to unlock'),
      h('button', { type: 'button', class: 'link danger-link', onclick: openEraseVault }, 'Erase vault and start over'))));
}

async function eraseVault() {
  if (!navigator.onLine) throw new OfflineError();
  stopSync();
  writeOutbox([]);
  for (const [name, page] of [['items', 200], ['blobs', 10]]) {
    const col = collection(db, 'users', uid(), name);
    for (;;) {
      const snap = await getDocs(query(col, limit(page)));
      if (snap.empty) break;
      const batch = writeBatch(db);
      for (const d of snap.docs) batch.delete(doc(db, 'users', uid(), name, d.id));
      await batch.commit();
    }
  }
  const batch = writeBatch(db);
  batch.delete(vaultRef());
  await batch.commit();
}

function openEraseVault() {
  const input = h('input', { class: 'input mono', placeholder: 'ERASE', ...noAssist, autocapitalize: 'characters', 'aria-label': 'Type ERASE to confirm' });
  const err = h('p', { class: 'form-error', role: 'alert' });
  const go = btn('Erase everything', { kind: 'danger', block: true, icon: 'trash' });
  go.disabled = true;
  input.addEventListener('input', () => { go.disabled = input.value.trim().toUpperCase() !== 'ERASE'; });
  const close = openSheet(() => [
    h('div', { class: 'sheet-handle' }),
    h('h3', { class: 'sheet-title' }, 'Erase vault and start over?'),
    h('p', { class: 'muted' }, 'This permanently deletes every item and photo in this vault. Nobody, including you, can get them back. Afterwards you can create a new, empty vault with a new master password.'),
    field('Type ERASE to confirm', input),
    err,
    go,
  ]);
  go.addEventListener('click', async () => {
    setBusy(go, true, 'Erasing…');
    try {
      await eraseVault();
      close();
      lock(false);
      S.meta = null;
      renderCreateVault();
      toast('Vault erased');
    } catch (x) {
      err.textContent = dbMessage(x);
      setBusy(go, false, 'Erase everything');
    }
  });
  focusSoon(input, 250);
}

// ---------- Settings → Recovery ----------

function recoverySection() {
  const m = S.meta || {};
  const u = auth.currentUser || S.user;
  const providers = (u.providerData || []).map((p) => p.providerId);
  const row = (label, value, action) => h('div', { class: 'kv' },
    h('div', { class: 'kv-text' }, h('div', { class: 'kv-label' }, label), h('div', { class: 'kv-value small-value' }, value)),
    action ? h('div', { class: 'kv-actions' }, action) : null);
  const emailText = providers.includes('password') ? `Sent to ${u.email}`
    : providers.includes('google.com') ? 'Google account: recover it through Google' : 'Not available for this sign-in';
  return h('section', { class: 'section' },
    h('h2', { class: 'section-title' }, 'Recovery'),
    h('p', { class: 'muted small pad-x' }, 'Forgot your master password? These can set a new one.'),
    h('div', { class: 'card kv-list' },
      row('Recovery key', m.recovery ? `Saved · created ${fmtDay(m.recovery.createdAt)}` : 'Not set up',
        btn(m.recovery ? 'New key' : 'Create', { kind: 'secondary', small: true, onClick: openRecoveryKeySheet })),
      row('Security questions', m.questions ? `${m.questions.list.length} questions` : 'Not set up',
        btn(m.questions ? 'Change' : 'Set up', { kind: 'secondary', small: true, onClick: openQuestionsSheet }))),
    h('p', { class: 'muted small pad-x' }, 'Can\'t sign in? These get you back into your account. You still need your master password or a recovery option above to open the vault.'),
    h('div', { class: 'card kv-list' },
      row('Email reset link', emailText),
      row('Text message code', u.phoneNumber || 'No phone added',
        u.phoneNumber
          ? btn('Remove', { kind: 'ghost', small: true, onClick: removePhone })
          : btn('Add phone', { kind: 'secondary', small: true, onClick: openAddPhone }))));
}

function openRecoveryKeySheet() {
  const had = !!S.meta.recovery;
  const label = had ? 'Create new key' : 'Create key';
  const pw = pwInput({ autocomplete: 'off', placeholder: 'Master password' });
  const err = h('p', { class: 'form-error', role: 'alert' });
  const submit = btn(label, { type: 'submit', block: true, icon: 'key' });
  const body = h('div', { class: 'stack' });
  const close = openSheet(() => [
    h('div', { class: 'sheet-handle' }),
    h('h3', { class: 'sheet-title' }, had ? 'New recovery key' : 'Create a recovery key'),
    body,
  ], { onClose: refreshSettings });
  body.append(
    h('p', { class: 'muted' }, had
      ? 'This makes a new recovery key, and the old one stops working. Do this if you lost the old key or think someone saw it.'
      : 'A recovery key lets you set a new master password if you forget it.'),
    h('form', {
      class: 'stack',
      onsubmit: async (e) => {
        e.preventDefault();
        err.textContent = '';
        if (!onlineOr(err)) return;
        setBusy(submit, true, 'Creating…');
        try {
          const rk = vc.generateRecoveryKey();
          const meta = await vc.setRecoveryKey(pw.input.value, S.meta, rk);
          await setDoc(vaultRef(), meta);
          S.meta = meta;
          body.replaceChildren(
            h('p', { class: 'muted' }, `Here's your new recovery key. It's shown only now.${had ? ' Your old key no longer works.' : ''}`),
            recoveryKeyBox(rk),
            btn('Done', { block: true, onClick: close }));
        } catch (x) {
          err.textContent = x instanceof vc.WrongPasswordError ? 'Wrong master password.' : (x.code ? dbMessage(x) : x.message);
          setBusy(submit, false, label);
        }
      },
    }, field('Confirm with your master password', pw.wrap), err, submit));
  focusSoon(pw.input, 250);
}

function openQuestionsSheet() {
  const had = S.meta.questions;
  const qf = questionFields(had ? had.list : []);
  const pw = pwInput({ autocomplete: 'off', placeholder: 'Master password' });
  const err = h('p', { class: 'form-error', role: 'alert' });
  const save = btn('Save questions', { type: 'submit', block: true, icon: 'lock' });
  let close = () => {};
  const fail = (x) => { err.textContent = x instanceof vc.WrongPasswordError ? 'Wrong master password.' : (x.code ? dbMessage(x) : x.message); };
  const form = h('form', {
    class: 'stack',
    onsubmit: async (e) => {
      e.preventDefault();
      err.textContent = '';
      let v;
      try { v = qf.read(); } catch (x) { err.textContent = x.message; return; }
      if (!onlineOr(err)) return;
      setBusy(save, true, 'Saving…');
      try {
        const meta = await vc.setSecurityQuestions(pw.input.value, S.meta, v.questions, v.answers);
        await setDoc(vaultRef(), meta);
        S.meta = meta;
        close();
        toast('Security questions saved');
      } catch (x) {
        fail(x);
        setBusy(save, false, 'Save questions');
      }
    },
  }, qf.el, field('Confirm with your master password', pw.wrap), err, save);
  const remove = had ? btn('Remove security questions', {
    kind: 'danger-ghost', block: true, icon: 'trash',
    onClick: async () => {
      err.textContent = '';
      if (!onlineOr(err)) return;
      try {
        await vc.unlockVault(pw.input.value, S.meta); // confirm it's really you
        const meta = vc.removeRecovery(S.meta, 'questions');
        await setDoc(vaultRef(), meta);
        S.meta = meta;
        close();
        toast('Security questions removed');
      } catch (x) {
        fail(x);
      }
    },
  }) : null;
  close = openSheet(() => [
    h('div', { class: 'sheet-handle' }),
    h('h3', { class: 'sheet-title' }, 'Security questions'),
    h('p', { class: 'muted' }, `Answer these to reset a forgotten master password. Capitals and punctuation are ignored.${had ? ' Saving replaces your old questions and answers.' : ''}`),
    h('div', { class: 'term-lines warn-lines' }, h('span', null, 'pick answers nobody could look up or guess')),
    form,
    remove,
  ], { onClose: refreshSettings });
}

// ---------- phone (SMS) ----------

const COUNTRY_CODES = [['+61', 'AU'], ['+60', 'MY'], ['+852', 'HK'], ['+853', 'MO'], ['+886', 'TW'], ['+86', 'CN'], ['+65', 'SG'], ['+64', 'NZ'], ['+1', 'US/CA'], ['+44', 'UK']];

function phoneField() {
  const cc = h('select', { class: 'input select cc', 'aria-label': 'Country code', value: '+61' },
    COUNTRY_CODES.map(([c, n]) => h('option', { value: c }, `${n} ${c}`)));
  const num = h('input', { class: 'input', type: 'tel', inputmode: 'tel', autocomplete: 'tel-national', placeholder: '0491 570 156', 'aria-label': 'Phone number' });
  return {
    el: h('div', { class: 'phone-row' }, cc, num),
    value() {
      const raw = num.value.trim();
      if (raw.startsWith('+')) {
        const d = raw.replace(/[^\d+]/g, '');
        if (!/^\+\d{7,15}$/.test(d)) throw new Error('That phone number doesn\'t look right.');
        return d;
      }
      const digits = raw.replace(/\D/g, '').replace(/^0+/, '');
      if (digits.length < 6 || digits.length > 13) throw new Error('That phone number doesn\'t look right.');
      return cc.value + digits;
    },
  };
}

/**
 * Two steps: phone number → 6-digit code. `send(phone, verifier)` returns Firebase's
 * confirmation result; `done(credential)` runs once the code is accepted.
 */
function smsSteps({ send, done, sendLabel = 'Send code', confirmLabel = 'Verify', beforeConfirm, afterFail }) {
  const err = h('p', { class: 'form-error', role: 'alert' });
  const info = h('p', { class: 'form-ok', role: 'status' });
  const captchaBox = h('div', { class: 'captcha-box' });
  let verifier = null;
  let confirmation = null;
  const resetVerifier = () => {
    try { verifier?.clear(); } catch { /* ignore */ }
    verifier = null;
    captchaBox.replaceChildren();
  };
  const phone = phoneField();
  const sendBtn = btn(sendLabel, { kind: 'secondary', block: true, icon: 'phone' });
  const code = h('input', {
    class: 'input mono code-input', inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: '6',
    placeholder: '123456', 'aria-label': 'Code from the text message',
  });
  const confirmBtn = btn(confirmLabel, { block: true, icon: 'check' });
  const step1 = h('div', { class: 'stack-sm' },
    field('Phone number', phone.el, 'Pick the country code, then your number. Standard SMS rates may apply.'), sendBtn);
  const step2 = h('div', { class: 'stack-sm', hidden: true },
    field('6-digit code', code), confirmBtn,
    h('button', { type: 'button', class: 'link', onclick: () => { step2.hidden = true; step1.hidden = false; info.textContent = ''; err.textContent = ''; } }, 'Use a different number'));
  sendBtn.addEventListener('click', async () => {
    err.textContent = '';
    info.textContent = '';
    let number;
    try { number = phone.value(); } catch (x) { err.textContent = x.message; return; }
    setBusy(sendBtn, true, 'Sending…');
    try {
      resetVerifier();
      const holder = h('div');
      captchaBox.append(holder);
      verifier = new RecaptchaVerifier(auth, holder, { size: 'invisible' });
      confirmation = await send(number, verifier);
      info.textContent = `Code sent to ${number}.`;
      step1.hidden = true;
      step2.hidden = false;
      setTimeout(() => code.focus(), 100);
    } catch (x) {
      resetVerifier();
      err.textContent = authMessage(x);
    }
    setBusy(sendBtn, false, sendLabel);
  });
  confirmBtn.addEventListener('click', async () => {
    err.textContent = '';
    if (!/^\d{6}$/.test(code.value.trim())) { err.textContent = 'Enter the 6-digit code from the text message.'; return; }
    setBusy(confirmBtn, true, 'Checking…');
    try {
      beforeConfirm?.();
      const cred = await confirmation.confirm(code.value.trim());
      resetVerifier();
      await done(cred);
    } catch (x) {
      afterFail?.();
      err.textContent = x.code ? authMessage(x) : x.message;
    }
    setBusy(confirmBtn, false, confirmLabel);
  });
  return h('div', { class: 'stack-sm' }, step1, step2, info, err, captchaBox);
}

function openAddPhone() {
  const close = openSheet(() => [
    h('div', { class: 'sheet-handle' }),
    h('h3', { class: 'sheet-title' }, 'Add a phone number'),
    h('p', { class: 'muted' }, 'Lets you sign in with a text-message code if you can\'t use your password or Google. It doesn\'t open the vault: you still need your master password or recovery key.'),
    smsSteps({
      confirmLabel: 'Add phone',
      send: (phone, v) => linkWithPhoneNumber(auth.currentUser, phone, v),
      done: async () => {
        try { await reload(auth.currentUser); } catch { /* ignore */ }
        close();
        toast('Phone number added');
      },
    }),
  ], { onClose: refreshSettings });
}

async function removePhone() {
  const ok = await confirmSheet({
    title: 'Remove phone number?',
    message: 'You won\'t be able to sign in with a text-message code any more.',
    confirmLabel: 'Remove',
    danger: true,
  });
  if (!ok) return;
  try {
    await unlink(auth.currentUser, 'phone');
    try { await reload(auth.currentUser); } catch { /* ignore */ }
    toast('Phone number removed');
    refreshSettings();
  } catch (x) {
    toast(authMessage(x), 'error');
  }
}

// ---------- can't sign in? ----------

async function finishPhoneSignIn(cred, close) {
  if (getAdditionalUserInfo(cred)?.isNewUser) {
    // The number wasn't linked to anyone, so Firebase just made a new, empty account. Undo that,
    // and ignore any late auth events about it.
    S.ignoreUid = cred.user.uid;
    try { await deleteUser(cred.user); } catch { /* ignore */ }
    try { await signOut(auth); } catch { /* ignore */ }
    S.authHold = false;
    throw new Error('That number isn\'t linked to a CyberVault account. Sign in another way, then add your phone in Settings → Recovery.');
  }
  S.authHold = false;
  close();
  handleUser(auth.currentUser);
}

function openSignInHelp(prefillEmail = '') {
  const email = h('input', {
    class: 'input', type: 'email', inputmode: 'email', autocomplete: 'username', placeholder: 'you@example.com',
    value: prefillEmail, ...noAssist, 'aria-label': 'Email for the reset link',
  });
  const emailErr = h('p', { class: 'form-error', role: 'alert' });
  const emailOk = h('p', { class: 'form-ok', role: 'status' });
  const sendReset = btn('Send reset link', { kind: 'secondary', block: true, icon: 'mail' });
  sendReset.addEventListener('click', async () => {
    emailErr.textContent = '';
    emailOk.textContent = '';
    const v = email.value.trim();
    if (!v) { emailErr.textContent = 'Type your email first.'; return; }
    setBusy(sendReset, true, 'Sending…');
    try {
      await sendPasswordResetEmail(auth, v);
      emailOk.textContent = `If an account uses ${v}, a reset link is on its way. Check your inbox and spam folder.`;
    } catch (x) {
      emailErr.textContent = authMessage(x);
    }
    setBusy(sendReset, false, 'Send reset link');
  });
  let close = () => {};
  close = openSheet(() => [
    h('div', { class: 'sheet-handle' }),
    h('h3', { class: 'sheet-title' }, 'Can\'t sign in?'),
    h('div', { class: 'help-block' },
      h('h4', null, 'Reset your password by email'),
      h('p', { class: 'muted small' }, 'For accounts that sign in with email and password.'),
      email, sendReset, emailOk, emailErr),
    h('div', { class: 'help-block' },
      h('h4', null, 'Sign in with a text-message code'),
      h('p', { class: 'muted small' }, 'Works if you added your phone in Settings → Recovery.'),
      smsSteps({
        sendLabel: 'Text me a code',
        confirmLabel: 'Sign in',
        send: (phone, v) => signInWithPhoneNumber(auth, phone, v),
        beforeConfirm: () => { S.authHold = true; },
        afterFail: () => { S.authHold = false; },
        done: (cred) => finishPhoneSignIn(cred, close),
      })),
    h('div', { class: 'help-block' },
      h('h4', null, 'Signed up with Google?'),
      h('p', { class: 'muted small' }, 'Google looks after that account. Use Google\'s account recovery (your phone or recovery email), then come back and tap Continue with Google.'),
      h('a', { class: 'btn btn-ghost btn-small', href: 'https://accounts.google.com/signin/recovery', target: '_blank', rel: 'noopener noreferrer' },
        icon('external'), h('span', { class: 'btn-label' }, 'Google account recovery'))),
  ]);
}

// =====================================================================
// Import / export: Google Password Manager CSV
// Google exports `name,url,username,password,note`. Other managers use similar
// headers, so a few common names are accepted too.
// =====================================================================

function parseCSV(text) {
  const rows = [];
  let row = [];
  let field = '';
  let quoted = false;
  text = text.replace(/^﻿/, '');
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"') {
        if (text[i + 1] === '"') { field += '"'; i++; } else quoted = false;
      } else field += c;
    } else if (c === '"') quoted = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\n') { row.push(field); rows.push(row); row = []; field = ''; }
    else if (c !== '\r') field += c;
  }
  if (field !== '' || row.length) { row.push(field); rows.push(row); }
  return rows.filter((r) => r.some((v) => v.trim() !== ''));
}

const csvCell = (v) => (/[",\n\r]/.test(v) || /^\s|\s$/.test(v) ? `"${v.replace(/"/g, '""')}"` : v);

const CSV_COLUMNS = {
  title: ['name', 'title'],
  url: ['url', 'website', 'login_uri', 'login url', 'origin', 'web site'],
  username: ['username', 'login_username', 'login', 'email', 'user', 'user name'],
  password: ['password', 'login_password'],
  note: ['note', 'notes', 'extra', 'comment', 'comments'],
};

function hostOf(url) {
  const m = /^android:\/\/[^@]*@([^/]+)/.exec(url || '');
  if (m) return m[1];
  try { return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(url) ? url : `https://${url}`).hostname.replace(/^www\./, ''); }
  catch { return ''; }
}

function parseLoginsCsv(text) {
  const rows = parseCSV(text);
  if (rows.length < 2) throw new Error('That file has no logins in it.');
  const header = rows[0].map((x) => x.trim().toLowerCase());
  const col = {};
  for (const [k, names] of Object.entries(CSV_COLUMNS)) col[k] = header.findIndex((x) => names.includes(x));
  if (col.password < 0) throw new Error('That doesn\'t look like a password export (no "password" column).');
  const get = (r, k) => (col[k] >= 0 ? (r[col[k]] || '').replace(/\r\n/g, '\n').trim() : '');
  const logins = [];
  let skipped = 0;
  for (const r of rows.slice(1)) {
    const l = { title: get(r, 'title'), url: get(r, 'url'), username: get(r, 'username'), password: get(r, 'password'), note: get(r, 'note') };
    if (!l.password) { skipped++; continue; }
    l.title = l.title || hostOf(l.url) || l.username || 'Imported login';
    logins.push(l);
  }
  return { logins, skipped };
}

/** The parts of a login item that map to Google's CSV columns. */
function loginParts(it) {
  const pw = it.fields.find((f) => f.secret && f.value);
  const site = it.fields.find((f) => f.kind === 'url' && f.value) || it.fields.find((f) => /website|url|site/i.test(f.label) && f.value);
  const plain = it.fields.filter((f) => !f.secret && f.kind !== 'url' && f.value);
  const user = plain.find((f) => /user|email|login|account/i.test(f.label)) || plain[0];
  return { title: it.title, url: site?.value || '', username: user?.value || '', password: pw?.value || '', note: it.notes || '' };
}

const normSite = (u) => (u || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/\/+$/, '');
const dupKey = (l) => `${normSite(l.url)}\u0000${l.username}\u0000${l.password}`;

function loginItem(l, now) {
  return {
    type: 'login',
    title: l.title,
    fields: [
      { label: 'Username / email', value: l.username, secret: false, kind: 'text' },
      { label: 'Password', value: l.password, secret: true, kind: 'text' },
      { label: 'Website', value: l.url, secret: false, kind: 'url' },
    ].filter((f) => f.value),
    photos: [],
    notes: l.note,
    createdAt: now,
    updatedAt: now,
  };
}

function infoSheet(title, message, label = 'Done') {
  return new Promise((resolve) => {
    openSheet((close) => [
      h('h3', { class: 'sheet-title' }, title),
      h('p', { class: 'muted' }, message),
      btn(label, { block: true, onClick: close }),
    ], { onClose: resolve });
  });
}

function pickImportFile() {
  const input = h('input', { type: 'file', accept: '.csv,text/csv', class: 'visually-hidden' });
  input.addEventListener('change', () => {
    const file = input.files[0];
    input.remove();
    if (file) importCsvFile(file);
  });
  input.addEventListener('cancel', () => input.remove());
  document.body.append(input);
  input.click();
}

async function importCsvFile(file) {
  if (file.size > 5 * 1024 * 1024) { toast('That file is too big to be a password export.', 'error'); return; }
  let parsed;
  try {
    parsed = parseLoginsCsv(await file.text());
  } catch (e) {
    toast(e.message, 'error');
    return;
  }
  const have = new Set([...S.items.values()].filter((i) => i.type === 'login').map((i) => dupKey(loginParts(i))));
  const fresh = [];
  let dups = 0;
  for (const l of parsed.logins) {
    const k = dupKey(l);
    if (have.has(k)) { dups++; continue; }
    have.add(k);
    fresh.push(l);
  }
  const notes = [
    dups && `${dups} already in your vault will be skipped.`,
    parsed.skipped && `${parsed.skipped} row${parsed.skipped > 1 ? 's' : ''} without a password will be ignored.`,
  ].filter(Boolean).join(' ');
  if (!fresh.length) {
    await infoSheet('Nothing new to import', `${notes || 'No logins found.'} Delete the CSV file now: it isn't encrypted.`);
    return;
  }
  const ok = await confirmSheet({
    title: `Import ${fresh.length} login${fresh.length > 1 ? 's' : ''}?`,
    message: `From “${file.name}”. ${notes} Each one is encrypted on this device before upload.`,
    confirmLabel: 'Import',
  });
  if (!ok) return;
  if (!onlineOr()) return;
  const key = S.key;
  const done = busy(`Encrypting 0 / ${fresh.length}…`);
  let saved = 0;
  try {
    const now = Date.now();
    for (let i = 0; i < fresh.length; i += 400) {
      const batch = writeBatch(db);
      const staged = [];
      for (const l of fresh.slice(i, i + 400)) {
        const id = newId();
        const rev = newRev();
        const item = loginItem(l, now);
        batch.set(itemRef(id), { ...(await vc.encryptJSON(key, item, aadItem(id))), rev });
        staged.push([id, item, rev]);
        S.mine.add(rev);
      }
      if (S.key !== key) { done(); return; }
      await batch.commit();
      for (const [id, item, rev] of staged) {
        S.server.set(id, normalizeItem({ ...item }, id));
        S.revs.set(id, rev);
      }
      rebuildItems();
      saved += staged.length;
      done(`Encrypting ${saved} / ${fresh.length}…`);
    }
    done();
    render();
    await infoSheet(`Imported ${saved} login${saved > 1 ? 's' : ''}`,
      'Now delete the CSV file you exported from Google (and empty the Bin / Recently Deleted). It holds your passwords unencrypted.');
  } catch (e) {
    done();
    render();
    toast(`${saved ? `Imported ${saved}, then stopped. ` : ''}${dbMessage(e)}`, 'error');
  }
}

function openExportCsv() {
  const logins = liveItems().filter((i) => i.type === 'login').map(loginParts).filter((l) => l.password);
  if (!logins.length) { toast('No logins with a password to export.'); return; }
  const noSite = logins.filter((l) => !l.url).length;
  const pw = pwInput({ autocomplete: 'off', placeholder: 'Master password' });
  const err = h('p', { class: 'form-error', role: 'alert' });
  const submit = btn('Download CSV', { type: 'submit', block: true, icon: 'download' });
  const close = openSheet(() => [
    h('div', { class: 'sheet-handle' }),
    h('h3', { class: 'sheet-title' }, 'Export logins for Google'),
    h('p', { class: 'muted' },
      `This saves ${logins.length} login${logins.length > 1 ? 's' : ''} as a CSV file that Google Password Manager can import. `,
      h('strong', null, 'The file is NOT encrypted.'),
      ' Import it on your own computer, then delete it.'),
    noSite ? h('p', { class: 'muted small' }, `${noSite} of them have no website, and Google may skip those.`) : null,
    h('form', {
      class: 'stack',
      onsubmit: async (e) => {
        e.preventDefault();
        err.textContent = '';
        setBusy(submit, true, 'Checking…');
        try {
          await vc.unlockVault(pw.input.value, S.meta); // confirm it's really you
        } catch (e2) {
          err.textContent = e2 instanceof vc.WrongPasswordError ? 'Wrong master password.' : (e2.message || 'Something went wrong.');
          setBusy(submit, false, 'Download CSV');
          return;
        }
        const lines = ['name,url,username,password,note'];
        for (const l of logins) lines.push([l.title, safeUrl(l.url) || l.url, l.username, l.password, l.note].map(csvCell).join(','));
        const blob = new Blob([`${lines.join('\n')}\n`], { type: 'text/csv;charset=utf-8' });
        await saveBlob(blob, `cybervault-logins-${localDay()}.csv`);
        close();
        toast(android ? 'Choose where to save the CSV, then delete it after importing.' : 'CSV downloaded. Delete it after importing.');
      },
    }, field('Confirm with your master password', pw.wrap), err, submit),
  ]);
  focusSoon(pw.input, 250);
}

// =====================================================================
// Backup and restore
// A backup is one JSON file holding the vault exactly as Firebase stores it: the wrapped key
// and the encrypted items and photos. Nothing in it is readable without the master password
// (or recovery key) the vault had when the backup was made.
// =====================================================================

const BACKUP_FORMAT = 'cybervault-backup';

async function buildBackup() {
  const key = S.key;
  const [items, blobs] = await Promise.all([
    withTimeout(getDocsFromServer(itemsCol()), 60_000),
    withTimeout(getDocsFromServer(blobsCol()), 120_000),
  ]);
  const blobMap = new Map(blobs.docs.map((d) => [d.id, d.data().d]));
  const out = {
    format: BACKUP_FORMAT, version: 1, app: APP_VERSION, createdAt: Date.now(),
    vault: { v: S.meta.v, kdf: S.meta.kdf, wrappedKey: S.meta.wrappedKey, ...(S.meta.recovery ? { recovery: S.meta.recovery } : {}) },
    counts: { items: 0, photos: 0 },
    items: {},
    blobs: {},
  };
  let missing = 0;
  for (const d of items.docs) {
    let it;
    try { it = await vc.decryptJSON(key, d.data(), aadItem(d.id)); } catch { continue; }
    if (it.deletedAt) continue; // Recently deleted items stay out of backups
    const { iv, ct, v } = d.data();
    out.items[d.id] = { v, iv, ct };
    out.counts.items++;
    for (const p of it.photos || []) {
      const parts = Array.from({ length: p.n }, (_, i) => blobMap.get(`${p.id}_${i}`));
      if (parts.some((x) => x === undefined)) { missing++; continue; }
      parts.forEach((x, i) => { out.blobs[`${p.id}_${i}`] = x; });
      out.counts.photos++;
    }
  }
  return { file: out, missing };
}

function openExportBackup() {
  const pw = pwInput({ autocomplete: 'off', placeholder: 'Master password' });
  const err = h('p', { class: 'form-error', role: 'alert' });
  const submit = btn('Download backup', { type: 'submit', block: true, icon: 'download' });
  const waiting = readOutbox().length;
  const close = openSheet(() => [
    h('div', { class: 'sheet-handle' }),
    h('h3', { class: 'sheet-title' }, 'Download a backup'),
    h('p', { class: 'muted' }, `Saves your ${liveItems().length} items and their photos as one encrypted file. To restore it, you'll need your master password as it is now, or your recovery key.`),
    waiting ? h('p', { class: 'muted small' }, `${waiting} change${waiting > 1 ? 's' : ''} made offline will be synced first.`) : null,
    h('form', {
      class: 'stack',
      onsubmit: async (e) => {
        e.preventDefault();
        err.textContent = '';
        if (!onlineOr(err)) return;
        setBusy(submit, true, 'Checking…');
        try {
          await vc.unlockVault(pw.input.value, S.meta); // the password this backup will need
        } catch (e2) {
          err.textContent = e2 instanceof vc.WrongPasswordError ? 'Wrong master password.' : (e2.message || 'Something went wrong.');
          setBusy(submit, false, 'Download backup');
          return;
        }
        setBusy(submit, true, 'Collecting…');
        try {
          await flushOutbox();
          const { file, missing } = await buildBackup();
          const name = `cybervault-backup-${localDay()}.json`;
          await saveBlob(new Blob([JSON.stringify(file)], { type: 'application/json' }), name);
          settings.lastBackupAt = Date.now();
          saveSettings();
          close();
          refreshView();
          const left = readOutbox().length;
          infoSheet(android ? 'Backup ready' : 'Backup downloaded', [
            `${file.counts.items} item${file.counts.items === 1 ? '' : 's'} and ${file.counts.photos} photo${file.counts.photos === 1 ? '' : 's'} ${android ? 'are in' : 'saved in'} “${name}”.`,
            android ? ' Choose where to save it.' : '',
            missing ? ` ${missing} photo${missing > 1 ? 's' : ''} couldn't be found on the server and ${missing > 1 ? 'were' : 'was'} left out.` : '',
            left ? ` ${left} offline change${left > 1 ? 's' : ''} hadn't synced yet and ${left > 1 ? 'aren\'t' : 'isn\'t'} included.` : '',
            ' Move it off this device, e.g. to a USB drive or cloud storage.',
          ].join(''));
        } catch (e2) {
          err.textContent = isOffline(e2) ? 'Couldn\'t reach Firebase. Check your connection and try again.' : (e2.code ? dbMessage(e2) : e2.message);
          setBusy(submit, false, 'Download backup');
        }
      },
    }, field('Confirm with your master password', pw.wrap), err, submit),
  ]);
  focusSoon(pw.input, 250);
}

function pickBackupFile() {
  const input = h('input', { type: 'file', accept: '.json,application/json,.cybervault', class: 'visually-hidden' });
  input.addEventListener('change', () => {
    const file = input.files[0];
    input.remove();
    if (file) openRestoreBackup(file);
  });
  input.addEventListener('cancel', () => input.remove());
  document.body.append(input);
  input.click();
}

async function openRestoreBackup(file) {
  let data;
  try {
    if (file.size > 500 * 1024 * 1024) throw new Error('too big');
    data = JSON.parse(await file.text());
    if (data?.format !== BACKUP_FORMAT || data.version !== 1 || !data.vault?.wrappedKey || typeof data.items !== 'object') throw new Error('format');
  } catch {
    toast('That isn\'t a CyberVault backup file. For a Google CSV, use Import CSV in Settings.', 'error');
    return;
  }
  const n = Object.keys(data.items).length;
  const secret = pwInput({ autocomplete: 'off', placeholder: 'Master password or recovery key' });
  const err = h('p', { class: 'form-error', role: 'alert' });
  const submit = btn('Restore', { type: 'submit', block: true, icon: 'upload' });
  const close = openSheet(() => [
    h('div', { class: 'sheet-handle' }),
    h('h3', { class: 'sheet-title' }, 'Restore a backup'),
    h('div', { class: 'term-lines' },
      h('span', null, file.name),
      h('span', { class: 'ok' }, `made ${fmtDate(data.createdAt || Date.now())} · ${n} item${n === 1 ? '' : 's'} · ${data.counts?.photos ?? '?'} photo${data.counts?.photos === 1 ? '' : 's'}`)),
    h('p', { class: 'muted' }, 'Items already in your vault are skipped, so nothing is overwritten. Restored items are encrypted again with this vault\'s key.'),
    h('form', {
      class: 'stack',
      onsubmit: async (e) => {
        e.preventDefault();
        err.textContent = '';
        if (!onlineOr(err)) return;
        setBusy(submit, true, 'Checking…');
        let bkey;
        try {
          bkey = await vc.unlockBackup(secret.input.value, data.vault);
        } catch (e2) {
          err.textContent = e2 instanceof vc.WrongPasswordError
            ? 'That doesn\'t open this backup. Use the master password from when it was made, or your recovery key.'
            : (e2.message || 'Something went wrong.');
          setBusy(submit, false, 'Restore');
          return;
        }
        close();
        await restoreBackup(data, bkey);
      },
    }, field('Master password or recovery key (from when the backup was made)', secret.wrap), err, submit),
  ]);
  focusSoon(secret.input, 250);
}

async function restoreBackup(data, bkey) {
  const key = S.key;
  const ids = Object.keys(data.items);
  const done = busy(`Restoring 0 / ${ids.length}…`);
  let restored = 0;
  let skipped = 0;
  let photos = 0;
  let lostPhotos = 0;
  let broken = 0;
  try {
    for (const id of ids) {
      if (S.key !== key) return;
      if (S.items.has(id)) { skipped++; continue; }
      let it;
      try { it = await vc.decryptJSON(bkey, data.items[id], aadItem(id)); } catch { broken++; continue; }
      const newPhotos = [];
      for (const p of it.photos || []) {
        try {
          const parts = Array.from({ length: p.n }, (_, i) => data.blobs?.[`${p.id}_${i}`]);
          if (parts.some((x) => typeof x !== 'string')) throw new Error('missing');
          const bytes = await vc.decryptBytes(bkey, vc.b64decode(parts.join('')), aadBlob(p.id));
          newPhotos.push(await uploadPhoto({ blob: new Blob([bytes], { type: p.mime || 'image/jpeg' }), w: p.w, h: p.h, mime: p.mime || 'image/jpeg' }));
          photos++;
        } catch {
          lostPhotos++;
        }
      }
      it.photos = newPhotos;
      delete it.deletedAt;
      try {
        await putItem(id, it, { base: 'none' });
      } catch (e) {
        if (!(e instanceof ConflictError)) throw e;
        await putItem(newId(), it, { base: 'none' });
      }
      restored++;
      done(`Restoring ${restored + skipped + broken} / ${ids.length}…`);
    }
    done();
    render();
    await infoSheet('Backup restored', [
      `Restored ${restored} item${restored === 1 ? '' : 's'} and ${photos} photo${photos === 1 ? '' : 's'}.`,
      skipped ? ` ${skipped} ${skipped === 1 ? 'was' : 'were'} already in your vault.` : '',
      lostPhotos ? ` ${lostPhotos} photo${lostPhotos > 1 ? 's' : ''} in the file couldn't be read.` : '',
      broken ? ` ${broken} item${broken > 1 ? 's' : ''} couldn't be decrypted.` : '',
    ].join(''));
  } catch (e) {
    done();
    render();
    toast(`${restored ? `Restored ${restored}, then stopped. ` : ''}${e?.code ? dbMessage(e) : e.message}`, 'error');
  }
}

// =====================================================================
// Screens: settings
// =====================================================================

function renderSettings() {
  const select = (value, options, onChange, parse = Number) => h('select', {
    class: 'input select', value: String(value),
    onchange: (e) => { onChange(parse(e.target.value)); saveSettings(); toast('Saved'); },
  }, options.map(([v, l]) => h('option', { value: String(v) }, l)));
  const toggle = (key) => h('input', {
    type: 'checkbox', class: 'switch', checked: settings[key], role: 'switch',
    onchange: (e) => { settings[key] = e.target.checked; saveSettings(); toast('Saved'); },
  });
  const row = (label, control, hint) => h('div', { class: 'setting' },
    h('div', { class: 'setting-text' }, h('div', null, label), hint && h('div', { class: 'muted small' }, hint)),
    control);

  const syncEl = h('div', { class: 'card kv-list' });
  const binCount = h('span', { class: 'muted small' });
  function paint() {
    const st = syncState();
    const status = st.offline ? 'Offline' : st.pending || st.busy ? 'Waiting to sync' : 'Up to date';
    syncEl.replaceChildren(
      h('div', { class: 'kv' },
        h('div', { class: 'kv-text' },
          h('div', { class: 'kv-label' }, 'Sync'),
          h('div', { class: `kv-value small-value sync-status${st.offline ? ' off' : ''}` }, status),
          h('div', { class: 'muted small' }, st.pending
            ? `${st.pending} change${st.pending > 1 ? 's' : ''} made on this device ${st.pending > 1 ? 'are' : 'is'} waiting to sync.`
            : 'Changes from your other devices appear here straight away.')),
        h('div', { class: 'kv-actions' }, btn('Sync now', { kind: 'secondary', small: true, icon: 'refresh', onClick: openSyncSheet }))),
      h('div', { class: 'kv' },
        h('div', { class: 'kv-text' },
          h('div', { class: 'kv-label' }, 'Offline access'),
          h('div', { class: 'kv-value small-value' }, 'On'),
          h('div', { class: 'muted small' }, 'An encrypted copy of your vault, photos included, is kept on this device so it works without internet. Changes made offline sync when you\'re back online.'))));
    const n = binItems().length;
    binCount.textContent = n ? `${n} item${n > 1 ? 's' : ''}` : 'Empty';
  }

  const live = liveItems().length;
  screen('settings-screen',
    topbar({ left: iconBtn('back', 'Back', () => back('#/')), title: 'Settings' }),
    h('div', { class: 'content' },
      h('section', { class: 'section' },
        h('h2', { class: 'section-title' }, 'Locking'),
        h('div', { class: 'card' },
          row('Lock when idle', select(settings.autoLockMin,
            [[1, '1 min'], [2, '2 min'], [5, '5 min'], [10, '10 min'], [15, '15 min'], [30, '30 min']],
            (v) => { settings.autoLockMin = v; })),
          row('Lock when I leave the app', select(settings.bgLockSec,
            [[0, 'Immediately'], [30, 'After 30 s'], [60, 'After 1 min'], [300, 'After 5 min'], [-1, 'Never']],
            (v) => { settings.bgLockSec = v; })),
          row('Clear clipboard', select(settings.clearClipSec,
            [[15, 'After 15 s'], [30, 'After 30 s'], [60, 'After 1 min'], [0, 'Never']],
            (v) => { settings.clearClipSec = v; }), 'Works while the app is open'))),
      h('section', { class: 'section' },
        h('h2', { class: 'section-title' }, 'List'),
        h('div', { class: 'card' },
          row('Sort items by', select(settings.sort, Object.entries(SORTS).map(([k, o]) => [k, o.label]), (v) => { settings.sort = v; }, String)),
          row('Pin favourites to the top', toggle('pinFav'), 'Tap the star on an item to make it a favourite.'),
          row('Pin the 3 most recently used', toggle('pinRecent'), 'Remembered on this device only.'))),
      h('section', { class: 'section' },
        h('h2', { class: 'section-title' }, 'Sync & offline'),
        syncEl),
      h('section', { class: 'section' },
        h('h2', { class: 'section-title' }, 'Backup'),
        h('div', { class: 'card pad' },
          h('p', { class: 'muted small' },
            'Save everything (logins, IDs, passport, licence, cards, notes and all photos) as one encrypted file. Keep it somewhere other than this phone or computer, like a USB drive or cloud storage. It opens with your master password or recovery key.'),
          h('p', { class: 'small backup-when' }, settings.lastBackupAt
            ? `Last backup from this device: ${fmtDate(settings.lastBackupAt)}`
            : 'No backup made on this device yet.'),
          h('div', { class: 'btn-row' },
            btn('Download backup', { kind: 'secondary', icon: 'download', onClick: openExportBackup }),
            btn('Restore backup', { kind: 'secondary', icon: 'upload', onClick: pickBackupFile })))),
      h('section', { class: 'section' },
        h('h2', { class: 'section-title' }, 'Recently deleted'),
        h('button', { type: 'button', class: 'card nav-card', onclick: () => go('#/bin') },
          icon('trash'),
          h('span', { class: 'nav-card-text' }, h('span', null, 'Recently deleted'), binCount),
          icon('forward'))),
      h('section', { class: 'section' },
        h('h2', { class: 'section-title' }, 'Master password'),
        h('div', { class: 'card pad' },
          h('p', { class: 'muted small' }, 'Changing it re-encrypts your vault key. Your other devices will need the new password.'),
          btn('Change master password', { kind: 'secondary', icon: 'key', onClick: openChangePassword }))),
      recoverySection(),
      h('section', { class: 'section' },
        h('h2', { class: 'section-title' }, 'Google Password Manager'),
        h('div', { class: 'card pad' },
          h('p', { class: 'muted small' }, 'Move logins to or from Google with a CSV file (logins only, not encrypted). In Chrome: Passwords and autofill → Google Password Manager → Settings → Export / Import passwords. For a full backup, use Backup above.'),
          h('div', { class: 'btn-row' },
            btn('Import CSV', { kind: 'ghost', small: true, icon: 'upload', onClick: pickImportFile }),
            btn('Export CSV', { kind: 'ghost', small: true, icon: 'download', onClick: openExportCsv })))),
      firebaseSection(),
      h('section', { class: 'section' },
        h('h2', { class: 'section-title' }, 'Account'),
        h('div', { class: 'card kv-list' },
          h('div', { class: 'kv' }, h('div', { class: 'kv-text' }, h('div', { class: 'kv-label' }, 'Signed in as'), h('div', { class: 'kv-value' }, S.user.email || '—'))),
          h('div', { class: 'kv' },
            h('div', { class: 'kv-text' }, h('div', { class: 'kv-label' }, 'User ID'), h('div', { class: 'kv-value mono small' }, S.user.uid)),
            h('div', { class: 'kv-actions' }, iconBtn('copy', 'Copy User ID', () => copyText(S.user.uid, 'User ID copied', { sensitive: false }))))),
        null),
      h('section', { class: 'section' },
        h('div', { class: 'stack-sm' },
          btn('Lock now', { kind: 'secondary', icon: 'lock', block: true, onClick: () => lock() }),
          btn('Sign out', { kind: 'danger-ghost', icon: 'logout', block: true, onClick: doSignOut }))),
      aboutSection(live)));
  paint();
  S.repaint = paint;
}

function aboutSection(count) {
  const installed = matchMedia('(display-mode: standalone)').matches || navigator.standalone === true;
  const row = (ic, label, value) => h('div', { class: 'about-row' },
    h('div', { class: 'about-ic' }, icon(ic)),
    h('div', { class: 'about-text' }, h('div', { class: 'about-label' }, label), h('div', { class: 'about-value' }, value)));
  const link = (href, text) => h('a', { href, target: '_blank', rel: 'noopener noreferrer', class: 'about-link' }, text);
  return h('section', { class: 'section about-section' },
    h('h2', { class: 'section-title' }, 'About'),
    h('div', { class: 'about-head' },
      h('img', { class: 'about-logo', src: 'icons/logo.svg', alt: '', width: '60', height: '60' }),
      h('div', null,
        h('div', { class: 'about-name' }, wordmark()),
        h('div', { class: 'muted small' }, `Version ${APP_VERSION} · ${android ? 'Android app' : installed ? 'Home-screen app' : 'Web app'}`))),
    h('div', { class: 'card about-card' },
      row('user', 'Created by', 'Tymon Ng'),
      row('sparkle', 'Built with', 'Claude AI'),
      row('southernCross', 'Made in', 'Proudly made in Australia'),
      row('globe', 'Website', link('https://tymon.website', 'tymon.website')),
      row('code', 'Source code', link('https://github.com/TymonBitesTheDust/CyberVault', 'github.com/TymonBitesTheDust/CyberVault'))),
    h('p', { class: 'muted small about-copy' }, `© ${new Date().getFullYear()} Tymon Ng`),
    h('p', { class: 'muted small about' },
      `${count} item${count === 1 ? '' : 's'} · AES-256-GCM · PBKDF2-SHA256, ${(S.meta?.kdf?.iterations || 0).toLocaleString('en-AU')} rounds. `,
      'Everything is encrypted on this device before upload. Firebase only ever stores scrambled data.'));
}

function firebaseSection() {
  const cfg = activeConfig;
  const locked = rulesText(S.user.uid);
  const parts = [
    h('div', { class: 'card kv-list' },
      h('div', { class: 'kv' },
        h('div', { class: 'kv-text' },
          h('div', { class: 'kv-label' }, 'Project'),
          h('div', { class: 'kv-value mono' }, cfg.projectId),
          h('div', { class: 'muted small' }, configSource === 'file' ? 'Built into the app, so every device is connected' : 'Saved on this device')))),
    h('div', { class: 'card pad' },
      h('p', { class: 'muted small' },
        h('b', null, 'Lock the database to this account. '),
        'Copy these rules, then in the Firebase console open Firestore Database → Rules, replace everything and click Publish. After that no other account can read or write anything, even if someone signs up on your site.'),
      btn('Copy locked rules', { kind: 'secondary', icon: 'lock', onClick: () => copyText(locked, 'Locked rules copied', { sensitive: false }) }),
      h('p', { class: 'muted small' }, 'Deploying with the Firebase CLI? Use firebase deploy --only hosting, or put your User ID in firestore.rules too, so a deploy doesn\'t undo the lock.')),
  ];
  if (configSource === 'device') {
    const link = setupLink(cfg);
    const code = makeSetupCode(cfg);
    parts.push(h('div', { class: 'card pad' },
      h('p', { class: 'muted small' },
        h('b', null, 'Add another device. '),
        'Open this link on your phone or other computer, or paste the setup code into its Connect screen. Then sign in with the same account. It holds your project details, not your passwords.'),
      h('div', { class: 'setup-code mono', 'aria-label': 'Setup code' }, code),
      h('div', { class: 'btn-row' },
        btn('Copy link', { kind: 'secondary', icon: 'copy', onClick: () => copyText(link, 'Setup link copied', { sensitive: false }) }),
        btn('Copy code', { kind: 'ghost', small: true, onClick: () => copyText(code, 'Setup code copied', { sensitive: false }) }),
        navigator.share ? btn('Share', { kind: 'ghost', small: true, icon: 'external', onClick: () => navigator.share({ title: 'CyberVault setup link', url: link }).catch(() => {}) }) : null)),
    h('button', { type: 'button', class: 'link danger-link', onclick: forgetProject }, 'Use a different Firebase project'));
  }
  return h('section', { class: 'section' }, h('h2', { class: 'section-title' }, 'Firebase'), ...parts);
}

function openChangePassword() {
  const cur = pwInput({ placeholder: 'Current master password', autocomplete: 'off' });
  const nw = pwInput({ placeholder: 'At least 10 characters', autocomplete: 'new-password' });
  const nw2 = pwInput({ placeholder: 'Type it again', autocomplete: 'new-password' });
  const meter = strengthMeter();
  nw.input.addEventListener('input', () => meter.update(nw.input.value));
  const err = h('p', { class: 'form-error', role: 'alert' });
  const submit = btn('Change password', { type: 'submit', block: true });
  openSheet((close) => [
    h('div', { class: 'sheet-handle' }),
    h('h3', { class: 'sheet-title' }, 'Change master password'),
    h('form', {
      class: 'stack',
      onsubmit: async (e) => {
        e.preventDefault();
        err.textContent = '';
        const p = nw.input.value;
        if (p.length < 10 || vc.passwordStrength(p).score < 2) { err.textContent = 'Choose a stronger new password (10+ characters).'; return; }
        if (p !== nw2.input.value) { err.textContent = 'The new passwords don\'t match.'; return; }
        if (!onlineOr(err)) return;
        setBusy(submit, true, 'Updating…');
        try {
          const meta = await vc.rewrapVault(cur.input.value, p, S.meta);
          await setDoc(vaultRef(), meta);
          S.meta = meta;
          close();
          toast('Master password changed');
        } catch (e2) {
          err.textContent = e2 instanceof vc.WrongPasswordError ? 'Current master password is wrong.' : dbMessage(e2);
          setBusy(submit, false, 'Change password');
        }
      },
    },
    field('Current master password', cur.wrap),
    field('New master password', nw.wrap),
    meter.el,
    field('Confirm new password', nw2.wrap),
    err,
    submit),
  ]);
  focusSoon(cur.input, 250);
}

// =====================================================================
// Boot
// =====================================================================

function listenAuth() {
  renderLoading('Starting…');
  onAuthStateChanged(auth, (user) => {
    if (S.authHold) return; // a phone sign-in is being checked (see finishPhoneSignIn)
    handleUser(user);
  });
}

async function handleUser(user) {
  if (user && user.uid === S.ignoreUid) return;            // deleted throwaway phone account
  if (user && S.user && user.uid === S.user.uid && S.meta) return;
  if (user && S.loadingUid === user.uid) return;            // already opening this account
  if (!user && !S.user && S.view.includes('signin')) return; // already signed out: keep any open sheet
  lock(false);
  S.user = user;
  S.meta = null;
  if (!user) { renderSignIn(); return; }
  S.loadingUid = user.uid;
  renderLoading('Opening your vault…');
  try {
    const snap = await getDocFast(vaultRef());
    S.meta = snap.exists() ? snap.data() : null;
    if (S.meta) renderUnlock();
    else if (!navigator.onLine && snap.metadata?.fromCache) throw new OfflineError();
    else renderCreateVault();
  } catch (e) {
    renderFatal(e);
  } finally {
    S.loadingUid = null;
  }
}

/**
 * Offline start-up: a service worker keeps a copy of the app's own files, so it opens with no
 * connection. (The vault data itself is kept offline by Firestore.)
 */
function registerOffline() {
  if (!('serviceWorker' in navigator) || !window.isSecureContext) return;
  if (android) {
    // The Android app already has its files on the phone, and its asset loader can't serve a
    // service worker's requests. Make sure none is left over.
    navigator.serviceWorker.getRegistrations().then((rs) => rs.forEach((r) => r.unregister())).catch(() => {});
    return;
  }
  navigator.serviceWorker.register('sw.js', { scope: './' }).then(async () => {
    const reg = await navigator.serviceWorker.ready;
    const urls = new Set([location.href.split('#')[0]]);
    for (const e of performance.getEntriesByType('resource')) {
      try {
        const u = new URL(e.name);
        if (u.origin === location.origin || (u.origin === 'https://www.gstatic.com' && u.pathname.startsWith('/firebasejs/'))) urls.add(u.href);
      } catch { /* ignore */ }
    }
    reg.active?.postMessage({ type: 'cache-urls', urls: [...urls] });
  }).catch(() => { /* no sw.js next to the page: works online only */ });
}

function boot() {
  registerOffline();
  // A setup link from another device: https://…/#connect=CV1-…
  const m = /^#connect=(.+)$/.exec(location.hash);
  const incoming = m ? decodeURIComponent(m[1]) : '';
  if (m) history.replaceState(null, '', location.pathname + location.search);
  if (!activeConfig) {
    renderConnect(incoming, incoming ? 'setup code found in your link: tap connect' : '');
    return;
  }
  if (incoming) {
    try {
      if (parseConfig(incoming).projectId !== activeConfig.projectId) {
        setTimeout(() => toast(`This device is already connected to ${activeConfig.projectId}.`), 800);
      }
    } catch { /* ignore a broken link */ }
  }
  startFirebase(activeConfig);
  listenAuth();
}

boot();
