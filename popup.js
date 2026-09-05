// State
let vault = [];
let currentKey = null;
let emergencyKey = null;
let onboardPin = "";
let unlockPin = "";
let totpInterval = null;

const VAULT_STORAGE_KEY = 'authpass_encrypted_vault';
const SALT_STORAGE_KEY = 'authpass_pbkdf2_salt';
const VERIFIER_STORAGE_KEY = 'authpass_pin_verifier';
const EM_HASH_STORAGE_KEY = 'authpass_em_hash';

// Storage Abstraction (chrome.storage.local with localStorage fallback)
const storage = {
  async get(key) {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      return new Promise((resolve) => {
        chrome.storage.local.get([key], (res) => resolve(res[key] || null));
      });
    }
    return localStorage.getItem(key);
  },
  async set(key, value) {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      return new Promise((resolve) => {
        chrome.storage.local.set({ [key]: value }, resolve);
      });
    }
    localStorage.setItem(key, value);
  }
};

function showToast(msg) {
  const t = document.getElementById('toastBox');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2200);
}

// Cryptography Helpers
async function getStoredSalt() {
  let salt = await storage.get(SALT_STORAGE_KEY);
  if (!salt) {
    const raw = crypto.getRandomValues(new Uint8Array(16));
    salt = Array.from(raw).map(b => b.toString(16).padStart(2, '0')).join('');
    await storage.set(SALT_STORAGE_KEY, salt);
  }
  return new Uint8Array(salt.match(/.{1,2}/g).map(b => parseInt(b, 16)));
}

async function deriveKeyFromPin(pin) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(pin), { name: "PBKDF2" }, false, ["deriveKey"]
  );
  const saltBytes = await getStoredSalt();
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations: 100000,
      hash: "SHA-256"
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function sha256(str) {
  const enc = new TextEncoder();
  const buf = await crypto.subtle.digest("SHA-256", enc.encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function encryptData(plainText, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const cipher = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv }, key, enc.encode(plainText)
  );
  const combined = new Uint8Array(iv.length + cipher.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(cipher), iv.length);
  return btoa(String.fromCharCode.apply(null, combined));
}

async function decryptData(cipherBase64, key) {
  const bin = atob(cipherBase64);
  const combined = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) combined[i] = bin.charCodeAt(i);
  const iv = combined.slice(0, 12);
  const cipher = combined.slice(12);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv }, key, cipher
  );
  return new TextDecoder().decode(plain);
}

function generateRandomEmergencyKey() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let parts = [];
  for (let p = 0; p < 4; p++) {
    let seg = "";
    for (let i = 0; i < 4; i++) {
      seg += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    parts.push(seg);
  }
  return "AUTHPASS-" + parts.join("-");
}

// TOTP Engine
function base32toHex(base32) {
  const base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "", hex = "";
  const cleaned = base32.replace(/[\s=-]/g, '').toUpperCase();
  for (let i = 0; i < cleaned.length; i++) {
    const val = base32chars.indexOf(cleaned.charAt(i));
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    hex += parseInt(bits.substring(i, i + 8), 2).toString(16).padStart(2, '0');
  }
  return hex;
}

async function generateTOTP(secretBase32, period = 30, digits = 6, algorithm = "SHA-1") {
  try {
    const epoch = Math.floor(Date.now() / 1000.0);
    const timeStep = Math.floor(epoch / period);

    const timeBuffer = new ArrayBuffer(8);
    const timeView = new DataView(timeBuffer);
    timeView.setUint32(4, timeStep);

    const secretHex = base32toHex(secretBase32);
    if (!secretHex || secretHex.length < 2) return "000000";

    const secretBytes = new Uint8Array(secretHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

    let hashName = "SHA-1";
    const upper = (algorithm || "SHA-1").toUpperCase().replace(/[^A-Z0-9]/g, "");
    if (upper === "SHA256") hashName = "SHA-256";
    else if (upper === "SHA512") hashName = "SHA-512";
    else hashName = "SHA-1";

    const key = await crypto.subtle.importKey(
      "raw", secretBytes, { name: "HMAC", hash: { name: hashName } }, false, ["sign"]
    );
    const signature = await crypto.subtle.sign("HMAC", key, timeBuffer);
    const hash = new Uint8Array(signature);

    const offset = hash[hash.length - 1] & 0xf;
    const binary = ((hash[offset] & 0x7f) << 24) |
                   ((hash[offset + 1] & 0xff) << 16) |
                   ((hash[offset + 2] & 0xff) << 8) |
                   (hash[offset + 3] & 0xff);

    const mod = Math.pow(10, digits);
    const otp = binary % mod;
    return otp.toString().padStart(digits, '0');
  } catch (e) {
    console.error("Erro ao gerar TOTP:", e);
    return "000000";
  }
}

// Screen Management Helper (Guarantees only 1 screen is visible)
function showScreen(screenId) {
  const screens = ['screenOnboarding', 'screenUnlock', 'screenDashboard'];
  screens.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.style.display = (id === screenId) ? 'block' : 'none';
  });

  const isUnlocked = (screenId === 'screenDashboard');
  const btnLock = document.getElementById('btnLockVault');
  const btnAdd = document.getElementById('btnOpenAdd');
  if (btnLock) btnLock.style.display = isUnlocked ? 'flex' : 'none';
  if (btnAdd) btnAdd.style.display = isUnlocked ? 'flex' : 'none';
}

// App LifeCycle
async function initApp() {
  await triggerManualSync(true);

  const encVault = await storage.get(VAULT_STORAGE_KEY);
  if (encVault) {
    showScreen('screenUnlock');
  } else {
    showScreen('screenOnboarding');
  }
}

async function triggerManualSync(silent = false) {
  if (!silent) showToast('Sincronizando com a Nuvem 4U...');
  const activeEmail = (await storage.get('authpass_active_email')) || 'fbr4g4@gmail.com';
  let token = await storage.get('authpass_cloud_token');

  try {
    const url = `https://4u.ia.br/app/authpass/index.php?action=pull&email=${encodeURIComponent(activeEmail)}` + (token ? `&token=${encodeURIComponent(token)}` : '');
    const res = await fetch(url);
    const data = await res.json();
    if (data && data.success) {
      if (data.token && !token) {
        token = data.token;
        await storage.set('authpass_cloud_token', token);
      }
      if (data.vault_data) {
        const vd = data.vault_data;
        if (vd.vault_encrypted) await storage.set(VAULT_STORAGE_KEY, vd.vault_encrypted);
        if (vd.salt) await storage.set(SALT_STORAGE_KEY, vd.salt);
        if (vd.verifier) await storage.set(VERIFIER_STORAGE_KEY, vd.verifier);
        if (vd.em_hash) await storage.set(EM_HASH_STORAGE_KEY, vd.em_hash);

        if (currentKey && vd.vault_encrypted) {
          const json = await decryptData(vd.vault_encrypted, currentKey);
          vault = JSON.parse(json) || [];
          renderAccounts();
        } else {
          showScreen('screenUnlock');
        }

        if (!silent) showToast(`Sincronizado da Nuvem 4U (${activeEmail})!`);
        return;
      }
    }
  } catch (err) {
    console.warn('Sync pull error:', err);
  }
}

// Onboarding Flow
function updateOnboardDots() {
  const dots = document.querySelectorAll('#onboardPinDots .pin-dot');
  dots.forEach((dot, idx) => {
    if (idx < onboardPin.length) dot.classList.add('filled');
    else dot.classList.remove('filled');
  });
}

function handleOnboardKey(num) {
  if (onboardPin.length < 6) {
    onboardPin += num;
    updateOnboardDots();
    if (onboardPin.length === 6) {
      emergencyKey = generateRandomEmergencyKey();
      document.getElementById('emergencyKeyDisplay').textContent = emergencyKey;
      document.getElementById('onboardKeypad').style.display = 'none';
      document.getElementById('stepEmergencyKey').style.display = 'block';
    }
  }
}

// Unlock Flow
function updateUnlockDots() {
  const dots = document.querySelectorAll('#unlockPinDots .pin-dot');
  dots.forEach((dot, idx) => {
    if (idx < unlockPin.length) dot.classList.add('filled');
    else dot.classList.remove('filled');
  });
}

async function handleUnlockKey(num) {
  if (unlockPin.length < 6) {
    unlockPin += num;
    updateUnlockDots();
    if (unlockPin.length === 6) {
      setTimeout(verifyUnlockPin, 50);
    }
  }
}

async function verifyUnlockPin() {
  const pinVerifier = await storage.get(VERIFIER_STORAGE_KEY);
  const enteredHash = await sha256("VERIFY:" + unlockPin);

  if (enteredHash !== pinVerifier) {
    showToast('PIN incorreto!');
    unlockPin = "";
    updateUnlockDots();
    return;
  }

  currentKey = await deriveKeyFromPin(unlockPin);
  const encVault = await storage.get(VAULT_STORAGE_KEY);
  try {
    const json = await decryptData(encVault, currentKey);
    vault = JSON.parse(json) || [];
  } catch (e) {
    vault = [];
  }

  unlockPin = "";
  updateUnlockDots();
  showScreen('screenDashboard');
  renderAccounts();
  startTOTPLoop();

  // Puxa atualizações em background
  triggerManualSync(true);
}

function lockVault() {
  currentKey = null;
  vault = [];
  unlockPin = "";
  updateUnlockDots();
  showScreen('screenUnlock');
}

async function saveVault() {
  if (!currentKey) return;
  const json = JSON.stringify(vault);
  const cipher = await encryptData(json, currentKey);
  await storage.set(VAULT_STORAGE_KEY, cipher);

  // Push para Nuvem 4U (SQLite Zero-Knowledge)
  const salt = await storage.get(SALT_STORAGE_KEY);
  const verifier = await storage.get(VERIFIER_STORAGE_KEY);
  const emHash = await storage.get(EM_HASH_STORAGE_KEY);
  const activeEmail = (await storage.get('authpass_active_email')) || 'fbr4g4@gmail.com';
  const token = await storage.get('authpass_cloud_token');

  const vaultPayload = {
    version: "1.0",
    app: "AuthPass 4U.IA.BR",
    updated_at: new Date().toISOString(),
    vault_encrypted: cipher,
    salt: salt,
    verifier: verifier,
    em_hash: emHash
  };

  try {
    const pushUrl = `https://4u.ia.br/app/authpass/index.php?action=push&email=${encodeURIComponent(activeEmail)}` + (token ? `&token=${encodeURIComponent(token)}` : '');
    await fetch(pushUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ vault_data: vaultPayload, email: activeEmail })
    });
  } catch (e) {
    console.warn('Sync push error:', e);
  }
}

// Render Accounts
async function renderAccounts() {
  const list = document.getElementById('accountsList');
  const empty = document.getElementById('emptyAccounts');
  const filter = (document.getElementById('filterInput').value || '').toLowerCase().trim();

  const filtered = vault.filter(acc => {
    return (acc.issuer || '').toLowerCase().includes(filter) ||
           (acc.label || '').toLowerCase().includes(filter);
  });

  if (filtered.length === 0) {
    list.innerHTML = '';
    empty.style.display = vault.length === 0 ? 'block' : 'none';
    return;
  }
  empty.style.display = 'none';

  let html = '';
  for (const acc of filtered) {
    const code = await generateTOTP(acc.secret, acc.period || 30, acc.digits || 6, acc.algorithm || 'SHA-1');
    const formattedCode = code.length === 6 ? `${code.slice(0,3)} ${code.slice(3)}` : code;
    html += `
      <div class="account-card" data-code="${code}" title="Clique para copiar">
        <div class="account-top">
          <div>
            <div class="account-issuer">${escapeHtml(acc.issuer || '2FA')}</div>
            <div class="account-label">${escapeHtml(acc.label || 'Conta')}</div>
          </div>
          <button class="btn-del-item" data-id="${acc.id}" title="Excluir">✖</button>
        </div>
        <div class="otp-wrapper">
          <div class="otp-code" id="code-${acc.id}">${formattedCode}</div>
          <div class="timer-text" id="sec-${acc.id}">30s</div>
        </div>
      </div>
    `;
  }
  list.innerHTML = html;

  // Add click listeners to cards and delete buttons
  list.querySelectorAll('.account-card').forEach(card => {
    card.addEventListener('click', (e) => {
      if (e.target.classList.contains('btn-del-item')) return;
      const c = card.getAttribute('data-code');
      navigator.clipboard.writeText(c);
      showToast('Código copiado!');
    });
  });

  list.querySelectorAll('.btn-del-item').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const id = parseInt(btn.getAttribute('data-id'));
      if (confirm('Remover esta conta?')) {
        vault = vault.filter(a => a.id !== id);
        await saveVault();
        renderAccounts();
        showToast('Conta removida.');
      }
    });
  });
}

function escapeHtml(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

// TOTP Loop
function startTOTPLoop() {
  if (totpInterval) clearInterval(totpInterval);
  updateTOTP();
  totpInterval = setInterval(updateTOTP, 500);
}

async function updateTOTP() {
  if (!currentKey || vault.length === 0) return;
  const epoch = Math.floor(Date.now() / 1000.0);
  const period = 30;
  const rem = period - (epoch % period);

  for (const acc of vault) {
    const secEl = document.getElementById(`sec-${acc.id}`);
    const codeEl = document.getElementById(`code-${acc.id}`);
    if (secEl) secEl.textContent = `${rem}s`;
    if (codeEl) {
      if (rem <= 5) {
        codeEl.className = 'otp-code danger';
      } else if (rem <= 10) {
        codeEl.className = 'otp-code warn';
      } else {
        codeEl.className = 'otp-code';
      }
      if (rem === period || rem === period - 1) {
        const newCode = await generateTOTP(acc.secret, acc.period || 30, acc.digits || 6, acc.algorithm || 'SHA-1');
        codeEl.textContent = newCode.length === 6 ? `${newCode.slice(0,3)} ${newCode.slice(3)}` : newCode;
      }
    }
  }
}

// Event Listeners on DOM Ready
document.addEventListener('DOMContentLoaded', () => {
  initApp();

  // Settings & Account Modal
  const btnOpenSettings = document.getElementById('btnOpenSettings');
  const btnCloseSettings = document.getElementById('btnCloseSettings');
  const modalSettings = document.getElementById('modalSettings');
  const formSettings = document.getElementById('formSettings');
  const settingsEmailInput = document.getElementById('settingsEmailInput');
  const btnOpenWebApp = document.getElementById('btnOpenWebApp');

  if (btnOpenSettings) {
    btnOpenSettings.addEventListener('click', async () => {
      const email = (await storage.get('authpass_active_email')) || 'fbr4g4@gmail.com';
      if (settingsEmailInput) settingsEmailInput.value = email;
      modalSettings?.classList.add('active');
    });
  }
  if (btnCloseSettings) {
    btnCloseSettings.addEventListener('click', () => {
      modalSettings?.classList.remove('active');
    });
  }
  if (formSettings) {
    formSettings.addEventListener('submit', async (e) => {
      e.preventDefault();
      const newEmail = (settingsEmailInput.value || '').trim().toLowerCase();
      if (!newEmail || !newEmail.includes('@')) {
        showToast('E-mail inválido.');
        return;
      }
      await storage.set('authpass_active_email', newEmail);
      modalSettings?.classList.remove('active');
      showToast('Conta atualizada! Sincronizando...');
      await triggerManualSync(false);
    });
  }
  if (btnOpenWebApp) {
    btnOpenWebApp.addEventListener('click', () => {
      if (typeof chrome !== 'undefined' && chrome.tabs) {
        chrome.tabs.create({ url: "https://4u.ia.br/app/authpass/" });
      } else {
        window.open("https://4u.ia.br/app/authpass/", "_blank");
      }
    });
  }

  // Onboard Keypad
  document.querySelectorAll('#onboardKeypad .keypad-btn[data-val]').forEach(btn => {
    btn.addEventListener('click', () => handleOnboardKey(btn.getAttribute('data-val')));
  });
  document.getElementById('btnOnboardClear').addEventListener('click', () => {
    onboardPin = "";
    updateOnboardDots();
  });
  document.getElementById('btnOnboardBack').addEventListener('click', () => {
    onboardPin = onboardPin.slice(0, -1);
    updateOnboardDots();
  });
  document.getElementById('btnCopyEmergencyKey').addEventListener('click', () => {
    navigator.clipboard.writeText(emergencyKey);
    showToast('Chave de emergência copiada!');
  });
  document.getElementById('chkSavedEmergencyKey').addEventListener('change', (e) => {
    const btn = document.getElementById('btnFinishOnboarding');
    btn.disabled = !e.target.checked;
    btn.style.opacity = e.target.checked ? '1' : '0.5';
  });
  document.getElementById('btnFinishOnboarding').addEventListener('click', async () => {
    currentKey = await deriveKeyFromPin(onboardPin);
    vault = [];
    const pinVerifier = await sha256("VERIFY:" + onboardPin);
    const emHash = await sha256("EMERGENCY:" + emergencyKey);
    await storage.set(VERIFIER_STORAGE_KEY, pinVerifier);
    await storage.set(EM_HASH_STORAGE_KEY, emHash);
    await saveVault();

    showScreen('screenDashboard');
    showToast('Cofre inicializado!');
    renderAccounts();
    startTOTPLoop();
  });

  // Unlock Keypad
  document.querySelectorAll('#unlockKeypad .keypad-btn[data-val]').forEach(btn => {
    btn.addEventListener('click', () => handleUnlockKey(btn.getAttribute('data-val')));
  });
  document.getElementById('btnUnlockClear').addEventListener('click', () => {
    unlockPin = "";
    updateUnlockDots();
  });
  document.getElementById('btnUnlockBack').addEventListener('click', () => {
    unlockPin = unlockPin.slice(0, -1);
    updateUnlockDots();
  });
  document.getElementById('btnSyncCloud')?.addEventListener('click', () => triggerManualSync(false));
  document.getElementById('btnLockVault').addEventListener('click', lockVault);

  // Recovery
  document.getElementById('btnOpenRecovery').addEventListener('click', () => {
    document.getElementById('modalRecovery').classList.add('active');
  });
  document.getElementById('btnCloseRecovery').addEventListener('click', () => {
    document.getElementById('modalRecovery').classList.remove('active');
  });
  document.getElementById('formRecovery').addEventListener('submit', async (e) => {
    e.preventDefault();
    const key = document.getElementById('recoveryKeyInput').value.trim();
    const newPin = document.getElementById('recoveryNewPin').value.trim();

    if (newPin.length !== 6 || !/^\d+$/.test(newPin)) {
      showToast('O novo PIN deve ter 6 dígitos.');
      return;
    }
    const storedEmHash = await storage.get(EM_HASH_STORAGE_KEY);
    const enteredEmHash = await sha256("EMERGENCY:" + key);

    if (enteredEmHash !== storedEmHash) {
      showToast('Chave de emergência inválida!');
      return;
    }

    const pinVerifier = await sha256("VERIFY:" + newPin);
    await storage.set(VERIFIER_STORAGE_KEY, pinVerifier);
    currentKey = await deriveKeyFromPin(newPin);
    await saveVault();

    document.getElementById('modalRecovery').classList.remove('active');
    showScreen('screenDashboard');
    showToast('PIN redefinido com sucesso!');
    renderAccounts();
    startTOTPLoop();
  });

  // Modals & Tabs
  document.getElementById('btnOpenAdd').addEventListener('click', () => {
    document.getElementById('modalAdd').classList.add('active');
  });
  document.getElementById('btnEmptyAdd').addEventListener('click', () => {
    document.getElementById('modalAdd').classList.add('active');
  });
  document.getElementById('btnCloseAdd').addEventListener('click', () => {
    document.getElementById('modalAdd').classList.remove('active');
  });

  document.getElementById('tabBtnManual').addEventListener('click', () => {
    document.getElementById('tabBtnManual').classList.add('active');
    document.getElementById('tabBtnUpload').classList.remove('active');
    document.getElementById('tabContentManual').style.display = 'block';
    document.getElementById('tabContentUpload').style.display = 'none';
  });

  document.getElementById('tabBtnUpload').addEventListener('click', () => {
    document.getElementById('tabBtnUpload').classList.add('active');
    document.getElementById('tabBtnManual').classList.remove('active');
    document.getElementById('tabContentUpload').style.display = 'block';
    document.getElementById('tabContentManual').style.display = 'none';
  });

  // Manual Add Form
  document.getElementById('formManualAdd').addEventListener('submit', async (e) => {
    e.preventDefault();
    const issuer = document.getElementById('inputIssuer').value.trim();
    const label = document.getElementById('inputLabel').value.trim();
    const secret = document.getElementById('inputSecret').value.trim().toUpperCase().replace(/[\s-]/g, '');

    if (!secret || secret.length < 4) {
      showToast('Chave secreta inválida.');
      return;
    }

    vault.push({
      id: Date.now(),
      issuer: issuer || '2FA',
      label: label || 'Conta',
      secret: secret
    });
    await saveVault();

    document.getElementById('modalAdd').classList.remove('active');
    renderAccounts();
    showToast('Conta 2FA adicionada!');

    document.getElementById('inputIssuer').value = '';
    document.getElementById('inputLabel').value = '';
    document.getElementById('inputSecret').value = '';
  });

  function bytesToBase32(bytes) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = 0;
    let value = 0;
    let output = '';
    for (let i = 0; i < bytes.length; i++) {
      value = (value << 8) | bytes[i];
      bits += 8;
      while (bits >= 5) {
        output += alphabet[(value >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }
    if (bits > 0) {
      output += alphabet[(value << (5 - bits)) & 31];
    }
    return output;
  }

  function decodeGoogleMigrationUri(uri) {
    try {
      const url = new URL(uri);
      if (!uri.startsWith('otpauth-migration:')) return null;
      const dataParam = url.searchParams.get('data');
      if (!dataParam) return null;

      let base64 = decodeURIComponent(dataParam).replace(/-/g, '+').replace(/_/g, '/');
      while (base64.length % 4) {
        base64 += '=';
      }
      const binaryStr = atob(base64);
      const bytes = new Uint8Array(binaryStr.length);
      for (let i = 0; i < binaryStr.length; i++) {
        bytes[i] = binaryStr.charCodeAt(i);
      }

      let pos = 0;
      function readVarint() {
        let res = 0;
        let shift = 0;
        while (pos < bytes.length) {
          const b = bytes[pos++];
          res |= (b & 0x7f) << shift;
          if ((b & 0x80) === 0) break;
          shift += 7;
          if (shift > 35) break;
        }
        return res;
      }

      const accounts = [];

      while (pos < bytes.length) {
        const tag = readVarint();
        const fieldNumber = tag >>> 3;
        const wireType = tag & 0x07;

        if (wireType === 2) {
          const len = readVarint();
          const endPos = Math.min(pos + len, bytes.length);
          if (fieldNumber === 1) { // otp_parameters
            let secret = null;
            let name = '';
            let issuer = '';
            let digits = 6;
            let algorithm = 'SHA-1';

            while (pos < endPos) {
              const innerTag = readVarint();
              const innerFieldNumber = innerTag >>> 3;
              const innerWireType = innerTag & 0x07;

              if (innerWireType === 2) {
                const innerLen = readVarint();
                const subBytes = bytes.slice(pos, pos + innerLen);
                pos += innerLen;
                if (innerFieldNumber === 1) {
                  secret = bytesToBase32(subBytes);
                } else if (innerFieldNumber === 2) {
                  name = new TextDecoder().decode(subBytes);
                } else if (innerFieldNumber === 3) {
                  issuer = new TextDecoder().decode(subBytes);
                }
              } else if (innerWireType === 0) {
                const val = readVarint();
                if (innerFieldNumber === 4) {
                  if (val === 2) algorithm = 'SHA-256';
                  else if (val === 3) algorithm = 'SHA-512';
                  else algorithm = 'SHA-1';
                } else if (innerFieldNumber === 5) {
                  if (val === 2) digits = 8;
                  else digits = 6;
                }
              } else if (innerWireType === 1) {
                pos += 8;
              } else if (innerWireType === 5) {
                pos += 4;
              } else {
                pos = endPos;
                break;
              }
            }

            if (secret) {
              let label = name;
              if (name.includes(':')) {
                const parts = name.split(':');
                if (!issuer) issuer = parts[0].trim();
                label = parts.slice(1).join(':').trim();
              }
              accounts.push({
                id: Date.now() + Math.floor(Math.random() * 100000),
                issuer: issuer || '2FA',
                label: label || name || 'Conta',
                secret: secret,
                digits: digits,
                period: 30,
                algorithm: algorithm
              });
            }
          } else {
            pos = endPos;
          }
        } else if (wireType === 0) {
          readVarint();
        } else if (wireType === 1) {
          pos += 8;
        } else if (wireType === 5) {
          pos += 4;
        } else {
          break;
        }
      }

      return accounts;
    } catch (err) {
      console.error('Erro ao decodificar migração Google Auth:', err);
      return null;
    }
  }

  // File Upload QR Code Scanner
  document.getElementById('dropZoneQr').addEventListener('click', () => {
    document.getElementById('fileQrInput').click();
  });

  document.getElementById('fileQrInput').addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      const img = new Image();
      img.onload = async () => {
        const canvas = document.getElementById('qrCanvas');
        const ctx = canvas.getContext('2d', { willReadFrequently: true });
        canvas.width = img.width;
        canvas.height = img.height;
        ctx.drawImage(img, 0, 0);
        const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        if (typeof jsQR !== 'undefined') {
          let code = jsQR(imgData.data, imgData.width, imgData.height, { inversionAttempts: 'attemptBoth' });
          if (!code && (img.width > 1200 || img.height > 1200)) {
            const scale = 1000 / Math.max(img.width, img.height);
            const sw = Math.floor(img.width * scale);
            const sh = Math.floor(img.height * scale);
            canvas.width = sw;
            canvas.height = sh;
            ctx.drawImage(img, 0, 0, sw, sh);
            const scaledData = ctx.getImageData(0, 0, sw, sh);
            code = jsQR(scaledData.data, scaledData.width, scaledData.height, { inversionAttempts: 'attemptBoth' });
          }

          if (code && code.data) {
            if (code.data.startsWith('otpauth-migration://')) {
              const imported = decodeGoogleMigrationUri(code.data);
              if (imported && imported.length > 0) {
                let addedCount = 0;
                imported.forEach(acc => {
                  const exists = vault.some(v => v.secret.replace(/\s+/g, '') === acc.secret.replace(/\s+/g, ''));
                  if (!exists) {
                    vault.push(acc);
                    addedCount++;
                  }
                });
                if (addedCount > 0) {
                  await saveVault();
                  document.getElementById('modalAdd').classList.remove('active');
                  renderAccounts();
                  showToast(`${addedCount} conta(s) importada(s) do Google Authenticator!`);
                } else {
                  document.getElementById('modalAdd').classList.remove('active');
                  showToast('Todas as contas do Google Authenticator já existem no seu cofre.');
                }
              } else {
                showToast('Nenhuma conta encontrada no QR de migração.');
              }
            } else if (code.data.startsWith('otpauth://totp/')) {
              const url = new URL(code.data);
              const labelPart = decodeURIComponent(url.pathname.replace('//totp/', ''));
              let issuer = url.searchParams.get('issuer') || '';
              let account = labelPart;
              if (labelPart.includes(':')) {
                const parts = labelPart.split(':');
                if (!issuer) issuer = parts[0].trim();
                account = parts[1].trim();
              }
              document.getElementById('inputIssuer').value = issuer || '2FA';
              document.getElementById('inputLabel').value = account;
              document.getElementById('inputSecret').value = url.searchParams.get('secret') || '';
              document.getElementById('tabBtnManual').click();
              showToast('QR Code lido! Clique em Salvar.');
            } else {
              showToast('QR Code não é um token 2FA compatível.');
            }
          } else {
            showToast('Nenhum QR Code 2FA válido encontrado.');
          }
        }
      };
      img.src = event.target.result;
    };
    reader.readAsDataURL(file);
  });

  document.getElementById('filterInput').addEventListener('input', renderAccounts);
});
