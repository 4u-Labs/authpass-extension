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

async function generateTOTP(secretBase32, period = 30, digits = 6) {
  try {
    const epoch = Math.floor(Date.now() / 1000.0);
    const timeStep = Math.floor(epoch / period);

    const timeBuffer = new ArrayBuffer(8);
    const timeView = new DataView(timeBuffer);
    timeView.setUint32(4, timeStep);

    const secretHex = base32toHex(secretBase32);
    if (!secretHex || secretHex.length < 2) return "000000";

    const secretBytes = new Uint8Array(secretHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const key = await crypto.subtle.importKey(
      "raw", secretBytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]
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
  const encVault = await storage.get(VAULT_STORAGE_KEY);
  if (!encVault) {
    showScreen('screenOnboarding');
  } else {
    showScreen('screenUnlock');
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
    const code = await generateTOTP(acc.secret);
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
        const newCode = await generateTOTP(acc.secret);
        codeEl.textContent = newCode.length === 6 ? `${newCode.slice(0,3)} ${newCode.slice(3)}` : newCode;
      }
    }
  }
}

// Event Listeners on DOM Ready
document.addEventListener('DOMContentLoaded', () => {
  initApp();

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
      img.onload = () => {
        const canvas = document.getElementById('qrCanvas');
        const ctx = canvas.getContext('2d');
        canvas.width = img.width;
        canvas.height = img.height;
        ctx.drawImage(img, 0, 0);
        const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        if (typeof jsQR !== 'undefined') {
          const code = jsQR(imgData.data, imgData.width, imgData.height);
          if (code && code.data && code.data.startsWith('otpauth://totp/')) {
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
