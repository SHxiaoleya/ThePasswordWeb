const STORAGE_KEY = "pm_secure_v1"; // 加密后的密码库
const SALT_LEN = 16;
const IV_LEN = 12;

// auth
const authCard = document.getElementById("authCard");
const authTitle = document.getElementById("authTitle");
const authTip = document.getElementById("authTip");
const masterPasswordInput = document.getElementById("masterPassword");
const masterPasswordConfirmInput = document.getElementById("masterPasswordConfirm");
const confirmRow = document.getElementById("confirmRow");
const authBtn = document.getElementById("authBtn");

// app
const appArea = document.getElementById("appArea");
const lockBtn = document.getElementById("lockBtn");
const vaultStatus = document.getElementById("vaultStatus");

const form = document.getElementById("passwordForm");
const formTitle = document.getElementById("formTitle");
const editIdInput = document.getElementById("editId");
const nameInput = document.getElementById("name");
const accountInput = document.getElementById("account");
const passwordInput = document.getElementById("password");
const noteInput = document.getElementById("note");
const searchInput = document.getElementById("searchInput");
const listContainer = document.getElementById("listContainer");
const genPasswordBtn = document.getElementById("genPasswordBtn");
const cancelEditBtn = document.getElementById("cancelEditBtn");

let items = [];
let cryptoKey = null;
let vaultSaltBase64 = null;

function toBase64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}
function fromBase64(base64) {
  return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}
function textEncode(str) {
  return new TextEncoder().encode(str);
}
function textDecode(buf) {
  return new TextDecoder().decode(buf);
}
function randomBytes(len) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return arr;
}

async function deriveKey(masterPassword, saltBytes) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    textEncode(masterPassword),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations: 200000,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptJson(obj, key) {
  const iv = randomBytes(IV_LEN);
  const plaintext = textEncode(JSON.stringify(obj));
  const cipher = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    plaintext
  );
  return {
    iv: toBase64(iv),
    data: toBase64(new Uint8Array(cipher)),
  };
}

async function decryptJson(payload, key) {
  const iv = fromBase64(payload.iv);
  const data = fromBase64(payload.data);
  const plainBuf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    data
  );
  return JSON.parse(textDecode(plainBuf));
}

function getVaultRaw() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY));
  } catch {
    return null;
  }
}

function hasVault() {
  return !!getVaultRaw();
}

async function createVault(masterPassword) {
  const salt = randomBytes(SALT_LEN);
  const key = await deriveKey(masterPassword, salt);
  const encrypted = await encryptJson([], key);

  const payload = {
    salt: toBase64(salt),
    iv: encrypted.iv,
    data: encrypted.data,
    updatedAt: Date.now(),
  };

  localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
  cryptoKey = key;
  vaultSaltBase64 = payload.salt;
  items = [];
}

async function unlockVault(masterPassword) {
  const raw = getVaultRaw();
  if (!raw) throw new Error("密码库不存在");

  const salt = fromBase64(raw.salt);
  const key = await deriveKey(masterPassword, salt);

  const list = await decryptJson({ iv: raw.iv, data: raw.data }, key);
  if (!Array.isArray(list)) throw new Error("数据格式错误");

  cryptoKey = key;
  vaultSaltBase64 = raw.salt;
  items = list;
}

async function persistVault() {
  if (!cryptoKey || !vaultSaltBase64) throw new Error("未解锁");
  const encrypted = await encryptJson(items, cryptoKey);

  const payload = {
    salt: vaultSaltBase64,
    iv: encrypted.iv,
    data: encrypted.data,
    updatedAt: Date.now(),
  };
  localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
}

function lockVault() {
  cryptoKey = null;
  items = [];
  vaultSaltBase64 = null;
  form.reset();
  editIdInput.value = "";
  searchInput.value = "";
  listContainer.innerHTML = `<div class="empty">已锁定</div>`;
  appArea.classList.add("hidden");
  authCard.classList.remove("hidden");
  masterPasswordInput.value = "";
  masterPasswordConfirmInput.value = "";
  vaultStatus.textContent = "已锁定";
}

function uid() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

function escapeHtml(str = "") {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function generateStrongPassword(length = 16) {
  const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const lower = "abcdefghijklmnopqrstuvwxyz";
  const digits = "0123456789";
  const symbols = "!@#$%^&*()_+[]{}<>?/|";
  const all = upper + lower + digits + symbols;

  let pwd = [
    upper[Math.floor(Math.random() * upper.length)],
    lower[Math.floor(Math.random() * lower.length)],
    digits[Math.floor(Math.random() * digits.length)],
    symbols[Math.floor(Math.random() * symbols.length)],
  ];

  for (let i = pwd.length; i < length; i++) {
    pwd.push(all[Math.floor(Math.random() * all.length)]);
  }

  for (let i = pwd.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [pwd[i], pwd[j]] = [pwd[j], pwd[i]];
  }
  return pwd.join("");
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    alert("复制成功");
  } catch {
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
    alert("复制成功");
  }
}

function resetForm() {
  form.reset();
  editIdInput.value = "";
  formTitle.textContent = "添加密码";
  cancelEditBtn.classList.add("hidden");
}

function startEdit(id) {
  const item = items.find((x) => x.id === id);
  if (!item) return;

  editIdInput.value = item.id;
  nameInput.value = item.name;
  accountInput.value = item.account;
  passwordInput.value = item.password;
  noteInput.value = item.note || "";

  formTitle.textContent = "编辑密码";
  cancelEditBtn.classList.remove("hidden");
  window.scrollTo({ top: 0, behavior: "smooth" });
}

async function removeItem(id) {
  if (!confirm("确定删除这条记录吗？")) return;
  items = items.filter((x) => x.id !== id);
  await persistVault();
  render();
}

function render() {
  const keyword = searchInput.value.trim().toLowerCase();
  const filtered = items.filter((x) => (
    x.name.toLowerCase().includes(keyword) ||
    x.account.toLowerCase().includes(keyword) ||
    (x.note || "").toLowerCase().includes(keyword)
  ));

  if (filtered.length === 0) {
    listContainer.innerHTML = `<div class="empty">暂无数据</div>`;
    return;
  }

  listContainer.innerHTML = filtered.map(item => {
    const maskedPwd = "•".repeat(Math.max(item.password.length, 8));
    return `
      <div class="item">
        <div class="item-head">
          <div class="item-title">${escapeHtml(item.name)}</div>
          <small class="meta">更新：${new Date(item.updatedAt).toLocaleString()}</small>
        </div>
        <div class="meta"><strong>账号：</strong>${escapeHtml(item.account)}</div>
        <div class="meta"><strong>密码：</strong>${escapeHtml(maskedPwd)}</div>
        <div class="meta"><strong>备注：</strong>${escapeHtml(item.note || "-")}</div>
        <div class="actions">
          <button onclick="copyField('${item.id}','account')">复制账号</button>
          <button onclick="copyField('${item.id}','password')">复制密码</button>
          <button class="secondary" onclick="startEdit('${item.id}')">修改</button>
          <button class="danger" onclick="removeItem('${item.id}')">删除</button>
        </div>
      </div>
    `;
  }).join("");
}

window.copyField = function (id, field) {
  const item = items.find((x) => x.id === id);
  if (!item) return;
  copyText(item[field] || "");
};
window.startEdit = startEdit;
window.removeItem = removeItem;

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const id = editIdInput.value.trim();

  const payload = {
    name: nameInput.value.trim(),
    account: accountInput.value.trim(),
    password: passwordInput.value.trim(),
    note: noteInput.value.trim(),
  };

  if (!payload.name || !payload.account || !payload.password) {
    alert("请填写必填项：名称、账号、密码");
    return;
  }

  if (id) {
    const idx = items.findIndex((x) => x.id === id);
    if (idx !== -1) items[idx] = { ...items[idx], ...payload, updatedAt: Date.now() };
  } else {
    items.unshift({
      id: uid(),
      ...payload,
      createdAt: Date.now(),
      updatedAt: Date.now(),
    });
  }

  await persistVault();
  resetForm();
  render();
});

genPasswordBtn.addEventListener("click", () => {
  passwordInput.value = generateStrongPassword(16);
});

cancelEditBtn.addEventListener("click", resetForm);
searchInput.addEventListener("input", render);

lockBtn.addEventListener("click", lockVault);

authBtn.addEventListener("click", async () => {
  const master = masterPasswordInput.value;
  const confirmPwd = masterPasswordConfirmInput.value;

  if (!master || master.length < 8) {
    alert("主密码至少 8 位");
    return;
  }

  try {
    if (!hasVault()) {
      if (master !== confirmPwd) {
        alert("两次输入的主密码不一致");
        return;
      }
      await createVault(master);
      alert("密码库已创建并解锁");
    } else {
      await unlockVault(master);
      alert("解锁成功");
    }

    authCard.classList.add("hidden");
    appArea.classList.remove("hidden");
    vaultStatus.textContent = "已解锁";
    masterPasswordInput.value = "";
    masterPasswordConfirmInput.value = "";
    render();
  } catch (err) {
    console.error(err);
    alert("解锁失败：主密码错误或数据损坏");
  }
});

// 初始化 auth UI
(function initAuthUI() {
  if (hasVault()) {
    authTitle.textContent = "解锁密码库";
    authTip.textContent = "请输入主密码解锁。";
    confirmRow.classList.add("hidden");
    authBtn.textContent = "解锁";
  } else {
    authTitle.textContent = "首次设置主密码";
    authTip.textContent = "主密码不会保存，请牢记；忘记将无法解密数据。";
    confirmRow.classList.remove("hidden");
    authBtn.textContent = "创建密码库";
  }
})();
