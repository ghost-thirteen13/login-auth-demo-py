'use strict';

// ===== 状态管理 =====
const state = {
  token: localStorage.getItem('token') || null,
  user: null,
  // 能力集合由服务端下发（server/permissions.js 推导），前端只据此做界面管控；
  // 即使被篡改也无法越权 —— 每个写操作后端都会重新校验。
  caps: {},
  // 管理操作结果提示（面板重绘后展示一次）
  adminNotice: null,
};

// ===== DOM =====
const $ = (id) => document.getElementById(id);

// [安全 F-2] 所有动态内容转义后再插入 innerHTML，防止存储型 XSS
// （LLM 输出的 reason、用户名等均按不可信数据处理）
function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ===== 前端即时校验（敏感词与 server/moderation.js RULE_BLOCKLIST 保持一致，同源单一来源） =====

// 与 server/moderation.js RULE_BLOCKLIST 保持一致
const NICKNAME_SENSITIVE_WORDS = [
  // 辱骂
  '傻逼', '煞笔', '沙比', '妈的', '他妈', '草泥马', 'fuck', 'shit', 'bitch',
  // 违法引流
  '赌博', '博彩', '代开发票', '办证', '枪支', '毒品', '冰毒', '洗钱',
  // 色情
  '色情', '约炮', '援交', '一夜情服务',
];

// 全/半角归一化 + 剥离分隔符变体（复用 server/moderation.js 的归一化思路）
function normSensitive(s) {
  return String(s)
    .replace(/[\u3000]/g, ' ')
    .replace(/[\uFF01-\uFF5E]/g, (ch) => String.fromCharCode(ch.charCodeAt(0) - 0xFEE0))
    .toLowerCase()
    .replace(/[\s_\-.*·•|/\\]+/g, '');
}

function validateUsernameLive(v) {
  const t = (v || '').trim();
  if (!/^[a-zA-Z0-9_]+$/.test(t)) return '用户名只能包含字母、数字和下划线';
  if (t.length < 3) return '用户名长度至少为 3 个字符';
  if (t.length > 20) return '用户名长度不能超过 20 个字符';
  return null;
}

function validateNicknameLive(v) {
  const t = (v || '').trim();
  if (!t) return '昵称不能为空'; // 必填校验（与后端一致）
  if (t.length > 20) return '昵称长度不能超过 20 个字符';
  const n = normSensitive(t);
  for (const w of NICKNAME_SENSITIVE_WORDS) {
    const nw = normSensitive(w);
    if (nw && n.includes(nw)) return '昵称包含敏感词，请更换';
  }
  return null;
}

// ===== API =====
async function api(path, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  const resp = await fetch(path, { ...options, headers });
  const data = await resp.json().catch(() => ({}));
  return { ok: resp.ok, status: resp.status, data };
}

// ===== 主题切换（明暗，持久化） =====
(function bindTheme() {
  const btn = $('btn-theme');
  const icon = btn && btn.querySelector('.theme-icon');
  function syncIcon() {
    const t = document.documentElement.getAttribute('data-theme');
    if (icon) icon.textContent = t === 'dark' ? '☀️' : '🌙';
  }
  if (btn) {
    btn.addEventListener('click', () => {
      const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      try { localStorage.setItem('theme', next); } catch (e) {}
      syncIcon();
    });
  }
  syncIcon();
})();

// ===== 按钮加载态（保留用户输入，仅展示 spinner） =====
async function withLoading(btn, fn) {
  if (!btn) { await fn(); return; }
  const original = btn.innerHTML;
  btn.disabled = true;
  btn.classList.add('is-loading');
  btn.innerHTML = '<span class="spinner" aria-hidden="true"></span><span>处理中…</span>';
  try {
    await fn();
  } finally {
    btn.disabled = false;
    btn.classList.remove('is-loading');
    btn.innerHTML = original;
  }
}

// ===== 浮层 Toast（独立于面板重绘，确保每次操作都有明确反馈） =====
let toastRoot = null;
function ensureToastRoot() {
  if (!toastRoot) {
    toastRoot = document.createElement('div');
    toastRoot.id = 'toast-root';
    toastRoot.className = 'toast-root';
    toastRoot.setAttribute('aria-live', 'polite');
    document.body.appendChild(toastRoot);
  }
  return toastRoot;
}
function dismissToast(el) {
  if (!el || el._dismissed) return;
  el._dismissed = true;
  clearTimeout(el._timer);
  el.classList.remove('show');
  setTimeout(() => el.remove(), 350);
}
function showToast(type, text, timeout = 4500) {
  const root = ensureToastRoot();
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  el.setAttribute('role', type === 'error' ? 'alert' : 'status');
  el.textContent = text;
  el.title = '点击关闭';
  el.addEventListener('click', () => dismissToast(el));
  root.appendChild(el);
  requestAnimationFrame(() => el.classList.add('show'));
  el._timer = setTimeout(() => dismissToast(el), timeout);
  return el;
}

// ===== 自定义模态确认框（替代原生 confirm，避免沙箱/预览环境禁用 confirm 导致操作静默取消） =====
function confirmModal({ title = '请确认', message = '', confirmText = '确认', cancelText = '取消', danger = false } = {}) {
  return new Promise((resolve) => {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';

    const modal = document.createElement('div');
    modal.className = 'modal' + (danger ? ' modal-danger' : '');
    modal.setAttribute('role', 'dialog');
    modal.setAttribute('aria-modal', 'true');

    const t = document.createElement('div');
    t.className = 'modal-title';
    t.textContent = title;

    const b = document.createElement('div');
    b.className = 'modal-body';
    b.textContent = message;

    const actions = document.createElement('div');
    actions.className = 'modal-actions';

    const btnCancel = document.createElement('button');
    btnCancel.type = 'button';
    btnCancel.className = 'btn btn-ghost';
    btnCancel.dataset.act = 'cancel';
    btnCancel.textContent = cancelText;

    const btnOk = document.createElement('button');
    btnOk.type = 'button';
    btnOk.className = 'btn ' + (danger ? 'btn-danger' : 'btn-primary');
    btnOk.dataset.act = 'ok';
    btnOk.textContent = confirmText;

    actions.append(btnCancel, btnOk);
    modal.append(t, b, actions);
    overlay.append(modal);
    document.body.append(overlay);

    let done = false;
    const close = (result) => {
      if (done) return;
      done = true;
      document.removeEventListener('keydown', onKey, true);
      overlay.remove();
      resolve(result);
    };
    // 仅支持 ESC 取消；破坏性操作不绑定 Enter 确认，强制显式点击，避免误触
    const onKey = (e) => {
      if (e.key === 'Escape') { e.preventDefault(); close(false); }
    };
    document.addEventListener('keydown', onKey, true);
    overlay.addEventListener('click', (e) => { if (e.target === overlay) close(false); });
    btnOk.addEventListener('click', () => close(true));
    btnCancel.addEventListener('click', () => close(false));

    // 默认聚焦「取消」，进一步降低误删/误封风险
    btnCancel.focus();
  });
}

// ===== 页面切换 =====
function showPage(id) {
  document.querySelectorAll('.page').forEach((p) => p.classList.add('hidden'));
  $(id).classList.remove('hidden');
}

function showAuthMsg(text, type = 'error') {
  const el = $('auth-msg');
  el.textContent = text;
  el.className = `msg ${type}`;
}

// ===== 登录/注册切换 =====
document.querySelectorAll('.tab').forEach((tab) => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach((t) => t.classList.remove('active'));
    tab.classList.add('active');
    $('form-login').classList.toggle('hidden', tab.dataset.tab !== 'login');
    $('form-register').classList.toggle('hidden', tab.dataset.tab !== 'register');
    showAuthMsg('');
  });
});

// ===== 登录 =====
$('form-login').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = $('form-login').querySelector('.btn-primary');
  await withLoading(btn, async () => {
    showAuthMsg('登录中…', 'success');
    const { ok, data } = await api('/api/login', {
      method: 'POST',
      body: JSON.stringify({
        username: $('login-username').value.trim(),
        password: $('login-password').value,
      }),
    });
    if (!ok) {
      showAuthMsg(data.error || '登录失败');
      return;
    }
    state.token = data.token;
    state.user = data.user;
    localStorage.setItem('token', state.token);
    enterDashboard();
  });
});

// ===== 注册 =====
$('form-register').addEventListener('submit', async (e) => {
  e.preventDefault();

  // 前端即时校验（最终以服务端为准）
  const usernameRaw = $('reg-username').value;
  const usernameErr = validateUsernameLive(usernameRaw);
  if (usernameErr) {
    showAuthMsg(usernameErr);
    return;
  }
  const nicknameRaw = $('reg-nickname').value;
  const nicknameErr = validateNicknameLive(nicknameRaw);
  if (nicknameErr) {
    showAuthMsg(nicknameErr);
    return;
  }

  const btn = $('form-register').querySelector('.btn-primary');
  await withLoading(btn, async () => {
    showAuthMsg('注册中（LLM 审核用户名与昵称）…', 'success');
    const { ok, data } = await api('/api/register', {
      method: 'POST',
      body: JSON.stringify({
        username: usernameRaw.trim(),
        password: $('reg-password').value,
        nickname: nicknameRaw.trim() || undefined, // 空则省略，服务端子段按可选处理
      }),
    });
    if (!ok) {
      const reason = data.error || '注册失败';
      const detail = data.category ? `（${data.category}）` : '';
      showAuthMsg(`${reason}${detail}`);
      return;
    }
    const m = data.moderation;
    showAuthMsg(`注册成功！${m ? m.reason : ''}。请使用该账号登录。`, 'success');
    // 自动切到登录 tab
    document.querySelector('.tab[data-tab="login"]').click();
    $('login-username').value = $('reg-username').value.trim();
    $('reg-username').value = '';
    $('reg-password').value = '';
    $('reg-nickname').value = '';
    $('reg-username-err').textContent = '';
    $('reg-nickname-err').textContent = '';
  });
});

// 注册表单即时校验（input/blur 事件，写入对应错误位）
(function bindLiveValidation() {
  const u = $('reg-username');
  const n = $('reg-nickname');
  if (u) {
    const handler = () => { $('reg-username-err').textContent = validateUsernameLive(u.value) || ''; };
    u.addEventListener('input', handler);
    u.addEventListener('blur', handler);
  }
  if (n) {
    const handler = () => { $('reg-nickname-err').textContent = validateNicknameLive(n.value) || ''; };
    n.addEventListener('input', handler);
    n.addEventListener('blur', handler);
  }
})();

// ===== 退出 =====
$('btn-logout').addEventListener('click', () => {
  state.token = null;
  state.user = null;
  localStorage.removeItem('token');
  showPage('page-auth');
  $('nav-user').classList.add('hidden');
});

// ===== 进入面板 =====
async function enterDashboard() {
  // 拉取用户信息（含 role / pendingReview）
  const { ok, data } = await api('/api/me');
  if (!ok) {
    // token 失效
    state.token = null;
    localStorage.removeItem('token');
    showPage('page-auth');
    return;
  }
  state.user = data.user;

  // 导航栏用户徽章（双行：昵称优先，无昵称回退显示用户名粗体）
  $('nav-user').classList.remove('hidden');
  const badge = $('user-badge');
  const line1 = $('badge-nickname');
  const line2 = $('badge-username');
  const hasNick = state.user.nickname && state.user.nickname.trim();
  if (hasNick) {
    line1.textContent = esc(state.user.nickname);
    line2.textContent = esc(state.user.username);
    line2.style.display = '';
  } else {
    line1.textContent = esc(state.user.username);
    line2.style.display = 'none';
  }
  badge.className = state.user.role === 'admin' ? 'user-badge role-admin' : 'user-badge';

  // 资源 B 按钮：依据服务端下发的能力控制（体验层置灰，真实拦截在后端）
  state.caps = state.user.capabilities || {};
  const btnB = $('btn-resource-b');
  btnB.disabled = !state.caps.viewResourceB;
  if (state.caps.manageUsers) {
    btnB.textContent = '资源 B · 管理面板';
    btnB.title = '管理面板：完全控制（可调整访问权限、封禁、删除用户）';
  } else if (state.caps.viewResourceB) {
    btnB.textContent = '资源 B · 管理面板（只读）';
    btnB.title = '管理面板：已获授权，仅可查看，禁止任何修改操作';
  } else {
    btnB.textContent = '资源 B · 管理面板';
    btnB.title = '权限不足：需要 admin 角色，或由管理员授予查看权限';
  }

  showPage('page-dashboard');
  // 默认加载资源 A
  loadResourceA();
}

// ===== 资源 A =====
$('btn-resource-a').addEventListener('click', loadResourceA);

async function loadResourceA() {
  const btn = $('btn-resource-a');
  await withLoading(btn, async () => {
    const el = $('resource-content');
    el.innerHTML = skeleton(3);
    const { ok, data } = await api('/api/resource/a');
    if (!ok) {
      el.innerHTML = `<div class="forbidden-note"><div class="icon">⛔</div><p>${esc(data.error) || '访问失败'}</p></div>`;
      return;
    }
    el.innerHTML = `
      <h2>${esc(data.name)}</h2>
      <p class="hint" style="color:var(--text-muted);margin:8px 0 20px;">当前用户：${esc(data.viewer)}</p>
      ${data.announcements.map((a) => `
        <div class="announcement">
          <h3>${esc(a.title)}</h3>
          <div class="meta">${esc(a.author)} · ${esc(a.time)}</div>
          <div class="body">${esc(a.body)}</div>
        </div>
      `).join('')}
    `;
  });
}

// ===== 资源 B =====
$('btn-resource-b').addEventListener('click', loadResourceB);

async function loadResourceB() {
  const btn = $('btn-resource-b');
  await withLoading(btn, async () => {
    const el = $('resource-content');
    el.innerHTML = skeleton(3);
    const { ok, status, data } = await api('/api/resource/b');
    if (status === 403) {
      el.innerHTML = `<div class="forbidden-note"><div class="icon">🔒</div><h3>权限不足</h3><p>${esc(data.error)}</p><p style="margin-top:12px;font-size:13px;color:var(--text-muted)">资源 B 需要 admin 角色，或由管理员授予查看权限；服务端已拦截此请求。</p></div>`;
      return;
    }
    if (!ok) {
      el.innerHTML = `<div class="forbidden-note"><div class="icon">⚠</div><p>${esc(data.error) || '访问失败'}</p></div>`;
      return;
    }

    const m = data.metrics;
    const access = data.access || {};
    // 以服务端返回的能力为准（而非本地缓存），避免撤销授权后界面仍显示操作按钮
    const caps = access.capabilities || {};
    const canManage = caps.manageUsers === true;
    state.caps = caps;

    // 管理操作结果提示：渲染一次后清空
    const notice = state.adminNotice;
    state.adminNotice = null;

    el.innerHTML = `
      <h2>${esc(data.name)}</h2>
      <p class="hint" style="margin:8px 0 16px;">
        当前用户：${esc(data.viewer)}
        ${canManage
          ? '<span class="tag tag-admin">完全控制</span>'
          : '<span class="tag tag-readonly">只读</span>'}
      </p>
      ${notice ? `<div class="msg ${notice.type === 'error' ? 'error' : 'success'}">${esc(notice.text)}</div>` : ''}
      ${canManage
        ? `<div class="access-banner is-admin">
             <span class="icon" aria-hidden="true">🛡️</span>
             <div><strong>管理员模式</strong><br>可调整用户对资源 B 的访问权限，并执行封禁 / 删除操作。该权限仅 admin 角色持有。</div>
           </div>`
        : `<div class="access-banner is-readonly">
             <span class="icon" aria-hidden="true">👁️</span>
             <div><strong>只读模式</strong><br>你已被管理员授权查看本面板，但无权执行任何修改、删除或权限调整操作。所有写操作都会被服务端拒绝。</div>
           </div>`}
      <div class="metrics">
        <div class="metric-box"><div class="num">${Number(m.totalUsers)}</div><div class="label">总用户数</div></div>
        <div class="metric-box"><div class="num">${Number(m.adminCount)}</div><div class="label">管理员数</div></div>
        <div class="metric-box"><div class="num">${Number(m.grantedCount || 0)}</div><div class="label">已授权只读</div></div>
        <div class="metric-box"><div class="num">${Number(m.bannedCount || 0)}</div><div class="label">已封禁</div></div>
        <div class="metric-box"><div class="num">${Number(m.pendingReviewCount)}</div><div class="label">待复审</div></div>
      </div>

      <h3>用户与权限管理</h3>
      ${renderUserTable(data.users || [], canManage)}

      <h3>待复审用户</h3>
      ${data.pendingReview.length === 0
        ? '<p class="hint">暂无待复审用户</p>'
        : data.pendingReview.map((u) => `<div class="pending-item"><span>${esc(u.username)}</span><span style="color:var(--text-muted)">${esc(u.moderation?.reason) || '—'}</span></div>`).join('')}

      <h3>系统日志</h3>
      ${data.systemLog.map((l) => `<div class="pending-item"><span>${esc(l.event)}</span><span style="color:var(--text-muted)">${esc(l.time)}</span></div>`).join('')}
    `;
  });
}

/**
 * 渲染用户清单。
 * canManage=false 时（只读用户）完全不输出任何操作控件 —— 不是置灰，而是根本不渲染。
 */
function renderUserTable(users, canManage) {
  if (!users.length) return '<p class="hint">暂无用户</p>';
  const rows = users.map((u) => {
    const isAdminRow = u.role === 'admin';
    const isSelf = state.user && u.id === state.user.id;
    const display = u.nickname ? `${esc(u.nickname)} <span class="u-sub">${esc(u.username)}</span>` : esc(u.username);
    const roleTag = isAdminRow
      ? '<span class="tag tag-admin">admin</span>'
      : '<span class="tag tag-user">user</span>';
    const accessTag = isAdminRow
      ? '<span class="tag tag-granted">完全控制</span>'
      : (u.resourceBAccess
        ? '<span class="tag tag-granted">已授权（只读）</span>'
        : '<span class="tag tag-none">未授权</span>');
    const statusTag = u.banned
      ? '<span class="tag tag-banned">已封禁</span>'
      : '<span class="tag tag-ok">正常</span>';

    let actions;
    if (!canManage) {
      // 只读用户：无任何操作入口
      actions = '<span class="hint inline">—</span>';
    } else if (isAdminRow || isSelf) {
      // admin 账号受保护：既不能被降权，也不能被封禁/删除
      actions = '<span class="hint inline">受保护</span>';
    } else {
      const nameAttr = esc(u.nickname || u.username);
      actions = `
        <div class="row-actions">
          <button class="btn btn-xs" data-act="access" data-id="${esc(u.id)}" data-val="${u.resourceBAccess ? 'false' : 'true'}" data-name="${nameAttr}">
            ${u.resourceBAccess ? '撤销访问' : '授权访问'}
          </button>
          <button class="btn btn-xs btn-warn" data-act="ban" data-id="${esc(u.id)}" data-val="${u.banned ? 'false' : 'true'}" data-name="${nameAttr}">
            ${u.banned ? '解封' : '封禁'}
          </button>
          <button class="btn btn-xs btn-danger" data-act="delete" data-id="${esc(u.id)}" data-name="${nameAttr}">删除</button>
        </div>`;
    }

    return `<tr class="${u.banned ? 'is-banned' : ''}">
      <td>${display}</td>
      <td>${roleTag}</td>
      <td>${accessTag}</td>
      <td>${statusTag}</td>
      <td>${actions}</td>
    </tr>`;
  }).join('');

  return `<div class="table-wrap">
    <table class="user-table">
      <thead><tr><th>用户</th><th>角色</th><th>资源 B 访问</th><th>状态</th><th>操作</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

// 管理操作：事件委托（面板每次重绘都会替换 innerHTML，故绑定在稳定的父容器上）
$('resource-content').addEventListener('click', async (e) => {
  const btn = e.target.closest('[data-act]');
  if (!btn) return;
  await handleAdminAction(btn);
});

async function handleAdminAction(btn) {
  const act = btn.dataset.act;
  const id = btn.dataset.id;
  const name = btn.dataset.name || '该用户';
  const val = btn.dataset.val === 'true';

  // 破坏性操作二次确认（自定义模态，不依赖被沙箱禁用的原生 confirm）
  if (act === 'delete') {
    const ok = await confirmModal({
      title: '删除用户',
      message: `确认删除用户「${name}」？该操作不可恢复。`,
      confirmText: '删除',
      danger: true,
    });
    if (!ok) return;
  }
  if (act === 'ban' && val) {
    const ok = await confirmModal({
      title: '封禁用户',
      message: `确认封禁用户「${name}」？其已登录的会话将立即失效。`,
      confirmText: '封禁',
      danger: true,
    });
    if (!ok) return;
  }

  try {
    await withLoading(btn, async () => {
      let resp;
      if (act === 'access') {
        resp = await api(`/api/admin/users/${encodeURIComponent(id)}/access`, {
          method: 'PATCH',
          body: JSON.stringify({ granted: val }),
        });
      } else if (act === 'ban') {
        resp = await api(`/api/admin/users/${encodeURIComponent(id)}/ban`, {
          method: 'PATCH',
          body: JSON.stringify({ banned: val }),
        });
      } else if (act === 'delete') {
        resp = await api(`/api/admin/users/${encodeURIComponent(id)}`, { method: 'DELETE' });
      } else {
        return;
      }
      if (resp.ok) {
        const text = resp.data.message || '操作成功';
        state.adminNotice = { type: 'success', text };
        showToast('success', text);
      } else {
        const text = resp.data.error || '操作失败（服务端已拒绝）';
        state.adminNotice = { type: 'error', text };
        showToast('error', text);
      }
    });

    // 重新拉取面板，确保界面与服务端状态一致
    await loadResourceB();
  } catch (err) {
    // 兜底：网络/JSON/未知异常也要显式反馈，而不是静默失败
    const text = '操作失败：' + (err && err.message ? err.message : '网络或服务器错误');
    state.adminNotice = { type: 'error', text };
    showToast('error', text);
  }
}

// 骨架屏占位（加载资源时即时反馈）
function skeleton(n) {
  let blocks = '<div class="skeleton-block lg"></div>';
  for (let i = 0; i < n; i++) blocks += '<div class="skeleton-block"></div>';
  return blocks;
}

// ===== 初始化：若已有 token 尝试恢复会话 =====
(async function init() {
  if (state.token) {
    await enterDashboard();
  } else {
    showPage('page-auth');
  }
})();
