/* OathNet Research Console - front end.
 *
 * The API key lives only on the server. This file holds no credentials and
 * cannot reveal secrets unless the server both allows it and the operator
 * confirms.
 */
'use strict';

const state = {
  csrf: null,
  allowReveal: false,
  reveal: false,
  rows: [],
  columns: [],
  cursor: null,
  cursorStack: [],
  query: null,
  dataset: 'breach',
  sort: { key: null, dir: 1 },
  lookups: [],
  busy: false,
};

const $ = (id) => document.getElementById(id);

/* ── api ──────────────────────────────────────────────────────────── */

async function api(path, { method = 'GET', body = null, signal = null } = {}) {
  const headers = { 'Accept': 'application/json' };
  if (body) headers['Content-Type'] = 'application/json';
  if (state.csrf) headers['X-CSRF-Token'] = state.csrf;
  // The server only honours reveal when it sees this explicit confirmation.
  if (state.reveal) headers['X-Reveal'] = 'confirm';

  const response = await fetch(path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : null,
    credentials: 'same-origin',
    signal,
  });

  let payload = null;
  try { payload = await response.json(); } catch { payload = null; }

  if (response.status === 401) {
    showLogin();
    throw new Error('Session expired. Sign in again.');
  }
  if (!response.ok) {
    const message = (payload && payload.message) || `Request failed (${response.status})`;
    const error = new Error(message);
    error.status = response.status;
    error.kind = payload && payload.error;
    throw error;
  }
  return payload;
}

/* ── chrome ───────────────────────────────────────────────────────── */

function showLogin() {
  $('login-view').hidden = false;
  $('app-view').hidden = true;
  $('password').focus();
}

function showApp() {
  $('login-view').hidden = true;
  $('app-view').hidden = false;
}

let toastTimer = null;
function toast(message, kind = '') {
  const el = $('toast');
  el.textContent = message;
  el.className = 'toast ' + kind;
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, 4500);
}

function setStatus(text, kind = 'busy') {
  const el = $('status');
  if (!text) { el.hidden = true; return; }
  el.textContent = text;
  el.className = 'status ' + kind;
  el.hidden = false;
}

function setBusy(on, label = 'Working…') {
  state.busy = on;
  if (on) setStatus(label, 'busy');
  else $('status').hidden = true;
  document.querySelectorAll('button').forEach((b) => { b.disabled = on; });
}

async function refreshQuota() {
  try {
    const { quota } = await api('/api/quota');
    const pill = $('quota-pill');
    if (!quota || quota.left_today == null) {
      pill.textContent = quota && quota.is_unlimited ? 'quota unlimited' : 'quota —';
      pill.className = 'pill';
      return;
    }
    pill.textContent = `${quota.left_today} lookups left`;
    pill.className = 'pill' + (quota.left_today <= 20 ? ' danger' : quota.left_today <= 100 ? ' warn' : '');
  } catch { /* quota is advisory only */ }
}

/* ── auth ─────────────────────────────────────────────────────────── */

async function boot() {
  try {
    const session = await api('/api/session');
    if (session.authenticated) {
      state.csrf = session.csrf;
      state.allowReveal = Boolean(session.allow_reveal);
      $('reveal-toggle').hidden = !state.allowReveal;
      showApp();
      await loadLookups();
      refreshQuota();
    } else {
      showLogin();
    }
  } catch {
    showLogin();
  }
}

$('login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const error = $('login-error');
  error.hidden = true;
  const button = event.target.querySelector('button');
  button.disabled = true;
  try {
    await api('/api/login', { method: 'POST', body: { password: $('password').value } });
    $('password').value = '';
    await boot();
  } catch (err) {
    error.textContent = err.message;
    error.hidden = false;
  } finally {
    button.disabled = false;
  }
});

$('logout').addEventListener('click', async () => {
  try { await api('/api/logout', { method: 'POST' }); } catch { /* fall through */ }
  state.csrf = null;
  state.reveal = false;
  $('reveal-toggle').setAttribute('aria-pressed', 'false');
  $('password').value = '';
  showLogin();
});

$('reveal-toggle').addEventListener('click', () => {
  if (!state.reveal) {
    const ok = window.confirm(
      'Reveal plaintext passwords, cookies, and tokens?\n\n' +
      'Only do this on a trusted machine. Anything on screen can be captured ' +
      'by screenshots, screen shares, or extension scripts.'
    );
    if (!ok) return;
  }
  state.reveal = !state.reveal;
  $('reveal-toggle').setAttribute('aria-pressed', String(state.reveal));
  toast(state.reveal ? 'Secrets will be shown in results.' : 'Secrets are masked again.');
  if (state.rows.length) render();
});

/* ── filters ──────────────────────────────────────────────────────── */

const FILTER_FIELDS = {
  breach: ['dbname', 'email', 'username', 'domain', 'ip', 'country', 'phone', 'discord_id', 'first_name', 'last_name', 'full_name', 'city', 'state'],
  stealer: ['domain', 'subdomain', 'email', 'email_domain', 'username', 'ip', 'discord_id', 'hwid', 'os', 'country', 'city', 'source_type', 'log_id'],
  victims: ['email', 'email_domain', 'username', 'discord_id', 'ip', 'hwid', 'os', 'country', 'city', 'domain', 'service', 'log_id'],
};

function addFilterRow(field = '', value = '') {
  const row = document.createElement('div');
  row.className = 'filter-row';

  const select = document.createElement('select');
  const fields = FILTER_FIELDS[state.dataset] || FILTER_FIELDS.breach;
  for (const name of fields) {
    const option = document.createElement('option');
    option.value = name;
    option.textContent = name;
    if (name === field) option.selected = true;
    select.appendChild(option);
  }

  const input = document.createElement('input');
  input.type = 'text';
  input.placeholder = 'value (comma-separate for several)';
  input.value = value;
  input.spellcheck = false;

  const remove = document.createElement('button');
  remove.type = 'button';
  remove.className = 'ghost small';
  remove.textContent = 'Remove';
  remove.addEventListener('click', () => row.remove());

  row.append(select, input, remove);
  $('filter-rows').appendChild(row);
}

$('add-filter').addEventListener('click', () => addFilterRow());
$('dataset').addEventListener('change', () => {
  state.dataset = $('dataset').value;
  $('filter-rows').replaceChildren();
});

function collectFilters() {
  const filters = {};
  for (const row of $('filter-rows').children) {
    const name = row.querySelector('select').value;
    const raw = row.querySelector('input').value.trim();
    if (!raw) continue;
    const values = raw.split(',').map((v) => v.trim()).filter(Boolean);
    if (!values.length) continue;
    filters[name] = filters[name] ? filters[name].concat(values) : values;
  }
  return filters;
}

/* ── search ───────────────────────────────────────────────────────── */

let inFlight = null;

$('search-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (state.busy) return;
  const query = $('query').value.trim();
  if (!query) return;

  if (inFlight) inFlight.abort();
  inFlight = new AbortController();

  state.dataset = $('dataset').value;
  state.query = query;
  state.cursor = null;
  state.cursorStack = [];
  state.sort = { key: null, dir: 1 };

  setBusy(true, `Searching ${state.dataset} for ${query}…`);
  try {
    const payload = await runSearch(query, null, inFlight.signal);
    applyResults(payload);
    refreshQuota();
  } catch (err) {
    if (err.name !== 'AbortError') {
      setStatus(err.message, 'err');
      $('table-wrap').innerHTML = '';
      $('results-actions').hidden = true;
      $('pager').hidden = true;
    }
  } finally {
    setBusy(false);
  }
});

async function runSearch(query, cursor, signal) {
  const body = {
    query,
    page_size: Number($('page-size').value),
    wildcard: $('wildcard').checked,
    filters: collectFilters(),
  };
  if (cursor) body.cursor = cursor;
  return api(`/api/${state.dataset}`, { method: 'POST', body, signal });
}

function applyResults(payload) {
  state.rows = Array.isArray(payload.rows) ? payload.rows : [];
  state.cursor = (payload.detail && payload.detail.next_cursor) || null;
  render();

  const total = (payload.meta && payload.meta.total);
  const shown = state.rows.length;
  $('result-count').textContent =
    `${shown} record${shown === 1 ? '' : 's'}` + (total != null ? ` of ${total} total` : '');
  $('results-actions').hidden = shown === 0;
  $('pager').hidden = !state.cursor;
  $('page-info').textContent = `page ${state.cursorStack.length + 1}`;

  if (shown === 0) {
    setStatus('No records matched. Try a broader query or remove filters.', 'warn');
  } else if (!state.reveal && payload.masked_count) {
    setStatus(`${payload.masked_count} secret value(s) masked. Use Reveal secrets to show them.`, 'warn');
  } else {
    setStatus('', '');
  }
}

/* ── table ────────────────────────────────────────────────────────── */

function computeColumns(rows) {
  const seen = [];
  for (const row of rows.slice(0, 40)) {
    for (const key of Object.keys(row)) if (!seen.includes(key)) seen.push(key);
  }
  const preferred = ['email', 'username', 'url', 'domain', 'password', 'dbname', 'log_id',
                     'ip', 'country', 'city', 'os', 'service_count', 'total_docs', 'indexed_at'];
  const ordered = preferred.filter((k) => seen.includes(k));
  for (const key of seen) if (!ordered.includes(key)) ordered.push(key);
  return ordered.slice(0, 14);
}

function cell(value) {
  if (value === null || value === undefined || value === '') return '—';
  if (Array.isArray(value)) return value.length ? value.map(cell).join(', ') : '—';
  if (typeof value === 'object') return JSON.stringify(value);
  if (typeof value === 'boolean') return value ? 'yes' : 'no';
  const text = String(value);
  const masked = text.includes('REDACTED') || (text.includes('*') && !text.includes(' '));
  const td = document.createElement('td');
  td.textContent = text;
  if (masked) td.className = 'masked';
  else if (/[@.\d]/.test(text) && !/\s/.test(text)) td.className = 'mono';
  td.title = text;
  return td;
}

function render() {
  const wrap = $('table-wrap');
  wrap.replaceChildren();
  if (!state.rows.length) {
    const empty = document.createElement('p');
    empty.className = 'muted empty-note';
    empty.textContent = 'No records to display.';
    wrap.appendChild(empty);
    state.columns = [];
    return;
  }

  state.columns = computeColumns(state.rows);
  let rows = state.rows.slice();
  if (state.sort.key) {
    const { key, dir } = state.sort;
    rows.sort((a, b) => {
      const av = a[key] ?? '';
      const bv = b[key] ?? '';
      if (typeof av === 'number' && typeof bv === 'number') return (av - bv) * dir;
      return String(av).localeCompare(String(bv), undefined, { numeric: true }) * dir;
    });
  }

  const table = document.createElement('table');
  const thead = table.createTHead().insertRow();
  for (const column of state.columns) {
    const th = document.createElement('th');
    th.textContent = column.replace(/_/g, ' ');
    if (state.sort.key === column) {
      th.textContent += state.sort.dir === 1 ? ' ▲' : ' ▼';
    }
    th.addEventListener('click', () => {
      state.sort = state.sort.key === column
        ? { key: column, dir: -state.sort.dir }
        : { key: column, dir: 1 };
      render();
    });
    thead.appendChild(th);
  }

  const tbody = table.createTBody();
  for (const row of rows) {
    const tr = tbody.insertRow();
    for (const column of state.columns) tr.appendChild(cell(row[column]));
  }
  wrap.appendChild(table);
}

/* ── paging ───────────────────────────────────────────────────────── */

$('page-next').addEventListener('click', async () => {
  if (!state.cursor) return;
  setBusy(true, 'Loading next page…');
  try {
    state.cursorStack.push(state.cursor);
    const payload = await runSearch(state.query, state.cursor);
    applyResults(payload);
  } catch (err) {
    state.cursorStack.pop();
    setStatus(err.message, 'err');
  } finally {
    setBusy(false);
  }
});

$('page-prev').addEventListener('click', async () => {
  state.cursorStack.pop();
  const cursor = state.cursorStack.length ? state.cursorStack[state.cursorStack.length - 1] : null;
  setBusy(true, 'Loading previous page…');
  try {
    const payload = await runSearch(state.query, cursor);
    applyResults(payload);
  } catch (err) {
    setStatus(err.message, 'err');
  } finally {
    setBusy(false);
  }
});

/* ── export ───────────────────────────────────────────────────────── */

function download(name, content, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  link.click();
  URL.revokeObjectURL(url);
}

const safeName = () => (state.query || 'results').replace(/[^a-z0-9._-]+/gi, '_').slice(0, 60);

$('export-json').addEventListener('click', () => {
  download(`${safeName()}.json`, JSON.stringify(state.rows, null, 2), 'application/json');
  if (!state.reveal) toast('Export contains masked values only.', '');
});

$('export-csv').addEventListener('click', () => {
  const columns = state.columns.length ? state.columns : Object.keys(state.rows[0] || {});
  const escape = (v) => {
    const text = Array.isArray(v) ? v.join(' ') : (v ?? '');
    return /[",\n]/.test(String(text)) ? `"${String(text).replace(/"/g, '""')}"` : text;
  };
  const csv = [columns.join(',')]
    .concat(state.rows.map((row) => columns.map((c) => escape(row[c])).join(',')))
    .join('\n');
  download(`${safeName()}.csv`, csv, 'text/csv');
  if (!state.reveal) toast('Export contains masked values only.', '');
});

/* ── lookups ──────────────────────────────────────────────────────── */

async function loadLookups() {
  try {
    const { lookups } = await api('/api/lookups');
    state.lookups = lookups;
    const select = $('lookup-name');
    select.replaceChildren();
    for (const item of lookups) {
      const option = document.createElement('option');
      option.value = item.name;
      option.textContent = item.label;
      select.appendChild(option);
    }
    updateLookupHint();
  } catch { /* non-fatal */ }
}

function updateLookupHint() {
  const item = state.lookups.find((l) => l.name === $('lookup-name').value);
  $('lookup-hint').textContent = item && item.param ? `Takes: ${item.param}` : 'Takes: ID or username';
}

$('lookup-name').addEventListener('change', updateLookupHint);

$('lookup-run').addEventListener('click', async () => {
  const value = $('lookup-value').value.trim();
  if (!value) { toast('Enter a value to look up.', 'err'); return; }
  setBusy(true, `Running ${$('lookup-name').value}…`);
  try {
    const payload = await api('/api/lookup', {
      method: 'POST',
      body: {
        lookup: $('lookup-name').value,
        value,
        alive: $('lookup-alive').checked,
      },
    });
    renderLookup(payload);
  } catch (err) {
    $('lookup-output').replaceChildren();
    const p = document.createElement('p');
    p.className = 'error';
    p.textContent = err.message;
    $('lookup-output').appendChild(p);
  } finally {
    setBusy(false);
  }
});

function renderLookup(payload) {
  const out = $('lookup-output');
  out.replaceChildren();
  const heading = document.createElement('h3');
  heading.textContent = payload.label;
  out.appendChild(heading);

  if (payload.revealed) {
    const warn = document.createElement('p');
    warn.className = 'error small';
    warn.textContent = 'Secrets are revealed in this view.';
    out.appendChild(warn);
  }

  const data = payload.data;
  if (Array.isArray(data)) {
    for (const entry of data) out.appendChild(renderNode(entry));
    return;
  }
  if (data && typeof data === 'object') {
    // Steam nests the interesting fields under meta.raw_data.
    const meta = data.meta;
    const merged = (meta && meta.raw_data && typeof meta.raw_data === 'object')
      ? Object.assign({}, data, meta.raw_data)
      : data;
    out.appendChild(renderNode(merged));
    return;
  }
  const p = document.createElement('p');
  p.textContent = String(data ?? 'No data returned.');
  out.appendChild(p);
}

function renderNode(value, depth = 0) {
  const wrap = document.createElement('div');
  if (value === null || value === undefined) return wrap;

  if (typeof value === 'object' && !Array.isArray(value)) {
    const dl = document.createElement('dl');
    dl.className = 'kv';
    for (const [key, item] of Object.entries(value)) {
      if (item === null || item === undefined || item === '') continue;
      const dt = document.createElement('dt');
      dt.textContent = key.replace(/_/g, ' ');
      const dd = document.createElement('dd');
      if (typeof item === 'object' && !Array.isArray(item)) {
        dd.appendChild(renderNode(item, depth + 1));
      } else if (Array.isArray(item)) {
        dd.textContent = item.length ? item.map((v) => (typeof v === 'object' ? JSON.stringify(v) : v)).join(', ') : '—';
      } else {
        const text = String(item);
        dd.textContent = text;
        if (text.includes('REDACTED')) dd.className = 'masked';
      }
      dl.append(dt, dd);
    }
    wrap.appendChild(dl);
    return wrap;
  }

  if (Array.isArray(value)) {
    const list = document.createElement('ul');
    list.className = 'array';
    for (const entry of value.slice(0, 200)) {
      const li = document.createElement('li');
      li.textContent = typeof entry === 'object' ? JSON.stringify(entry) : String(entry);
      list.appendChild(li);
    }
    if (value.length > 200) {
      const li = document.createElement('li');
      li.textContent = `… ${value.length - 200} more`;
      list.appendChild(li);
    }
    wrap.appendChild(list);
    return wrap;
  }

  const p = document.createElement('p');
  p.textContent = String(value);
  wrap.appendChild(p);
  return wrap;
}

/* ── tabs ─────────────────────────────────────────────────────────── */

document.querySelectorAll('.tab').forEach((tab) => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach((t) => {
      t.classList.remove('active');
      t.setAttribute('aria-selected', 'false');
    });
    tab.classList.add('active');
    tab.setAttribute('aria-selected', 'true');
    for (const name of ['results', 'enrich']) {
      $('panel-' + name).hidden = name !== tab.dataset.panel;
    }
  });
});

/* ── indicator detection ──────────────────────────────────────────── */

let detectTimer = null;
$('query').addEventListener('input', () => {
  clearTimeout(detectTimer);
  const value = $('query').value.trim();
  const hint = $('detect-hint');
  if (value.length < 3) { hint.hidden = true; return; }
  detectTimer = setTimeout(async () => {
    try {
      const payload = await api(`/api/detect?q=${encodeURIComponent(value)}`);
      hint.hidden = false;
      hint.textContent = `Detected: ${payload.kind}. Suggested: ${payload.suggested.join(', ')}`;
    } catch { hint.hidden = true; }
  }, 350);
});

boot();
