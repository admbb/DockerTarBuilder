/**
 * The Credentials tab's pinned "MikroDash login" row (#143): the account
 * MikroDash ITSELF signs in with - user `mikrodash` in group `mikrodash` - one
 * password for every linked device.
 *
 * ── ONE LOGIN, PINNED IN THE PROFILES TABLE ─────────────────────────────────
 *
 * The operator's layout: not a table of its own, but the first row of the
 * credential profiles table, always there. So the page holds ONE login,
 * created as `MIKRODASH_LOGIN` the first time a password is set; the server
 * keeps a list (`/data/login-profiles.json`) and the page uses its first entry.
 *
 * ── LINKING WRITES TO THE DEVICE, AND PROVES IT FIRST ───────────────────────
 *
 * The server creates the account on each device, signs in afresh with it, and
 * only then switches the device over; a failure puts the device back as it was
 * (`internal/server/loginprof_api.go`). So linking is a job that runs for a
 * while, and its progress is polled from the list rather than awaited.
 *
 * ── THE PASSWORD IS WRITE-ONLY ───────────────────────────────────────────────
 *
 * The server never sends it. On edit the box is empty and blank keeps it; a
 * value there changes the password on EVERY linked device, all or nothing.
 */

import { el, esc } from '../dom';
import { isChinese, translate, translateCredentialError } from '../language';
import { mountPicker, type Picker } from '../device-picker';

export interface LoginOpResult { state: string; message: string }

export interface LoginOp {
  kind: string;
  running: boolean;
  started: number;
  results: Record<string, LoginOpResult>;
  summary: string;
}

/** One profile, as GET /api/credentials/logins lists it. */
export interface LoginProfileView {
  id: string;
  name: string;
  username: string;
  group: string;
  hasSecret: boolean;
  devices: string[];
  updatedAt: number;
  op: LoginOp | null;
}

interface Device { id: string; label: string; host: string; model: string; siteIds: string[]; loginProfileId: string }

/** The status cell: the job's state while it runs, then its summary. */
export function opStatus(op: LoginOp | null, devices = 0): string {
  // NO JOB IN MEMORY (none run yet, or the server restarted): the device
  // records are the truth, in the words the other rows use.
  if (!op) {
    return devices ? '<span class="pill pill-ok">' + translate('applied', '已应用') + '</span>' : '<span class="pill pill-muted">' + translate('not linked', '未关联') + '</span>';
  }
  const vals = Object.values(op.results);
  const failed = vals.filter((r) => r.state === 'failed').length;
  if (op.running) {
    const done = vals.filter((r) => r.state === 'done' || r.state === 'failed').length;
    const what = op.kind === 'password' ? translate('Changing password', '正在更改密码') : translate('Linking', '正在关联');
    return `<span class="pill pill-rx">${what} ${done}/${vals.length}</span>`;
  }
  // SHORT, in the table's own state words; the sentence is the tooltip. The
  // whole summary in the cell pushed the row's buttons out of the table.
  const word = failed ? translate(`${failed} failed`, `${failed} 个失败`) : translate('applied', '已应用');
  return `<span class="pill pill-${failed ? 'warn' : 'ok'}" title="${esc(op.summary)}">${esc(word)}</span>`;
}

/** The name the pinned login is created with. */
export const MIKRODASH_LOGIN = 'MikroDash login';

/**
 * The pinned row, in the credential profiles table's columns: name, RouterOS
 * user, permissions, devices, state, actions. `null` is a login not set up yet,
 * which still shows - pinned means always there - offering to set it.
 */
export function pinnedRow(p: LoginProfileView | null): string {
  const busy = !!(p && p.op && p.op.running);
  const actions = p
    ? `<button class="sbtn sbtn-outline is-sm" type="button" data-lp-edit="${esc(p.id)}"${busy ? ' disabled' : ''}>${translate('Edit', '编辑')}</button> `
      + `<button class="sbtn sbtn-outline is-sm" type="button" data-lp-devices="${esc(p.id)}">${translate('Devices', '设备')}</button>`
    : '<button class="sbtn sbtn-primary is-sm" type="button" data-lp-new="1">' + translate('Set password', '设置密码') + '</button>';
  return '<tr class="lp-pinned">'
    + `<td><strong>${esc(p ? p.name : translate(MIKRODASH_LOGIN, 'MikroDash 登录账户'))}</strong> `
    + '<span class="pill pill-rx" title="' + translate('The account MikroDash itself signs in with. Always first, never deleted.', 'MikroDash 自身使用的登录账户，始终置顶，不会被删除。') + '">'
    + translate('pinned', '已置顶') + '</span></td>'
    + `<td><span class="pill pill-alt">${esc(p ? p.username : 'mikrodash')}</span></td>`
    + `<td><span class="cp-perms">${esc(p ? p.group : 'mikrodash')}: ${translate('every permission', '所有权限')}</span></td>`
    + `<td>${p ? p.devices.length : 0}</td>`
    + `<td>${p ? opStatus(p.op, p.devices.length) : '<span class="pill pill-muted">' + translate('not set', '未设置') + '</span>'}</td>`
    + `<td class="text-end cp-actions">${actions}</td></tr>`;
}

/**
 * The devices Link would act on: the picked ones not already on this profile.
 * A site here is a shortcut that adds its devices as they are now (the picker's
 * `shortcut` mode), so there is no site set to expand.
 */
export function linkTargets(picked: readonly string[], devices: readonly Pick<Device, 'id' | 'loginProfileId'>[],
  profileId: string): string[] {
  const on = new Set(picked);
  return devices.filter((d) => d.loginProfileId !== profileId && on.has(d.id)).map((d) => d.id);
}

/** Checks the form before anything is sent. "" when it is fine. */
export function formError(pass: string, pass2: string, creating: boolean): string {
  if (creating && !pass) return translate('A password is required.', '请输入密码。');
  if (pass && pass.length < 12) return translate('The password needs at least 12 characters.', '密码至少需要 12 个字符。');
  if (pass !== pass2) return translate('The two passwords differ.', '两次输入的密码不一致。');
  return '';
}

async function lpApi<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch('/api/credentials/logins' + path, { credentials: 'same-origin', ...init });
  const body = (await r.json().catch(() => ({}))) as T & { error?: string };
  if (!r.ok) throw new Error(body.error ? translateCredentialError(body.error) : translate('The request failed (' + r.status + ')', '请求失败（' + r.status + '）'));
  return body;
}

const send = (method: string, v: unknown): RequestInit => ({
  method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(v),
});

export function mountLoginProfiles(redraw: (row: string) => void): { load: () => Promise<void> } {
  let list: LoginProfileView[] = [];
  let devices: Device[] = [];
  let sites: { id: string; name: string }[] = [];
  let editing: LoginProfileView | null = null;
  let devFor = '';
  let ownFor = '';
  let picker: Picker | null = null;
  let poll: ReturnType<typeof setTimeout> | null = null;

  const open = (id: string, on: boolean): void => { el(id)?.classList.toggle('open', on); };
  const showErr = (id: string, msg: string): void => {
    const n = el(id);
    if (!n) return;
    n.textContent = msg;
    n.style.display = msg ? '' : 'none';
  };
  const nameOf = (id: string): string => devices.find((d) => d.id === id)?.label ?? id;

  async function loadDevices(): Promise<void> {
    try {
      const r = await fetch('/api/routers', { credentials: 'same-origin' });
      const b = (await r.json()) as { routers?: { id: string; label?: string; host?: string; disabled?: boolean;
        siteIds?: string[]; loginProfileId?: string; model?: string }[] };
      devices = (b.routers ?? []).filter((x) => !x.disabled).map((x) => ({
        id: x.id, label: x.label || x.host || x.id, host: x.host ?? '', model: x.model ?? '',
        siteIds: x.siteIds ?? [], loginProfileId: x.loginProfileId ?? '',
      }));
    } catch {
      devices = [];
    }
  }

  async function load(): Promise<void> {
    try {
      list = (await lpApi<{ logins: LoginProfileView[] }>('')).logins;
    } catch {
      list = [];
    }
    redraw(pinnedRow(list[0] ?? null));
    if (devFor) {
      await loadDevices();
      picker?.refresh();
      drawDevices();
    }
    // POLLED WHILE A JOB RUNS, and only then.
    if (poll) clearTimeout(poll);
    poll = list.some((p) => p.op && p.op.running) ? setTimeout(() => void load(), 2000) : null;
  }

  // ── the password form ───────────────────────────────────────────────────
  function openForm(p: LoginProfileView | null): void {
    editing = p;
    showErr('lpError', '');
    const set = (id: string, v: string): void => { const n = el<HTMLInputElement>(id); if (n) n.value = v; };
    set('lpPass', '');
    set('lpPass2', '');
    const lbl = el('lpPassLabel');
    if (lbl) lbl.textContent = p ? translate('New password', '新密码') : translate('Password', '密码');
    const note = el('lpPassNote');
    if (note) {
      note.textContent = isChinese() ? (p && p.devices.length
        ? `新密码将同时应用到全部 ${p.devices.length} 台关联设备，或全部不更改：任何设备离线或拒绝时，均不会更改。`
        : '至少 12 个字符。该账户拥有所有权限并用于登录每台关联设备，请像设备管理员密码一样妥善保管。') : p && p.devices.length
        ? `A new password is changed on all ${p.devices.length} linked device(s) at once, or on none: if any `
          + 'device is offline or refuses it, nothing changes.'
        : 'At least 12 characters. It signs in to every linked device with every permission, so treat it '
          + "like the devices' admin password.";
    }
    open('lpModal', true);
  }

  async function save(): Promise<void> {
    const pass = el<HTMLInputElement>('lpPass')?.value ?? '';
    const pass2 = el<HTMLInputElement>('lpPass2')?.value ?? '';
    const bad = formError(pass, pass2, true);
    if (bad) { showErr('lpError', bad); return; }
    try {
      if (editing) {
        await lpApi('/' + editing.id, send('PUT', { name: editing.name, password: pass }));
      } else {
        await lpApi('', send('POST', { name: MIKRODASH_LOGIN, password: pass }));
      }
      open('lpModal', false);
      await load();
    } catch (e) {
      showErr('lpError', e instanceof Error ? e.message : 'The password could not be saved');
    }
  }

  // ── the devices dialog ──────────────────────────────────────────────────
  //
  // The shared picker (`device-picker.ts`). Devices already on this login are
  // LOCKED pills with "Use own login"; a device on another login says so, and
  // linking moves it. The last job's result per device colours its pill.
  function pickerFor(): Picker | null {
    if (picker) return picker;
    const host = el('lpDevList');
    if (!host) return null;
    picker = mountPicker(host, {
      items: () => devices.map((d) => ({ id: d.id, label: d.label, host: d.host, model: d.model, siteIds: d.siteIds })),
      sites: () => sites,
      siteMode: 'shortcut',
      fixed: () => devices.filter((d) => d.loginProfileId === devFor).map((d) => d.id),
      info: (id) => {
        const d = devices.find((x) => x.id === id);
        if (d && d.loginProfileId === devFor) {
          return { kind: 'ok', text: 'linked', locked: true,
            action: `<button class="dp-act" type="button" data-lp-own="${esc(id)}">Use own login</button>` };
        }
        const r = list.find((x) => x.id === devFor)?.op?.results[id];
        if (r) {
          const kind = r.state === 'failed' ? 'bad' : r.state === 'done' ? 'ok' : 'wait';
          return { kind, text: r.state, title: r.message };
        }
        if (d && d.loginProfileId) return { kind: 'wait', text: 'other login', title: 'Signs in with another login; linking moves it' };
        return undefined;
      },
      placeholder: translate('Search devices or sites', '搜索设备或站点'),
      emptyText: translate('No devices sign in with this login yet. Search to add some.', '尚无设备使用此账户登录，请搜索并添加。'),
      onChange: drawDevices,
    });
    return picker;
  }

  function drawDevices(): void {
    const p = list.find((x) => x.id === devFor);
    const t = el('lpDevTitle');
    if (t) t.textContent = translate('Devices signing in with the MikroDash login', '使用 MikroDash 登录账户的设备');
    const n = linkTargets(picker?.get().items ?? [], devices, devFor).length;
    const btn = el<HTMLButtonElement>('lpDevApply');
    const running = !!(p && p.op && p.op.running);
    if (btn) {
      btn.disabled = n === 0 || running;
      btn.textContent = running ? translate('Working…', '正在处理…') : n ? translate(`Link ${n} device${n === 1 ? '' : 's'}`, `关联 ${n} 台设备`) : translate('Link', '关联');
    }
  }

  async function openDevices(id: string): Promise<void> {
    devFor = id;
    showErr('lpDevError', '');
    await loadDevices();
    try {
      const r = await fetch('/api/sites', { credentials: 'same-origin' });
      sites = ((await r.json()) as { sites?: { id: string; name: string }[] }).sites ?? [];
    } catch {
      sites = [];
    }
    pickerFor()?.set({ items: [], sites: [] });
    drawDevices();
    open('lpDevModal', true);
  }

  async function link(): Promise<void> {
    const ids = linkTargets(picker?.get().items ?? [], devices, devFor);
    const p = list.find((x) => x.id === devFor);
    if (!ids.length || !p) return;
    const msg = `Link ${ids.length} device(s) to "${p.name}"?\n\nOn each one this creates user mikrodash in group `
      + 'mikrodash (every permission, if the group is new) with the profile\'s password, checks it signs in, and switches MikroDash '
      + 'over. A device where that fails is put back as it was.';
    const zhMsg = `将 ${ids.length} 台设备关联到“${p.name}”？\n\n系统将在每台设备上使用该配置的密码创建 mikrodash 用户及用户组（若用户组是新建的，将拥有所有权限），验证能否登录后再切换 MikroDash。操作失败的设备会恢复原状。`;
    if (!window.confirm(translate(msg, zhMsg))) return;
    try {
      await lpApi('/' + devFor + '/devices', send('POST', { routerIds: ids }));
      picker?.set({ items: [], sites: [] });
      await load();
    } catch (e) {
      showErr('lpDevError', e instanceof Error ? e.message : 'Linking could not start');
    }
  }

  // ── back to an own login ────────────────────────────────────────────────
  function openOwn(routerId: string): void {
    ownFor = routerId;
    showErr('lpOwnError', '');
    const d = el('lpOwnDevice');
    if (d) d.textContent = nameOf(routerId);
    for (const id of ['lpOwnUser', 'lpOwnPass']) { const n = el<HTMLInputElement>(id); if (n) n.value = ''; }
    open('lpOwnModal', true);
  }

  async function saveOwn(): Promise<void> {
    const username = el<HTMLInputElement>('lpOwnUser')?.value.trim() ?? '';
    const password = el<HTMLInputElement>('lpOwnPass')?.value ?? '';
    if (!username || !password) { showErr('lpOwnError', translate('A username and password are required.', '请输入用户名和密码。')); return; }
    try {
      await lpApi('/' + devFor + '/devices/' + encodeURIComponent(ownFor) + '/own',
        send('POST', { username, password }));
      open('lpOwnModal', false);
      await load();
    } catch (e) {
      showErr('lpOwnError', e instanceof Error ? e.message : 'The device could not be switched');
    }
  }

  // ── wiring ──────────────────────────────────────────────────────────────
  el('lpCancel')?.addEventListener('click', () => open('lpModal', false));
  el('lpSave')?.addEventListener('click', () => void save());
  // THE PINNED ROW LIVES IN THE PROFILES TABLE, so its buttons are found there.
  el('cpBody')?.addEventListener('click', (e) => {
    const t = e.target as HTMLElement | null;
    const b = t?.closest?.('button') as HTMLElement | null;
    if (!b) return;
    if (b.dataset.lpNew) openForm(null);
    if (b.dataset.lpEdit) openForm(list.find((p) => p.id === b.dataset.lpEdit) ?? null);
    if (b.dataset.lpDevices) void openDevices(b.dataset.lpDevices);
  });
  el('lpDevClose')?.addEventListener('click', () => { devFor = ''; open('lpDevModal', false); });
  el('lpDevApply')?.addEventListener('click', () => void link());
  el('lpDevList')?.addEventListener('click', (e) => {
    const b = (e.target as HTMLElement | null)?.closest?.('[data-lp-own]') as HTMLElement | null;
    if (!b) return;
    e.preventDefault();
    openOwn(b.dataset.lpOwn || '');
  });
  el('lpOwnCancel')?.addEventListener('click', () => open('lpOwnModal', false));
  el('lpOwnSave')?.addEventListener('click', () => void saveOwn());

  return { load };
}
