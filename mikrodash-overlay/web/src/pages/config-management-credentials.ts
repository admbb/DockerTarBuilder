/**
 * The Credentials tab: RouterOS accounts MikroDash provisions across the fleet.
 *
 * ── WHAT THIS IS NOT ─────────────────────────────────────────────────────────
 *
 * A profile here is not where MikroDash's own login is kept - that is the pinned
 * "MikroDash login" row, `config-management-logins.ts`. A profile creates
 * accounts for PEOPLE; MikroDash signs in as itself throughout, and the server refuses per
 * router - `internal/guard/selfguard.go` - any write that could disturb that.
 * The copy on the page says so, because an operator who believes otherwise will
 * eventually try to use a profile to change MikroDash's own password.
 *
 * ── THE PASSWORD IS WRITE-ONLY ───────────────────────────────────────────────
 *
 * The server sends `hasSecret` and never the value, sealed or otherwise. So the
 * edit form's password box is EMPTY on open and blank means "leave it alone" -
 * the same contract `resource.TypeSecret` has. The help text has to say so,
 * because a box that looks empty and is not is how somebody clears a password
 * by accident.
 */

import { el, esc } from '../dom';
import { isChinese, translate } from '../language';
import type { PillTone } from '../palette';

/** One profile, as GET /api/credentials/profiles lists it. */
export interface CredProfile {
  id: string;
  name: string;
  description: string;
  username: string;
  groupName: string;
  policies: string[];
  hasSecret: boolean;
  links: number;
  revision: number;
  /** Offered first when a device is provisioned. At most one profile has it. */
  isDefault: boolean;
  /** Set when Delete was pressed while routers still held the account. */
  pendingDelete: boolean;
}

/** One profile's standing on one router. */
export interface CredLink {
  profileId: string;
  routerId: string;
  state: string;
  code: string;
  error: string;
  appliedRevision: number;
  attempts: number;
  /** 'direct' if somebody picked this router, 'site' if a site did. */
  via: string;
}

/**
 * The state pills.
 *
 * ── DECLARED BY KIND, NEVER BY COLOUR ────────────────────────────────────────
 *
 * CLAUDE.md's rule for the generated pages, kept by hand here because this is a
 * hand-built panel. `refused` and `conflict` are AMBER rather than red: neither
 * is a fault, both are MikroDash declining to do something, and a red row for
 * "the guard protected your login" reads as a bug report.
 */
const STATE_KIND: Record<string, string> = {
  applied: 'ok',
  pending: 'wait',
  applying: 'wait',
  removing: 'wait',
  refused: 'warn',
  conflict: 'warn',
  orphaned: 'warn',
  failed: 'bad',
  unreachable: 'bad',
  unknown: 'bad',
};

/** What each state means, in the operator's terms rather than the code's. */
const STATE_TITLE: Record<string, string> = {
  'not linked': 'This profile is not on any device yet. Open Devices to put it on one.',
  applied: 'The account is on this router, in the right group.',
  pending: 'Queued. It will be applied the next time the router answers.',
  applying: 'Being applied now.',
  removing: 'Queued for removal. The account comes off when the router answers.',
  refused: 'MikroDash declined this write to protect its own login. It will not be retried on '
    + 'its own - fix the profile, then use Retry.',
  conflict: 'An account with that name is already on the router and MikroDash did not put it '
    + 'there. Nothing was changed.',
  orphaned: 'The account could not be taken off. The link is kept so it is not forgotten.',
  failed: 'The router refused the write.',
  unreachable: 'The router did not answer. It will be retried.',
  unknown: 'The write was accepted but could not be confirmed. It will be re-checked.',
};

/** The picker pill kind for a link state (see `PillInfo`). */
export function stateKind(state: string): 'ok' | 'wait' | 'warn' | 'bad' | undefined {
  const k = STATE_KIND[state];
  return k === 'ok' || k === 'wait' || k === 'warn' || k === 'bad' ? k : undefined;
}

/** The pill tone for each picker kind: in progress is blue, refusal amber. */
const KIND_TONE: Record<string, PillTone> = { ok: 'ok', wait: 'rx', warn: 'warn', bad: 'err' };

const STATE_ZH: Record<string, string> = { 'not linked': '未关联', applied: '已应用', pending: '等待中', applying: '正在应用', removing: '正在移除', refused: '已拒绝', conflict: '冲突', orphaned: '移除未完成', failed: '失败', unreachable: '无法连接', unknown: '待确认' };
const STATE_TITLE_ZH: Record<string, string> = {
  'not linked': '此配置尚未关联任何设备。请打开设备列表进行关联。', applied: '账户已在此路由器上创建，并属于正确的用户组。',
  pending: '已排队，路由器下次响应时将应用。', applying: '正在应用。', removing: '已排队移除，路由器响应后将移除账户。',
  refused: 'MikroDash 为保护自身登录拒绝了此次写入，不会自动重试。请修正配置后重试。',
  conflict: '路由器上已有同名账户，且不是由 MikroDash 创建；未做任何更改。',
  orphaned: '无法移除账户，关联记录会保留以便后续处理。', failed: '路由器拒绝了写入。',
  unreachable: '路由器无响应，系统将重试。', unknown: '写入已接受但无法确认，系统将重新检查。',
};

export function statePill(state: string): string {
  // AN UNKNOWN STATE IS NEUTRAL, NOT RED. `not linked` is the ordinary case for
  // a profile nobody has put anywhere yet, and colouring it like a failure
  // would make an untouched profile look broken.
  const tone = KIND_TONE[STATE_KIND[state] ?? ''] ?? 'muted';
  const title = isChinese() ? STATE_TITLE_ZH[state] ?? '' : STATE_TITLE[state] ?? '';
  const label = isChinese() ? STATE_ZH[state] ?? state : state;
  return `<span class="pill pill-${tone}" title="${esc(title)}">${esc(label)}</span>`;
}

/**
 * How a profile's permissions read in the table.
 *
 * A custom set names its policies rather than saying "custom", because "custom"
 * tells an operator nothing about what the account can do - which is the one
 * question the column exists to answer.
 */
export function permissionText(p: CredProfile): string {
  if (!p.policies.length) return `${p.groupName}${translate(' (no permissions)', '（无权限）')}`;
  return `${p.groupName}: ${p.policies.join(', ')}`;
}

/**
 * The worst state among a profile's links, which is what the row shows.
 *
 * ── THE WORST, NOT THE COMMONEST ─────────────────────────────────────────────
 *
 * Nineteen routers applied and one refused is a row that must say `refused`. A
 * majority reading would show `applied`, and the one device that needs
 * attention would be invisible until somebody opened the profile.
 */
const STATE_RANK = ['applied', 'pending', 'applying', 'removing', 'unreachable',
  'unknown', 'failed', 'orphaned', 'conflict', 'refused'];

export function worstState(links: readonly CredLink[]): string {
  let worst = '';
  let rank = -1;
  for (const l of links) {
    const r = STATE_RANK.indexOf(l.state);
    if (r > rank) {
      rank = r;
      worst = l.state;
    }
  }
  return worst;
}

/** One table row. */
export function profileRow(p: CredProfile, links: readonly CredLink[]): string {
  const mine = links.filter((l) => l.profileId === p.id);
  const state = worstState(mine);
  // THE ROW CARRIES NO ID ATTRIBUTE. The buttons carry it; one on the row as
  // well would be decoration, and TestRenderedAttributesAreRead refuses an
  // attribute nothing reads - it is indistinguishable from a handler that was
  // deleted. (Written without the attribute's own spelling: that check does not
  // strip comments, so naming it here would make this comment fail it. The
  // traps skill calls this out - "write the example so the checker does not
  // recognise it".)
  return '<tr>'
    + `<td><strong>${esc(p.name)}</strong>`
    // THE DEFAULT IS MARKED IN THE LIST, because "which one is the default" is
    // otherwise only visible by opening each profile in turn.
    + (p.isDefault ? ' <span class="pill pill-rx" title="Offered first when a device '
      + 'is provisioned">default</span>' : '')
    + (p.description ? `<div class="cfg-meta">${esc(p.description)}</div>` : '')
    + '</td>'
    // THE ACCOUNT, as a pill: it is the thing this profile puts on a router,
    // and the column reads as a set of accounts rather than a run of text.
    + `<td><span class="pill pill-alt">${esc(p.username)}</span></td>`
    // TRUNCATED, WITH THE WHOLE LIST IN title. Seventeen policies used to wrap
    // the cell, grow the row, and push the buttons beside it onto two lines.
    + `<td><span class="cp-perms" title="${esc(permissionText(p))}">`
    + `${esc(permissionText(p))}</span></td>`
    + `<td>${p.links}</td>`
    + `<td>${state ? statePill(state) : statePill('not linked')}</td>`
    + '<td class="text-end cp-actions">'
    + `<button class="sbtn sbtn-outline" type="button" data-cp-edit="${esc(p.id)}">${translate('Edit', '编辑')}</button> `
    + `<button class="sbtn sbtn-outline" type="button" data-cp-links="${esc(p.id)}">${translate('Devices', '设备')}</button> `
    // DELETE IS NOT INSTANT when routers hold the account, and the label says
    // which it will be. A button that reads "Delete" and then leaves the row in
    // place for a minute reads as a failure.
    + `<button class="sbtn sbtn-danger" type="button" data-cp-del="${esc(p.id)}">`
    + (p.links > 0 ? translate('Remove &amp; delete', '移除并删除') : translate('Delete', '删除')) + '</button>'
    + '</td></tr>';
}

/** Draws the whole table, or the empty state. */
export function drawProfiles(profiles: readonly CredProfile[],
  links: readonly CredLink[], pinned = ''): void {
  const body = el('cpBody');
  const empty = el('cpEmpty');
  if (!body || !empty) return;
  // THE PINNED ROW FIRST: the MikroDash login (config-management-logins.ts).
  body.innerHTML = pinned + profiles.map((p) => profileRow(p, links)).join('');
  empty.hidden = profiles.length > 0 || pinned !== '';
}

/** What a links-dialog Apply would send. */
export interface LinkDiff {
  addSites: string[];
  dropSites: string[];
  addRouters: string[];
  dropRouters: string[];
}

/**
 * The staged state, minus what the server already has.
 *
 * ── A SITE-COVERED ROUTER IS IN NEITHER LIST, AND THAT IS THE RULE ─────────
 *
 * A router pulled in by a ticked site comes and goes WITH that site. Sending a
 * direct link for it as well would create a second, independent claim on the
 * same device - and unticking the site later would not withdraw it, so the
 * account would stay with nothing on screen explaining why. Equally it must not
 * appear in `dropRouters`: it is not a direct link, and deleting it would fight
 * the reconciler, which would put it straight back on the next sweep.
 *
 * Pure, and separate from the dialog, because this is the part with a rule in
 * it - the rendering around it is obvious and this is not.
 */
export function linkDiff(
  wantSites: ReadonlySet<string>,
  wantRouters: ReadonlySet<string>,
  haveSites: readonly string[],
  haveDirect: readonly string[],
  routerSites: Readonly<Record<string, string[]>>,
  routerIDs: readonly string[],
): LinkDiff {
  const have = new Set(haveSites);
  const direct = new Set(haveDirect);
  const covered = new Set<string>();
  for (const id of routerIDs) {
    if ((routerSites[id] ?? []).some((sid) => wantSites.has(sid))) covered.add(id);
  }
  return {
    addSites: [...wantSites].filter((x) => !have.has(x)),
    dropSites: [...have].filter((x) => !wantSites.has(x)),
    addRouters: [...wantRouters].filter((x) => !direct.has(x) && !covered.has(x)),
    dropRouters: [...direct].filter((x) => !wantRouters.has(x) && !covered.has(x)),
  };
}
