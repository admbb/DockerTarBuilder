// The Deploy tab's markup, as pure functions: the router picker, the settings
// grid, each router's preview, and the rollout's tiles.

import { esc } from '../dom';
import { translate, translateLabel } from '../language';
import type { CfgDeployPayload, CfgDeployTarget } from '../gen/payloads';
import { findingRow, highlight } from './config-management-cards';
import type { VarDef } from './config-management-editor';

export interface RouterOpt { id: string; label: string; host?: string; model?: string; siteIds?: string[] }

export interface Finding { level: string; code: string; line?: number; message: string }

/** What one router's preview answered (POST …/preview). */
export interface RouterPreview {
  routerId: string;
  error?: string;
  fields?: Record<string, string>;
  hash?: string;
  rendered?: string;
  findings?: Finding[];
  lockClass?: boolean;
  target?: { board: string; serial: string; osVersion: string };
}

/** A finding's key, as the server's cfgdeploy.FindingKey writes it. */
export const findingKey = (f: Finding): string => f.code + '@' + (f.line ?? 0);

/** A fresh password for a secret setting: 20 letters and digits from the
 *  browser's CSPRNG. A secret has no default on purpose (one would be the
 *  same on every install), so the Deploy tab fills it with one of these. */
export function newSecret(): string {
  const abc = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  const out: string[] = [];
  // Rejection sampling: only bytes below the largest multiple of the alphabet
  // are used, so no letter is likelier than another.
  const limit = 256 - (256 % abc.length);
  while (out.length < 20) {
    for (const b of crypto.getRandomValues(new Uint8Array(32))) {
      if (b < limit && out.length < 20) out.push(abc[b % abc.length] as string);
    }
  }
  return out.join('');
}

/** The template's settings with these values as their defaults: what "Save
 *  these settings as the template's defaults" stores. A secret keeps no
 *  default, since it would be stored with the template. */
export function defaultsFromValues(defs: VarDef[], values: Record<string, string>): VarDef[] {
  return defs.map((d) => {
    if (d.type === 'secret') return { ...d, default: undefined };
    const v = (values[d.name] ?? '').trim();
    return { ...d, default: v || undefined };
  });
}

/** The settings grid: a row per router, a column per setting, and a first row
 *  that fills them all. Passwords are hidden unless `reveal`. */
export function valuesGrid(defs: VarDef[], routers: RouterOpt[], values: Record<string, Record<string, string>>,
  reveal = false): string {
  if (!defs.length) return '<div class="cfg-meta">' + translate('This template asks for no settings.', '此模板无需设置。') + '</div>';
  if (!routers.length) return '<div class="cfg-meta">' + translate('Pick routers first.', '请先选择路由器。') + '</div>';
  const kind = (d: VarDef): string => (d.type === 'secret' && !reveal ? 'password' : 'text');
  const secrets = defs.some((d) => d.type === 'secret');
  const cell = (rid: string, d: VarDef): string => {
    const v = values[rid]?.[d.name] ?? (d.type === 'secret' ? '' : d.default ?? '');
    return '<td><input class="sform-input" data-dep-val="' + esc(rid) + '" data-dep-var="' +
      esc(d.name) + '" type="' + kind(d) + '" value="' + esc(v) + '" placeholder="' + esc(d.type) + '" autocomplete="off"></td>';
  };
  return (secrets ? '<label class="cfg-reveal"><input type="checkbox" data-dep-reveal' + (reveal ? ' checked' : '') +
    '> Show passwords <span class="cfg-meta">(each was generated for this deploy; change it, or note it for ' +
    'whatever will use it)</span></label>' : '') +
    '<div class="cfg-scroll"><table class="table cfg-grid-vals"><thead><tr><th>Router</th>' +
    defs.map((d) => '<th><span class="cfg-var">{{' + esc(d.name) + '}}</span>' +
      (d.label ? '<div class="cfg-meta">' + esc(d.label) + '</div>' : '') + '</th>').join('') +
    '</tr></thead><tbody><tr class="cfg-grid-all"><td>All routers</td>' +
    defs.map((d) => '<td><input class="sform-input" data-dep-all-var="' + esc(d.name) + '" type="' +
      kind(d) + '" placeholder="fill every row" autocomplete="off"></td>').join('') +
    '</tr>' + routers.map((r) => '<tr><td>' + esc(r.label) + '</td>' + defs.map((d) => cell(r.id, d)).join('') + '</tr>').join('') +
    '</tbody></table></div>';
}

/** One router's preview: its identity, the checks (an OK box for each that
 *  needs one), and the text it would receive. */
export function previewCard(label: string, p: RouterPreview, acked: Set<string>): string {
  if (p.error) {
    const fields = p.fields ? Object.entries(p.fields).map(([k, v]) => '<li><span class="cfg-var">{{' + esc(k) + '}}</span> ' +
      esc(v) + '</li>').join('') : '';
    return '<div class="cfg-prev is-bad"><div class="cfg-prev-head"><strong>' + esc(label) + '</strong>' +
      '<span class="pill pill-err">Cannot deploy</span></div><div class="cfg-prev-msg">' + esc(p.error) +
      '</div>' + (fields ? '<ul class="cfg-prev-fields">' + fields + '</ul>' : '') + '</div>';
  }
  const findings = p.findings ?? [];
  const refused = findings.some((f) => f.level === 'refuse');
  // One OK per key: an acknowledgement is of a code on a line, so two findings
  // sharing both (source= and policy= on one script line) are one tick. Two
  // boxes on one key fought: unticking either cleared the other's.
  const msgs = new Map<string, string[]>();
  for (const f of findings) {
    if (f.level !== 'ack') continue;
    const k = findingKey(f);
    if (msgs.has(k)) msgs.get(k)!.push(f.message);
    else msgs.set(k, [f.message]);
  }
  const checks = findings.map((f) => {
    if (f.level !== 'ack') return findingRow(f);
    const k = findingKey(f);
    const all = msgs.get(k);
    if (!all) return '';
    msgs.delete(k);
    const key = p.routerId + '|' + k;
    return '<li class="cfg-finding cfg-lvl-ack"><label class="cfg-ack"><input type="checkbox" data-dep-ack="' +
      esc(p.routerId) + '" data-key="' + esc(k) + '"' + (acked.has(key) ? ' checked' : '') + '> OK</label>' +
      '<span class="cfg-meta">line ' + (f.line ?? 0) + '</span><span class="cfg-finding-msg">' +
      all.map(esc).join('<br>') + '</span></li>';
  }).join('');
  const t = p.target;
  return '<div class="cfg-prev' + (refused ? ' is-bad' : '') + '"><div class="cfg-prev-head"><strong>' + esc(label) + '</strong>' +
    (t ? '<span class="cfg-meta">' + esc(t.board) + ' · RouterOS ' + esc(t.osVersion) + '</span>' : '') +
    (p.lockClass ? '<span class="pill pill-warn">' + translate('Auto-revert armed', '已启用自动回滚') + '</span>' : '') +
    (refused ? '<span class="pill pill-err">' + translate('Refused', '已拒绝') + '</span>' : '') + '</div>' +
    (findings.length ? '<ul class="cfg-findings">' + checks + '</ul>' : '<div class="cfg-meta">Nothing to flag.</div>') +
    '<details class="cfg-prev-text"><summary>What this router will receive</summary><pre class="cfg-code md-ros">' +
    highlight(p.rendered ?? '') + '</pre></details></div>';
}

/** Why the deploy may not start yet, or '' when it may: every router previewed,
 *  nothing refused, every acknowledgement ticked. */
export function readyToStart(ids: string[], previews: Record<string, RouterPreview>, acked: Set<string>): string {
  if (!ids.length) return translate('Pick at least one router', '请至少选择一台路由器');
  for (const id of ids) {
    const p = previews[id];
    if (!p || !p.hash) return p?.error ? translate('A router cannot take this template', '某台路由器无法应用此模板') : translate('Preview every router first', '请先预览每台路由器的配置');
    for (const f of p.findings ?? []) {
      if (f.level === 'refuse') return translate('A check refuses this template on a router', '某台路由器的检查拒绝了此模板');
      if (f.level === 'ack' && !acked.has(id + '|' + findingKey(f))) return translate('Tick OK on every check that needs it', '请勾选所有需要确认的检查项');
    }
  }
  return '';
}

const TILE: Record<string, { cls: string; word: string }> = {
  pending: { cls: 'is-queued', word: 'Waiting' },
  applying: { cls: 'is-active', word: 'Working' },
  applied: { cls: 'is-ok', word: 'Applied' },
  failed: { cls: 'is-bad', word: 'Failed' },
  'failed-partial': { cls: 'is-part', word: 'Partly applied' },
  unknown: { cls: 'is-part', word: 'Unknown' },
  'preflight-failed': { cls: 'is-bad', word: 'Not started' },
  'not-attempted': { cls: 'is-skip', word: 'Skipped' },
};

const STEP: Record<string, string> = {
  sweep: 'Tidying old files', backup: 'Taking a restore point', upload: 'Uploading', 'dry-run': 'Checking syntax on the router',
  recheck: 'Checking nothing moved', arm: 'Arming the auto-revert', import: 'Applying', reconnect: 'Logging in afresh',
  disarm: 'Disarming the auto-revert', baseline: 'Recording the baseline', reverting: 'Waiting for the revert',
  reset: 'Resetting', reboot: 'Waiting for the reboot',
};

/** One router in the rollout. */
export function deployTile(t: CfgDeployTarget): string {
  const k = TILE[t.state] ?? { cls: 'is-queued', word: t.state };
  const detail = t.state === 'applying' ? translateLabel(STEP[t.step] ?? t.step)
    : t.message || (t.state === 'applied' && t.reconnectMs ? 'Back in ' + (t.reconnectMs / 1000).toFixed(1) + ' s' : '');
  return '<div class="cfg-tile ' + k.cls + '"><div class="cfg-tile-ring"></div><div class="cfg-tile-body">' +
    '<div class="cfg-tile-name">' + esc(t.label) + (t.canary ? '<span class="pill pill-alt">' + translate('Canary', '先行设备') + '</span>' : '') +
    '</div><div class="cfg-tile-state">' + esc(translateLabel(k.word)) + (t.reverted ? translate(' · reverted', ' · 已回滚') : '') + '</div>' +
    (detail ? '<div class="cfg-tile-detail">' + esc(detail) + '</div>' : '') +
    (t.backupId ? '<div class="cfg-meta">Restore point #' + t.backupId + '</div>' : '') + '</div></div>';
}

const RUN_WORD: Record<string, string> = {
  canary: 'Deploying to the canary', 'awaiting-canary': 'The canary is done: your call', rolling: 'Rolling out',
  done: 'Deployed', halted: 'Stopped', cancelled: 'Cancelled', interrupted: 'Interrupted by a restart',
};

/** The rollout: a headline, the decision the canary needs, and the tiles. */
export function rolloutView(p: CfgDeployPayload): string {
  if (!p.runId) return '';
  const live = p.state === 'canary' || p.state === 'rolling' || p.state === 'awaiting-canary';
  const ask = p.state === 'awaiting-canary'
    ? '<div class="cfg-decide"><span>' + translate('Check the canary, then type ', '请检查先行设备，然后输入 ') + '<strong>' + p.targets.length +
      '</strong>' + translate(' to deploy to every router.', ' 以部署到所有路由器。') + '</span><input class="sform-input sform-sm" id="cfgDepCount" ' +
      'autocomplete="off" placeholder="' + p.targets.length + '"><button class="sbtn sbtn-primary is-sm" type="button" ' +
      'id="cfgDepContinue">' + translate('Continue', '继续') + '</button></div>'
    : '';
  const reset = p.kind === 'full-export'
    ? '<div class="cfg-banner is-warn">' + translate(
      'A full replacement resets each router and reboots it; MikroDash cannot see it until it returns.',
      '完整替换会重置并重启每台路由器；在路由器恢复连接前，MikroDash 无法访问它。') + '</div>'
    : '';
  return '<div class="cfg-roll-head state-' + esc(p.state) + '"><div><div class="cfg-roll-title">' +
    esc(translateLabel(RUN_WORD[p.state] ?? p.state)) + '</div><div class="cfg-meta">' + esc(p.templateName) + translate(' · started by ', ' · 发起人：') +
    esc(p.startedBy) + '</div></div>' + (live ? '<button class="sbtn sbtn-outline is-sm" type="button" id="cfgDepCancel">Cancel</button>' : '') +
    '</div>' + (p.error ? '<div class="cfg-banner is-bad">' + esc(p.error) + '</div>' : '') + reset + ask +
    '<div class="cfg-tiles">' + p.targets.map(deployTile).join('') + '</div>';
}
