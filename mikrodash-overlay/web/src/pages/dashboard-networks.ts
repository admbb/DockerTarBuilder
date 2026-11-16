// The Dashboard's Networks card: the internet-facing interfaces, and the LAN
// networks with their gateway, DNS and lease count.
//
// ── THIS IS ONE HALF OF A CROSS-PAGE HANDLER ────────────────────────────────
//
// The live `lan:overview` handler draws THREE things: this card, the DHCP page's
// subnet table, and its pool gauge. The DHCP half is already ported - it lives
// in `pages/dhcp.ts` with its own subscription - so only the Dashboard half is
// here. Two subscriptions to one event, which is what the live app effectively
// has: it registers a second `lan:overview` handler further down the file.
//
// ── TWO THINGS IN THE ORIGINAL ARE NOT REPRODUCED, DELIBERATELY ─────────────
//
// `ndLanCidr` and `ndGateway`: the handler writes both behind `if(el)` guards,
// and NO ELEMENT WITH EITHER ID EXISTS anywhere in the live markup - not in
// `index.html`, not in `public/js/`. They are dead writes, and the comment above
// them ("other consumers ... on other pages") describes pages that no longer
// carry them. Porting them would carry a dead branch across.
//
// `lastLanData`: assigned at three sites and READ AT NONE. It is left over from
// the fix its own comment describes - the empty-payload guard that used to skip
// renders was removed, and the variable it keyed on was not. The BEHAVIOUR that
// fix produced is reproduced exactly; the vestigial variable is not.
//
// ── AN EMPTY PAYLOAD IS NEWS, NOT SILENCE ───────────────────────────────────
//
// That is the rule those two findings surround, and it is the card's only
// interesting one: no networks means the card says so and RETURNS, rather than
// leaving the previous render - which after a router switch would be the
// previous ROUTER's networks, sitting under the new one's name indefinitely.

import { esc, el } from '../dom';
import { translate } from '../language';
import type { LanPayload, WANPayload } from '../gen/payloads';

/** The live app's `DOT`, a middle dot separator. */
const DOT = '·';

/** Render the same selected uplinks as the WAN page. */
export function renderNetworkWan(data: WANPayload): void {
  const host = el('netInternetIfaces');
  if (!host) return;
  const ifaces = data.wans || [];
  if (!ifaces.length && (data.denied || !data.available)) {
    host.innerHTML = '<div class="empty-state">' + translate('WAN information is unavailable', '无法获取 WAN 接口信息') + '</div>';
    return;
  }
  host.innerHTML = ifaces.length
    ? '<div style="display:grid;grid-template-columns:1fr 1fr;gap:.25rem">' + ifaces.map((f) =>
      '<div class="net-wan-row"><div class="net-field-label">' + esc(f.name) + '</div>' +
      '<div class="net-field-val">' + esc((f.address || '').split('/')[0] || '-') + '</div></div>').join('') + '</div>'
    : '<div class="empty-state">' + translate('No WAN interfaces selected or detected', '未选择或检测到 WAN 接口') + '</div>';
}

export function clearNetworkWan(): void {
  const host = el('netInternetIfaces');
  if (host) host.textContent = translate('Waiting for WAN data…', '正在等待 WAN 数据…');
}

export function renderNetworks(data: LanPayload): void {
  const nets = (data && data.networks) ? data.networks : [];
  const lanOverview = el('lanOverview');
  if (!lanOverview) return;
  if (!nets.length) {
    lanOverview.innerHTML = '<div class="empty-state">No DHCP networks</div>';
    return;
  }
  lanOverview.innerHTML = nets.map((n) =>
    '<div class="lan-net"><div class="lan-cidr">' +
      '<span style="color:var(--text-muted);font-size:.65rem;margin-right:.3rem">LAN:</span>' +
      esc(n.cidr) + '</div>' +
    '<div class="lan-meta">GW: ' + esc(n.gateway || '-') + ' ' + DOT +
      ' DNS: ' + esc(n.dns || '-') + ' ' + DOT +
      ' <strong style="color:rgb(from var(--text-main) r g b / .75)">' + n.leaseCount + '</strong> leases</div></div>').join('');
}
