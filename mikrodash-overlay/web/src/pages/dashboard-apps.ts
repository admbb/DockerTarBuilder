import { el, esc, fmtBytes } from '../dom';
import { translate } from '../language';
import type { AppUsagePayload } from '../gen/payloads';

/** Recent application usage, using the same rolling window as the Apps page. */
export function renderDashboardApps(data: AppUsagePayload): void {
  const table = el('talkersTable');
  if (!table) return;
  const apps = (data.apps || []).slice(0, 5);
  const rows = apps.map((app) => '<tr><td>' + esc(app.name || app.id) + '</td>' +
    '<td class="text-end" style="color:var(--accent-rx)">' + esc(fmtBytes(app.rxBytes)) + '</td>' +
    '<td class="text-end" style="color:var(--accent-tx)">' + esc(fmtBytes(app.txBytes)) + '</td>' +
    '<td class="text-end">' + esc(app.share.toFixed(1)) + '%</td></tr>');
  if (data.unnamedBytes > 0) rows.push('<tr><td colspan="4" class="muted-note">' +
    translate('Unidentified traffic: ', '未识别流量：') + esc(fmtBytes(data.unnamedBytes)) + '</td></tr>');
  table.innerHTML = rows.length ? rows.join('') : '<tr><td colspan="4" class="empty-state">' +
    translate('Waiting for application traffic data', '正在等待应用流量数据') + '</td></tr>';
  const period = el('dashAppsPeriod');
  if (period) {
    const mins = Math.floor(Math.max(0, data.to - data.from) / 60000);
    period.textContent = mins >= 59 ? translate('Last hour', '最近一小时') :
      mins < 2 ? translate('Last minute', '最近一分钟') : translate('Last ' + mins + ' minutes', '最近 ' + mins + ' 分钟');
  }
}

export function clearDashboardApps(): void {
  const table = el('talkersTable');
  if (table) table.innerHTML = '<tr><td colspan="4" class="empty-state">' +
    translate('Waiting for application traffic data', '正在等待应用流量数据') + '</td></tr>';
  const period = el('dashAppsPeriod');
  if (period) period.textContent = '';
}
