import { useEffect, useMemo, useState, type FormEvent } from "react";
import { del, get, post, put } from "../lib/api";
import { displayError, isChinese } from "../lib/i18n";
import { bytes } from "../lib/format";

type App = { id: string; name: string; category: string };
type Rule = { id: number; domain: string; match: "exact" | "suffix"; appId: string; exclude: boolean; enabled: boolean };
type HistoricalDomain = { domain: string; up: number; down: number; connections: number };
type BuiltinRule = { domain: string; match: string; appId: string; sourceVersion?: string };
type TestResult = { application: string; match: { appId?: string; domain?: string; source?: string; sourceVersion?: string; matchedBy?: string; confidence?: string; excluded?: boolean; ambiguous?: boolean } };
const empty = (): Rule => ({ id: 0, domain: "", match: "suffix", appId: "", exclude: false, enabled: true });
const t = (zh: string, en: string) => isChinese() ? zh : en;

export function DomainRules() {
  const [apps, setApps] = useState<App[]>([]);
  const [rules, setRules] = useState<Rule[]>([]);
  const [unknown, setUnknown] = useState<HistoricalDomain[]>([]);
  const [domainSearch, setDomainSearch] = useState("");
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [builtin, setBuiltin] = useState<BuiltinRule[]>([]);
  const [testResult, setTestResult] = useState<TestResult | null>(null);
  const [form, setForm] = useState<Rule>(empty);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const rankedDomains = useMemo(() => unknown.filter(item => item.domain.toLowerCase().includes(domainSearch.trim().toLowerCase())), [unknown, domainSearch]);
  const maxDomainBytes = Math.max(1, ...unknown.map(item => item.up + item.down));
  const rankedTotal = unknown.reduce((sum, item) => sum + item.up + item.down, 0);
  const refresh = async () => {
    const [a, r, u, b] = await Promise.allSettled([get<App[]>("/api/v1/domains/apps"), get<Rule[]>("/api/v1/domains/rules"), get<{items: HistoricalDomain[]}>("/api/v1/domains/unknown"), get<BuiltinRule[]>("/api/v1/domains/builtin")]);
    if (a.status === "fulfilled") setApps(a.value);
    if (r.status === "fulfilled") setRules(r.value);
    if (u.status === "fulfilled") setUnknown(u.value.items);
    if (b.status === "fulfilled") setBuiltin(b.value);
    const failed = [a, r, u, b].find(result => result.status === "rejected");
    if (failed && failed.status === "rejected") setError(t("部分数据刷新失败：", "Some data could not be refreshed: ") + displayError(String(failed.reason?.message ?? failed.reason)));
  };
  useEffect(() => { void refresh(); }, []);
  const save = async (event: FormEvent) => {
    event.preventDefault(); setBusy(true); setError("");
    try {
      if (form.id) await put(`/api/v1/domains/rules/${form.id}`, form);
      else await post("/api/v1/domains/rules", form);
      setForm(empty()); await refresh();
    } catch (e) { setError(displayError((e as Error).message)); } finally { setBusy(false); }
  };
  const remove = async (rule: Rule) => {
    if (!window.confirm(t(`确定删除规则 ${rule.domain}？`, `Delete rule ${rule.domain}?`))) return;
    setBusy(true); setError("");
    try { await del(`/api/v1/domains/rules/${rule.id}`); if (form.id === rule.id) setForm(empty()); await refresh(); }
    catch (e) { setError(displayError((e as Error).message)); } finally { setBusy(false); }
  };
  const test = async () => {
    setBusy(true); setError(""); setTestResult(null);
    try { setTestResult(await post<TestResult>("/api/v1/domains/rules/test", {domain: form.domain})); }
    catch (e) { setError(displayError((e as Error).message)); } finally { setBusy(false); }
  };
  return <div className="domain-page">
    <div className="page-head domain-heading"><div><h1 className="page-title">{t("域名流量排行", "Domain traffic ranking")}</h1>
      <p className="page-sub">{t("查看历史未归类域名的流量分布与连接情况", "Explore historical unclassified domain traffic and connections")}</p></div><button type="button" className="btn" aria-expanded={settingsOpen} onClick={() => setSettingsOpen(!settingsOpen)}>{settingsOpen ? t("收起规则设置", "Close rule settings") : t("规则与来源设置", "Rule and source settings")}</button></div>
    <div className="domain-summary"><div className="card"><div className="card-note">{t("排行流量合计", "Ranked traffic")}</div><strong>{bytes(rankedTotal)}</strong><div className="card-note">{t("最近约 7 天 · 前 50 项", "About 7 days · top 50")}</div></div><div className="card"><div className="card-note">{t("排行域名", "Ranked domains")}</div><strong>{unknown.length}</strong><div className="card-note">{t("按历史流量排序", "Ranked by historical traffic")}</div></div><div className="card"><div className="card-note">{t("流量最高的域名", "Top domain")}</div><strong className="domain-top-name">{unknown[0]?.domain ?? "—"}</strong><div className="card-note">{unknown[0] ? bytes(unknown[0].up + unknown[0].down) : t("暂无数据", "No data")}</div></div></div>
    {settingsOpen && <div className="domain-settings" id="domain-settings">
    <div className="card" style={{marginBottom: 16}}>
      <div className="card-title">{form.id ? t("编辑规则", "Edit rule") : t("添加规则", "Add rule")}</div>
      <p className="card-note">{t("候选域名未知、冲突或不完整时会保留原有目标分类。DNS 缓存只能提供推断，并非逐连接证据。", "Unknown, conflicting or incomplete candidates retain their original destination. DNS cache attribution is an inference, not per-connection proof.")}</p>
      <form onSubmit={save} style={{display:"grid",gap:12,marginTop:12}}>
        <div className="form-row">
          <label className="field" style={{flex:"2 1 220px"}}><span>{t("域名", "Domain")}</span><input className="input" value={form.domain} required placeholder="example.com" onChange={e => { setTestResult(null); setForm({...form,domain:e.target.value}); }} /></label>
          <label className="field"><span>{t("匹配方式", "Match")}</span><select className="input" value={form.match} onChange={e => setForm({...form,match:e.target.value as Rule["match"]})}><option value="suffix">{t("域名及子域名", "Domain and subdomains")}</option><option value="exact">{t("仅完整域名", "Exact domain")}</option></select></label>
          <label className="field"><span>{t("应用", "Application")}</span><select className="input" value={form.appId} required={!form.exclude} disabled={form.exclude} onChange={e => setForm({...form,appId:e.target.value})}><option value="">{t("请选择", "Select")}</option>{apps.map(a => <option key={a.id} value={a.id}>{a.name}</option>)}</select></label>
        </div>
        <div className="form-row"><label className="field inline"><input type="checkbox" checked={form.exclude} onChange={e => setForm({...form,exclude:e.target.checked})} />{t("排除此域名", "Exclude this domain")}</label><label className="field inline"><input type="checkbox" checked={form.enabled} onChange={e => setForm({...form,enabled:e.target.checked})} />{t("启用", "Enabled")}</label></div>
        {error && <div className="error-inline" role="alert">{error}</div>}
        <div className="form-row"><button className="btn primary" disabled={busy} type="submit">{t("保存", "Save")}</button><button className="btn" type="button" disabled={busy || !form.domain} onClick={test}>{t("测试当前已保存规则", "Test saved rules")}</button>{form.id > 0 && <button className="btn" type="button" onClick={() => setForm(empty())}>{t("取消编辑", "Cancel")}</button>}</div>
        {testResult && <div className="card-note" role="status">{testResult.match.excluded ? t("结果：已排除", "Result: excluded") : testResult.match.ambiguous ? t("结果：规则冲突", "Result: conflicting rules") : testResult.application ? `${t("结果", "Result")}: ${testResult.application} · ${testResult.match.source} · ${testResult.match.matchedBy}${testResult.match.sourceVersion ? " · " + testResult.match.sourceVersion : ""}` : t("结果：未匹配", "Result: no match")}<br />{t("仅测试输入的域名，不代表共享 IP 上的实际连接一定归属于该应用；未保存的表单规则不会参与测试。", "Tests only the entered domain, not actual connections on shared IPs; unsaved form values are not included.")}</div>}
      </form>
    </div>
    <div className="card" style={{marginTop:16}}><div className="card-title">{t("内置规则与来源", "Built-in rules and sources")}</div><p className="card-note">{t("当前启用的内置规则及固定来源版本。用户规则优先；尚不支持自动更新。", "Enabled built-in rules and pinned source versions. User rules take precedence; automatic updates are not yet supported.")}</p>
      {builtin.length === 0 ? <p className="card-note">{t("暂无启用的内置规则。", "No built-in rules are enabled.")}</p> : <div style={{overflowX:"auto"}}><table style={{width:"100%",textAlign:"left",marginTop:12}}><thead><tr><th>{t("域名", "Domain")}</th><th>{t("应用", "Application")}</th><th>{t("来源版本", "Source version")}</th></tr></thead><tbody>{builtin.map(item => <tr key={item.domain}><td>{item.domain}</td><td>{apps.find(a => a.id === item.appId)?.name ?? item.appId}</td><td>{item.sourceVersion}</td></tr>)}</tbody></table></div>}
    </div>
    <div className="card"><div className="card-title">{t("用户规则", "User rules")}</div>
      {rules.length === 0 ? <p className="card-note">{t("暂无用户规则。已启用少量经核验的内置规则，其余样例尚未启用。", "No user rules. A small set of verified built-in rules is enabled; the remaining examples are inactive.")}</p> :
      <div style={{overflowX:"auto"}}><table style={{width:"100%",textAlign:"left",marginTop:12}}><thead><tr><th>{t("域名", "Domain")}</th><th>{t("匹配", "Match")}</th><th>{t("应用", "Application")}</th><th>{t("状态", "Status")}</th><th>{t("操作", "Actions")}</th></tr></thead><tbody>{rules.map(r => <tr key={r.id}><td>{r.domain}</td><td>{r.match === "exact" ? t("完整域名", "Exact") : t("含子域名", "Suffix")}</td><td>{r.exclude ? t("排除", "Excluded") : (apps.find(a => a.id === r.appId)?.name ?? r.appId)}</td><td>{r.enabled ? t("已启用", "Enabled") : t("已停用", "Disabled")}</td><td><button type="button" className="btn small" onClick={() => setForm(r)}>{t("编辑", "Edit")}</button>{" "}<button type="button" className="btn small" disabled={busy} onClick={() => remove(r)}>{t("删除", "Delete")}</button></td></tr>)}</tbody></table></div>}
    </div>
    </div>}
    <div className="domain-highlights">{unknown.slice(0, 6).map((item, index) => <div className="card domain-highlight" key={item.domain}><div className="domain-highlight-head"><span className="domain-badge">{index + 1}</span><span className="mono domain-highlight-name" title={item.domain}>{item.domain}</span></div><strong>{bytes(item.up + item.down)}</strong><div className="card-note"><span className="domain-down">↓ {bytes(item.down)}</span>　<span className="domain-up">↑ {bytes(item.up)}</span></div><div className="card-note">{item.connections.toLocaleString()} {t("次连接", "connections")}</div></div>)}</div>
    <div className="card domain-ranking" style={{marginTop:16}}><div className="card-title">{t("历史未归类域名排行", "Historical unclassified domains")}</div>
      <p className="card-note">{t("最近约 7 天、按小时汇总的域名目的地，最多显示 50 项。历史记录不会因新规则重新分类；这里是归并后的域名，不是完整 DNS 查询记录。", "Up to 50 domain destinations from approximately the last 7 days, aggregated hourly. New rules do not reclassify history; names are grouped domains, not a complete DNS query log.")}</p>
      <label className="field" style={{marginTop:12,maxWidth:360}}><span>{t("搜索排行中的域名", "Search ranked domains")}</span><input className="input" type="search" value={domainSearch} onChange={e => setDomainSearch(e.target.value)} placeholder={t("输入域名", "Enter a domain")} /></label>
      {rankedDomains.length === 0 ? <p className="card-note">{unknown.length ? t("没有匹配的域名。", "No matching domains.") : t("暂无历史域名流量。", "No historical domain traffic.")}</p> :
        <div style={{overflowX:"auto"}}><table className="tbl" style={{width:"100%",marginTop:12}}><thead><tr><th>{t("排名 / 域名", "Rank / domain")}</th><th>{t("流量分布", "Traffic")}</th><th className="num">{t("下载", "Download")}</th><th className="num">{t("上传", "Upload")}</th><th className="num">{t("连接数", "Connections")}</th><th>{t("操作", "Action")}</th></tr></thead><tbody>{rankedDomains.map(item => { const total = item.up + item.down; const originalRank = unknown.indexOf(item) + 1; return <tr key={item.domain}><td><span className="dim">{originalRank}. </span><span className="mono">{item.domain}</span></td><td><span className="rank-track" aria-label={`${t("下载", "Download")}: ${bytes(item.down)}, ${t("上传", "Upload")}: ${bytes(item.up)}`}><span className="rank-bar" style={{width: `${Math.max(total ? 1.5 : 0, total / maxDomainBytes * 100)}%`}}><span className="rank-seg down" style={{flexBasis: `${total ? item.down / total * 100 : 0}%`}} /><span className="rank-seg up" style={{flexBasis: `${total ? item.up / total * 100 : 0}%`}} /></span></span><span className="dim">{bytes(total)}</span></td><td className="num">{bytes(item.down)}</td><td className="num">{bytes(item.up)}</td><td className="num">{item.connections.toLocaleString()}</td><td><button className="btn small" type="button" onClick={() => { setForm({...empty(),domain:item.domain}); setSettingsOpen(true); window.setTimeout(() => document.getElementById("domain-settings")?.scrollIntoView({behavior:"smooth"}), 0); }}>{t("添加规则", "Add rule")}</button></td></tr>; })}</tbody></table></div>}
    </div>
  </div>;
}
