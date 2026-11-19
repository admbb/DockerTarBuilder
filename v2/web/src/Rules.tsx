import { useEffect, useState, type FormEvent } from "react";
import { categoryName } from "./categories";
import "./Rules.css";

type App = { id: string; name: string; category: string; icon: string };
type Rule = { id: number; domain: string; app_id: string; match: string; exclude: boolean; priority: number };
type RuleImportResult = { apps_added: number; rules_added: number; rules_skipped: number };

const emptyApp = { id: "", name: "", category: "其他", icon: "" };
const jsonHeaders = { "Content-Type": "application/json" };
const iconName = (path: string) => path.replace(/^\/icons\//, "").replace(/\.svg$/, "");

async function jsonRequest<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, init);
  if (!response.ok) {
    const data = await response.json().catch(() => null);
    throw new Error(data?.error || "请求失败");
  }
  return response.json() as Promise<T>;
}

function IconOptions({ icons }: { icons: string[] }) {
  return <>{icons.map(icon => <option key={icon} value={icon}>{iconName(icon)}</option>)}</>;
}

export default function Rules({initialDomain, onClose, onChanged}: {
  initialDomain: string;
  onClose: () => void;
  onChanged: () => void;
}) {
  const [apps, setApps] = useState<App[]>([]);
  const [rules, setRules] = useState<Rule[]>([]);
  const [icons, setIcons] = useState<string[]>([]);
  const [builtinCount, setBuiltinCount] = useState(0);
  const [domain, setDomain] = useState(initialDomain);
  const [app, setApp] = useState("");
  const [match, setMatch] = useState("suffix");
  const [priority, setPriority] = useState(100);
  const [exclude, setExclude] = useState(false);
  const [editing, setEditing] = useState<number | null>(null);
  const [newApp, setNewApp] = useState(emptyApp);
  const [iconApp, setIconApp] = useState("");
  const [iconPath, setIconPath] = useState("");
  const [svgFile, setSVGFile] = useState<File | null>(null);
  const [backupFile, setBackupFile] = useState<File | null>(null);
  const [backupInputVersion, setBackupInputVersion] = useState(0);
  const [svgInputVersion, setSVGInputVersion] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [status, setStatus] = useState("");

  async function load() {
    const [appList, ruleList, iconList] = await Promise.all([
      jsonRequest<App[]>("/api/apps"),
      jsonRequest<{ items: Rule[]; builtin_count: number }>("/api/rules"),
      jsonRequest<string[]>("/api/apps/icons"),
    ]);
    setApps(appList);
    setApp(current => appList.some(item => item.id === current) ? current : appList[0]?.id || "");
    setIconApp(current => appList.some(item => item.id === current) ? current : appList[0]?.id || "");
    setRules(ruleList.items);
    setBuiltinCount(ruleList.builtin_count);
    setIcons(iconList);
  }

  useEffect(() => {
    void load().catch(() => setError("无法读取规则，请检查服务状态"));
  }, []);

  async function mutate(action: () => Promise<string>) {
    setBusy(true);
    setError("");
    setStatus("");
    try {
      const message = await action();
      setStatus(message);
      onChanged();
      await load();
    } catch (reason) {
      setError((reason as Error).message);
    } finally {
      setBusy(false);
    }
  }

  function resetRule() {
    setEditing(null);
    setDomain("");
    setPriority(100);
    setMatch("suffix");
    setExclude(false);
  }

  function saveRule(event: FormEvent) {
    event.preventDefault();
    void mutate(async () => {
      await jsonRequest(editing === null ? "/api/rules" : `/api/rules/${editing}`, {
        method: editing === null ? "POST" : "PUT",
        headers: jsonHeaders,
        body: JSON.stringify({ domain, app_id: exclude ? "" : app, match, exclude, priority }),
      });
      resetRule();
      return "规则已保存";
    });
  }

  function removeRule(id: number) {
    void mutate(async () => {
      await jsonRequest(`/api/rules/${id}`, { method: "DELETE", headers: jsonHeaders });
      if (editing === id) resetRule();
      return "规则已删除";
    });
  }

  function addApp(event: FormEvent) {
    event.preventDefault();
    void mutate(async () => {
      const created = await jsonRequest<App>("/api/apps", {
        method: "POST", headers: jsonHeaders, body: JSON.stringify(newApp),
      });
      setApp(created.id);
      setNewApp(emptyApp);
      return "应用已添加";
    });
  }

  function importRules(event: FormEvent) {
    event.preventDefault();
    if (!backupFile) return;
    void mutate(async () => {
      if (backupFile.size > 2 * 1024 * 1024) throw new Error("规则文件不得超过 2 MiB");
      const result = await jsonRequest<RuleImportResult>("/api/rules/import", {
        method: "POST", headers: jsonHeaders, body: await backupFile.text(),
      });
      setBackupFile(null);
      setBackupInputVersion(version => version + 1);
      return `新增 ${result.rules_added} 条规则和 ${result.apps_added} 个应用，跳过 ${result.rules_skipped} 条重复规则`;
    });
  }

  function changeIcon(reset: boolean) {
    void mutate(async () => {
      if (!reset && svgFile && svgFile.size > 64 * 1024) throw new Error("SVG 文件不得超过 64 KiB");
      const change = reset ? { reset: true } : svgFile ? { svg: await svgFile.text() } : { path: iconPath };
      if ("svg" in change && !change.svg?.trim()) throw new Error("SVG 文件为空");
      await jsonRequest(`/api/apps/${encodeURIComponent(iconApp)}/icon`, {
        method: "PUT", headers: jsonHeaders, body: JSON.stringify(change),
      });
      setSVGFile(null);
      setSVGInputVersion(version => version + 1);
      return "图标已更新";
    });
  }

  const currentIcon = apps.find(item => item.id === iconApp)?.icon;

  return <div className="rule-overlay" onClick={onClose}>
    <section className="rule-modal" role="dialog" aria-modal="true" aria-label="应用识别规则" onClick={event => event.stopPropagation()}>
      <div className="panelhead">
        <div><h2>应用识别规则</h2><p>{builtinCount} 条内置规则 · {rules.length} 条人工规则</p></div>
        <button onClick={onClose}>关闭</button>
      </div>
      <form className="rule-form" onSubmit={saveRule}>
        <label>域名<input required value={domain} onChange={event => setDomain(event.target.value)} placeholder="example.com"/></label>
        <label>匹配方式<select value={match} onChange={event => setMatch(event.target.value)}>
          <option value="suffix">域名及子域名</option><option value="exact">仅此域名</option>
        </select></label>
        <label>应用<select disabled={exclude} value={app} onChange={event => setApp(event.target.value)}>
          {apps.map(item => <option key={item.id} value={item.id}>{item.name} · {categoryName(item.category)}</option>)}
        </select></label>
        <label>优先级<input type="number" min="-10000" max="10000" value={priority} onChange={event => setPriority(Number(event.target.value))}/></label>
        <label className="rule-check"><input type="checkbox" checked={exclude} onChange={event => setExclude(event.target.checked)}/>排除此域名</label>
        <button type="submit" disabled={busy || (!exclude && !app)}>{editing === null ? "添加规则" : "保存修改"}</button>
        {editing !== null && <button type="button" onClick={resetRule}>取消编辑</button>}
      </form>
      {error && <p role="alert" className="rule-error">{error}</p>}
      {status && <p role="status">{status}</p>}
      <p className="hint">优先级越高越先匹配。字节归属仍需要对应客户端的 DNS 答案与流量时间证据。</p>
      <details>
        <summary>导入和导出规则</summary>
        <form className="rule-form" onSubmit={importRules}>
          <label>备份 JSON 文件<input key={backupInputVersion} type="file" accept=".json,application/json" onChange={event => setBackupFile(event.target.files?.[0] ?? null)}/></label>
          <button type="submit" disabled={busy || !backupFile}>合并导入</button>
          <a className="rule-link" href="/api/rules/export" download>导出规则</a>
        </form>
        <p className="hint">备份包含人工规则和自定义应用。导入保留现有数据并跳过重复规则。</p>
      </details>
      <details>
        <summary>添加自定义应用</summary>
        <form className="rule-form" onSubmit={addApp}>
          <label>应用编号（小写英文、数字）<input required pattern="[a-z0-9][a-z0-9_\-]*" maxLength={64} value={newApp.id} onChange={event => setNewApp({ ...newApp, id: event.target.value })}/></label>
          <label>应用名称<input required value={newApp.name} onChange={event => setNewApp({ ...newApp, name: event.target.value })}/></label>
          <label>分类<input required value={newApp.category} onChange={event => setNewApp({ ...newApp, category: event.target.value })}/></label>
          <label>本地图标<select value={newApp.icon} onChange={event => setNewApp({ ...newApp, icon: event.target.value })}>
            <option value="">通用图标</option><IconOptions icons={icons}/>
          </select></label>
          <button type="submit" disabled={busy}>添加应用</button>
        </form>
      </details>
      <details>
        <summary>更换应用图标</summary>
        <form className="rule-form" onSubmit={event => { event.preventDefault(); changeIcon(false); }}>
          <label>应用<select value={iconApp} onChange={event => setIconApp(event.target.value)}>
            {apps.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}
          </select></label>
          {currentIcon && <span className="icon"><img src={currentIcon} alt="当前图标"/></span>}
          <label>本地图标<select value={iconPath} disabled={!!svgFile} onChange={event => setIconPath(event.target.value)}>
            <option value="">通用图标</option><IconOptions icons={icons}/>
          </select></label>
          <label>上传 SVG<input key={svgInputVersion} type="file" accept=".svg,image/svg+xml" onChange={event => setSVGFile(event.target.files?.[0] ?? null)}/></label>
          <button type="submit" disabled={busy || !iconApp}>保存图标</button>
          <button type="button" disabled={busy || !iconApp} onClick={() => changeIcon(true)}>恢复默认图标</button>
        </form>
        <p className="hint">最多 64 KiB，支持路径、圆形、矩形等基础 SVG 图形。</p>
      </details>
      <div className="rule-list">
        {rules.length === 0 ? <div className="empty">暂无人工规则</div> : rules.map(rule => <div className="rule-item" key={rule.id}>
          <div>
            <strong>{rule.domain}</strong>
            <small>{rule.match === "exact" ? "精确" : "含子域名"} · {rule.exclude ? "排除" : apps.find(item => item.id === rule.app_id)?.name || rule.app_id} · 优先级 {rule.priority}</small>
          </div>
          <div>
            <button disabled={busy} onClick={() => {
              setEditing(rule.id);
              setDomain(rule.domain);
              setApp(rule.app_id || apps[0]?.id || "");
              setMatch(rule.match);
              setExclude(rule.exclude);
              setPriority(rule.priority);
            }}>编辑</button>
            <button disabled={busy} onClick={() => removeRule(rule.id)}>删除</button>
          </div>
        </div>)}
      </div>
    </section>
  </div>;
}

