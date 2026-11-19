import { useEffect, useId, useState } from "react";
import { categoryName } from "./categories";

type Count = { bytes: number; up: number; down: number; records: number };
type Entry = Count & { id: string; name: string; category: string; icon: string };
type Point = { start_ms: number; end_ms: number; observed: Count; attributed: Count; unknown: Count; selected: Count };
type ViewData = {
  items: Entry[];
  observed: Count;
  attributed: Count;
  unknown: Count;
  unknown_reasons: Record<string, Count>;
  attribution_enabled: boolean;
  app?: Entry;
  points?: Point[];
};
type Device = { ip: string; up: number; down: number };
type View = "apps" | "categories" | "trend" | "devices";
const format = (n: number) => n >= 1e9 ? (n / 1e9).toFixed(2) + " GB" : n >= 1e6 ? (n / 1e6).toFixed(1) + " MB" : n >= 1e3 ? (n / 1e3).toFixed(1) + " KB" : n + " B";
const dateTime = (value: number) => new Date(value).toLocaleString("zh-CN", { hour12: false });
const views: [View, string][] = [["apps", "应用排行"], ["categories", "分类排行"], ["trend", "流量趋势"], ["devices", "设备排行"]];
const reasons: Record<string, string> = {
  dns_completeness_unverified: "DNS 数据完整性尚未验证",
  outside_verified_dns_interval: "流量超出可信 DNS 区间",
  flow_time_unreliable: "流量时间不可靠",
  unsupported_flow_protocol: "此协议不支持 DNS 归属",
  application_missing: "缺少对应的应用",
  dns_rescan_pending: "DNS 二次扫描未稳定或流量超出稳定区间",
  no_matching_dns: "缺少可匹配的 DNS 证据",
  ambiguous_or_unknown: "多个应用或未识别域名共用地址",
  dns_segment_not_covered: "DNS 有效期未覆盖整个流段",
  dns_evidence_limit: "匹配证据达到处理上限",
  dns_stability_changed: "匹配时 DNS 稳定区间发生变化",
};

function Trend({ points, app }: { points: Point[]; app: boolean }) {
  const [selected, setSelected] = useState(0);
  const index = Math.min(selected, points.length - 1);
  const point = points[index];
  if (!point) return null;
  const max = Math.max(1, ...points.map(p => app ? p.selected.bytes : p.observed.bytes));
  return <figure className="traffic-trend">
    <figcaption>{app ? "应用推断字节" : "已观察字节"} · {dateTime(point.start_ms)} 至 {dateTime(point.end_ms)}</figcaption>
    <div className="trend-bars">
      {points.map((p, i) => <button type="button" key={p.start_ms} onClick={() => setSelected(i)}
        aria-pressed={i === index} aria-label={dateTime(p.start_ms) + " " + format(app ? p.selected.bytes : p.observed.bytes)}>
        <i style={{ height: ((app ? p.selected.bytes : p.observed.bytes) / max * 100) + "%" }} />
      </button>)}
    </div>
    <p className="hint">{app
      ? "下载 " + format(point.selected.down) + " · 上传 " + format(point.selected.up)
      : "已观察 " + format(point.observed.bytes) + " · 已归属 " + format(point.attributed.bytes) + " · 未知 " + format(point.unknown.bytes)}</p>
  </figure>;
}

export default function Traffic({ query, revision }: { query: string; revision: number }) {
  const [view, setView] = useState<View>("apps");
  const [category, setCategory] = useState("");
  const [device, setDevice] = useState("");
  const [appID, setAppID] = useState("");
  const [deviceResult, setDeviceResult] = useState<{ query: string; items?: Device[]; error?: string }>();
  const devices = deviceResult?.query === query ? deviceResult.items ?? [] : [];
  const [result, setResult] = useState<{ key: string; data?: ViewData; error?: string }>();
  const deviceID = useId();
  const params = new URLSearchParams(query);
  if (device) params.set("device", device);
  if (category && view === "apps") params.set("category", category);
  params.set("metric", "bytes");
  const endpoint = appID ? "/api/apps/" + encodeURIComponent(appID) + "/traffic" : view === "categories" ? "/api/categories" : view === "trend" ? "/api/traffic/trend" : "/api/apps/top";
  const url = endpoint + "?" + params;
  const key = url + "#" + revision;

  useEffect(() => {
    const controller = new AbortController();
    fetch("/api/traffic/devices?" + query, { signal: controller.signal })
      .then(async r => {
        if (!r.ok) {
          if (!controller.signal.aborted) setDeviceResult({ query, error: r.status === 422 ? "独立 IPFIX 采集器未启用" : "设备流量暂不可用" });
          return;
        }
        const payload = await r.json() as { items: Device[] };
        if (!controller.signal.aborted) setDeviceResult({ query, items: payload.items });
      })
      .catch(() => { if (!controller.signal.aborted) setDeviceResult({ query, error: "设备流量暂不可用" }); });
    return () => controller.abort();
  }, [query, revision]);

  useEffect(() => {
    if (view === "devices") return;
    const controller = new AbortController();
    const load = async () => {
      try {
        const r = await fetch(url, { signal: controller.signal });
        if (!r.ok) {
          if (!controller.signal.aborted) setResult({ key, error: r.status === 422 ? "独立 IPFIX 采集器未启用" : "应用流量暂不可用" });
          return;
        }
        const data = await r.json() as ViewData;
        if (!controller.signal.aborted) setResult({ key, data });
      } catch (err) {
        if (!controller.signal.aborted) setResult({ key, error: "应用流量暂不可用" });
      }
    };
    void load();
    const timer = window.setInterval(load, 30000);
    return () => { controller.abort(); window.clearInterval(timer); };
  }, [url, key, view]);

  const current = view !== "devices" && result?.key === key ? result : undefined;
  const data = current?.data;
  return <section className="panel device-panel">
    <div className="panelhead">
      <div><h2>应用流量</h2><p>V2 独立 IPFIX 按接收时间汇总，应用字节根据 DNS 证据推断</p></div>
      <label className="device-filter" htmlFor={deviceID}>设备 <select id={deviceID} value={device} onChange={e => setDevice(e.target.value)}>
        <option value="">全部设备</option>
        {device && !devices.some(d => d.ip === device) && <option value={device}>{device}</option>}
        {devices.map(d => <option key={d.ip} value={d.ip}>{d.ip} · {format(d.up + d.down)}</option>)}
      </select></label>
    </div>
    <div className="traffic-tabs">
      {views.map(([name, label]) => <button key={name} type="button" aria-pressed={name === view && !appID}
        onClick={() => { setView(name); setAppID(""); if (name !== "apps") setCategory(""); }}>{label}</button>)}
      {category && view === "apps" && <button type="button" onClick={() => setCategory("")}>{categoryName(category)} ×</button>}
      {appID && <button type="button" onClick={() => setAppID("")}>返回排行</button>}
    </div>
    {view === "devices" && <div>
      <p className="hint">按 IPFIX 观察字节排序，流量覆盖可能不完整。选择设备可查看该设备的应用排行。</p>
      {devices.length ? <div className="ranking">{devices.map(d => <button type="button" className="row traffic-row" key={d.ip}
        onClick={() => { setDevice(d.ip); setView("apps"); }}>
        <span className="app-name"><strong>{d.ip}</strong><small>下载 {format(d.down)} · 上传 {format(d.up)}</small></span>
        <span className="amount"><strong>{format(d.down + d.up)}</strong><small>已观察</small></span>
      </button>)}</div> : <p className="empty" role="status">{deviceResult?.query !== query ? "正在读取设备流量" : deviceResult.error ?? "此时段暂无设备流量"}</p>}
    </div>}
    {!current && view !== "devices" && <p className="empty" role="status">正在读取流量</p>}
    {current?.error && <p className="empty" role="status">{current.error}</p>}
    {data && <>
      <p className="hint">已观察 {format(data.observed.bytes)} · 已归属 {format(data.attributed.bytes)} · 未知 {format(data.unknown.bytes)}。流量覆盖可能不完整。{!data.attribution_enabled && " 暂无已稳定的 DNS 记录器区间。"}</p>
      {Object.keys(data.unknown_reasons).length > 0 && <details className="hint"><summary>查看未知流量原因</summary>
        <ul>{Object.entries(data.unknown_reasons).sort((a, b) => b[1].bytes - a[1].bytes).map(([reason, count]) =>
          <li key={reason} title={reason}>{reasons[reason] ?? "其他未归属流量"} · {format(count.bytes)}</li>)}</ul>
      </details>}
      {data.app && <div className="traffic-app">
        <h3>{data.app.name} <small>{categoryName(data.app.category)}</small></h3>
        <p>推断流量 {format(data.app.bytes)} · 下载 {format(data.app.down)} · 上传 {format(data.app.up)} · {data.app.records.toLocaleString("zh-CN")} 条记录</p>
      </div>}
      {data.points && <Trend key={key} points={data.points} app={Boolean(data.app)} />}
      {!data.points && (data.items.length ? <div className="ranking">{data.items.map(a => <button type="button" className="row traffic-row" key={a.id}
        onClick={() => view === "categories" ? (setCategory(a.id), setView("apps")) : setAppID(a.id)}>
        {a.icon && <span className="icon"><img src={a.icon} alt="" /></span>}
        <span className="app-name"><strong>{view === "categories" ? categoryName(a.category) : a.name}</strong>
          <small>{view !== "categories" && categoryName(a.category) + " · "}下载 {format(a.down)} · 上传 {format(a.up)}</small>
          <span className="bar"><i style={{ width: a.bytes / Math.max(1, data.observed.bytes) * 100 + "%" }} /></span></span>
        <span className="amount"><strong>{format(a.bytes)}</strong><small>DNS 推断</small></span>
      </button>)}</div> : <p className="empty">暂无具备可靠证据的应用流量</p>)}
    </>}
  </section>;
}



