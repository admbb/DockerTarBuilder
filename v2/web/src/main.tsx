import { categoryName } from "./categories";
import { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";
import Rules from "./Rules";
import Traffic from "./Traffic";
type Summary={range:string;dns_coverage_start_ms:number;dns_synced_until_ms:number;app_traffic_available:boolean;traffic?:{up:number;down:number;conns:number};traffic_error?:string;v2_flow?:{up:number;down:number;records:number};v2_flow_note?:string};
type App={id:string;name:string;category:string;icon:string;queries:number};
type Top={items:App[];unknown_queries:number;truncated_domains:boolean;note:string};
type Domain={domain:string;queries:number;devices:number};
type Unknown={items:Domain[];truncated_domains:boolean};
type Device={id:number;name:string;ips:string[];up:number;down:number};
const bytes=(n:number)=>{if(n>=1e9)return (n/1e9).toFixed(2)+" GB";if(n>=1e6)return(n/1e6).toFixed(1)+" MB";if(n>=1e3)return(n/1e3).toFixed(1)+" KB";return n+" B"};
const localInput=(value:Date)=>new Date(value.getTime()-value.getTimezoneOffset()*60000).toISOString().slice(0,16);
function Dashboard(){
 const [customOpen,setCustomOpen]=useState(false);
 const [customBounds,setCustomBounds]=useState<{from:number;to:number}>();
 const [customFrom,setCustomFrom]=useState(()=>localInput(new Date(Date.now()-86400000)));
 const [customTo,setCustomTo]=useState(()=>localInput(new Date()));
 const [customError,setCustomError]=useState("");
 const [range,setRange]=useState("24h"),[summary,setSummary]=useState<Summary|null>(null),[top,setTop]=useState<Top|null>(null),[unknown,setUnknown]=useState<Unknown|null>(null),[error,setError]=useState(""),[search,setSearch]=useState(""),[light,setLight]=useState(false),[devices,setDevices]=useState<Device[]>([]),[rulesOpen,setRulesOpen]=useState(false),[ruleDomain,setRuleDomain]=useState(""),[revision,setRevision]=useState(0);
 const query=range==="custom"&&customBounds ? 'range=custom&from_ms='+customBounds.from+'&to_ms='+customBounds.to : 'range='+range;
 useEffect(()=>{let live=true;const load=async()=>{try{const req=async<T,>(path:string)=>{const r=await fetch(path,{credentials:"same-origin"});if(!r.ok)throw new Error(`HTTP ${r.status}`);return r.json() as Promise<T>};const q="?"+query;const [s,t,u]=await Promise.all([req<Summary>(`/api/summary${q}`),req<Top>(`/api/apps/top${q}&metric=dns&limit=100`),req<Unknown>(`/api/unknown${q}`)]);if(live){setSummary(s);setTop(t);setUnknown(u);setError("")} if(range==="custom"){if(live)setDevices([]);return} try { const d=await req<{items:Device[]}>(`/api/devices/top${q}&limit=10`); if(live)setDevices(d.items); } catch { if(live)setDevices([]); }}catch(e){if(live)setError((e as Error).message)}};void load();const timer=window.setInterval(load,30000);return()=>{live=false;window.clearInterval(timer)}},[query,range,revision]);
 const items=useMemo(()=>top?.items.filter(x=>x.name.toLowerCase().includes(search.toLowerCase()))??[],[top,search]);const max=Math.max(1,...items.map(x=>x.queries));
 return <div className={light?"app light":"app"}><header><div className="brand"><div className="mark">N</div><div><strong>NetFlow <span>V2</span></strong><small>家庭网络观察台</small></div></div><div className="header-actions"><span className="status"><i/>独立分析服务</span><button className="theme" onClick={()=>{setRuleDomain("");setRulesOpen(true)}}>识别规则</button><button className="theme" onClick={()=>setLight(!light)}>{light?"深色":"浅色"}</button></div></header><main><div className="intro"><div><h1>让网络活动，一目了然</h1><p>查看真实流量汇总与 DNS 应用访问热度</p></div><div className="period">{[["1h","1 小时"],["24h","24 小时"],["7d","7 天"],["30d","30 天"]].map(([id,label])=><button key={id} className={range===id?"selected":""} onClick={()=>{setRange(id);setCustomOpen(false)}}>{label}</button>)}
 <button className={customOpen?"selected":""} aria-expanded={customOpen} onClick={()=>setCustomOpen(!customOpen)}>自定义</button></div></div>
 {customOpen&&<form className="custom-period" onSubmit={e=>{
  e.preventDefault();
  const from=new Date(customFrom).getTime(),to=new Date(customTo).getTime();
  if(!Number.isFinite(from)||!Number.isFinite(to)||to<=from||to>Date.now()||to-from>30*86400000){setCustomError("请输入有效的起止时间，最多 30 天，且不能晚于当前时间。");return}
  setCustomError("");setCustomBounds({from,to});setRange("custom");
 }}>
  <label>开始 <input type="datetime-local" required value={customFrom} onChange={e=>setCustomFrom(e.target.value)}/></label>
  <label>结束 <input type="datetime-local" required value={customTo} onChange={e=>setCustomTo(e.target.value)}/></label>
  <button className="theme" type="submit">应用时间范围</button>
  {customError&&<p className="rule-error" role="alert">{customError}</p>}
 </form>}
 {error&&<div className="notice error">数据暂不可用：{error}。请检查凭据与服务状态。</div>}
 <div className="notice"><b>数据口径</b><span>DNS 查询次数表示访问热度，不代表流量。应用归属需要可靠 DNS 证据，未验证时流量会显示为无法归属。{summary?.v2_flow && ` V2 独立 IPFIX 按接收时间统计：下载 ${bytes(summary.v2_flow.down)}，上传 ${bytes(summary.v2_flow.up)}；覆盖可能不完整。`}</span></div>
 <section className="metrics"><article><small>总流量 · NetFlow</small><strong>{summary?.traffic?bytes(summary.traffic.up+summary.traffic.down):"—"}</strong><p>{summary?.traffic?"现有采集器汇总":range==="custom"?"NetFlow Plus 总量仅支持预设时间":"未连接或数据不可用"}</p></article><article><small>下载 / 上传</small><strong className="metric-split">{summary?.traffic?bytes(summary.traffic.down):"—"} <em>/</em> {summary?.traffic?bytes(summary.traffic.up):"—"}</strong><p>所选时间范围</p></article><article><small>应用字节归属</small><strong>{summary?.app_traffic_available?"查看下方":"尚未启用"}</strong><p>未验证的流量保留为未知</p></article><article><small>DNS 同步进度</small><strong className="metric-split">{summary?.dns_synced_until_ms?new Date(summary.dns_synced_until_ms).toLocaleString("zh-CN"):"尚未同步"}</strong><p>已扫描范围；不保证上游历史完整</p></article></section>
 <Traffic query={query} revision={revision}/><div className="columns"><section className="panel"><div className="panelhead"><div><h2>应用访问热度</h2><p>按小时汇总的 DNS 查询次数排序，并非应用流量</p></div><input value={search} onChange={e=>setSearch(e.target.value)} placeholder="搜索应用" aria-label="搜索应用"/></div>{top?.truncated_domains&&<p className="hint">域名超过查询上限，当前热度统计可能不完整。</p>}{items.length===0?<div className="empty">暂无可展示的已识别查询记录</div>:<div className="ranking">{items.map((a,i)=><div className="row" key={a.id}><span className="number">{String(i+1).padStart(2,"0")}</span><span className="icon">{a.icon?<img src={a.icon} alt=""/>:<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" strokeWidth="1.5"><rect x="3" y="3" width="7" height="7" rx="2"/><rect x="14" y="3" width="7" height="7" rx="2"/><rect x="3" y="14" width="7" height="7" rx="2"/><rect x="14" y="14" width="7" height="7" rx="2"/></svg>}</span><div className="app-name"><strong>{a.name}</strong><small>{categoryName(a.category)}</small><div className="bar"><i style={{width:`${a.queries/max*100}%`}}/></div></div><div className="amount"><strong>{a.queries.toLocaleString()}</strong><small>次查询</small></div></div>)}</div>}</section>
 <section className="panel"><div className="panelhead"><div><h2>未识别域名</h2><p>按小时汇总的 DNS 查询次数排序</p></div></div>{!unknown?.items.length?<div className="empty">暂无待处理域名</div>:<div className="unknown">{unknown.items.slice(0,15).map((d,i)=><div className="unknown-row" key={d.domain}><span className="number">{String(i+1).padStart(2,"0")}</span><span className="domain">{d.domain}</span><b>{d.queries.toLocaleString()}</b><button onClick={()=>{setRuleDomain(d.domain);setRulesOpen(true)}}>添加规则</button></div>)}</div>}<p className="hint">显示前 15 项，查询记录受上游保留期和同步完整性影响。</p></section></div>{range!=="custom"&&<section className="panel device-panel"><div className="panelhead"><div><h2>设备流量排行</h2><p>来源于 NetFlow Plus 已有的设备外网流量汇总</p></div></div>{devices.length===0?<div className="empty">尚无设备流量或采集器未连接</div>:<div className="unknown">{devices.map((d,i)=><div className="unknown-row" key={d.id}><span className="number">{String(i+1).padStart(2,"0")}</span><span className="domain">{d.name}<small className="device-ip">{d.ips?.[0]??""}</small></span><b>{bytes(d.down+d.up)}</b></div>)}</div>}</section>}{rulesOpen&&<Rules initialDomain={ruleDomain} onClose={()=>setRulesOpen(false)} onChanged={()=>setRevision(x=>x+1)}/>}<footer>NetFlow V2 · 独立读取 OxiDNS 与 NetFlow Plus · 不修改源数据</footer></main></div>
}
createRoot(document.getElementById("root")!).render(<Dashboard/>);





