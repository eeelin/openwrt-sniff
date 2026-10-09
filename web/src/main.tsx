import { StrictMode, useEffect, useMemo, useState } from 'react'
import { createRoot } from 'react-dom/client'
import './style.css'

type Flow = { id:number; first_seen:number; last_seen:number; source:string; destination:string; network:string; protocol?:string; domain?:string; packets_seen:number; bytes_sampled:number; proxy_set_match:boolean; classification:string; sniff_state?:string; sniff_error?:string; stream_bytes?:number; expected_bytes?:number; tcp_syn_seen?:boolean; tcp_gap_packets?:number; tcp_retransmissions?:number }
type Diagnostics = { decode_failures:number; non_lan_packets:number; tcp_sequence_gaps:number; tcp_retransmissions:number }
type DebugCapture = { active:boolean; started_at?:number; expires_at?:number; bytes:number; packets:number; max_bytes:number; ready:boolean; filter?:string }
type CaptureStatus = { capturing:boolean; interfaces:string[]; lan_prefixes:string[]; bpf_enabled:boolean; started_at?:number; errors?:Record<string,string>; packets:number; drops:number; queue_freezes:number; nft_set_enabled:boolean; nft_set_errors?:Record<string,string>; diagnostics:Diagnostics; debug_capture:DebugCapture }
type Status = { version:string; capture:CaptureStatus; flow_count:number; event_drops:number }

function App() {
  const [status,setStatus]=useState<Status|null>(null)
  const [flows,setFlows]=useState<Map<number,Flow>>(new Map())
  const [filter,setFilter]=useState('')
  const [connected,setConnected]=useState(false)

  const refresh=()=>fetch('/api/v1/status').then(r=>r.json()).then(setStatus)
  useEffect(()=>{ refresh(); const timer=setInterval(refresh,3000); return()=>clearInterval(timer) },[])
  useEffect(()=>{
    const scheme=location.protocol==='https:'?'wss':'ws'
    const ws=new WebSocket(`${scheme}://${location.host}/api/v1/events`)
    ws.onopen=()=>setConnected(true); ws.onclose=()=>setConnected(false)
    ws.onmessage=e=>{ const event=JSON.parse(e.data); if(event.type==='snapshot') setFlows(new Map(event.flows.map((f:Flow)=>[f.id,f]))); else if(event.flow) setFlows(prev=>{const next=new Map(prev);if(event.type==='flow.close')next.delete(event.flow.id);else next.set(event.flow.id,event.flow);return next}) }
    return()=>ws.close()
  },[])
  const rows=useMemo(()=>Array.from(flows.values()).filter(f=>`${f.source} ${f.destination} ${f.protocol} ${f.domain} ${f.proxy_set_match?'proxy':''}`.toLowerCase().includes(filter.toLowerCase())).sort((a,b)=>b.last_seen-a.last_seen).slice(0,1000),[flows,filter])
  const action=async(name:'start'|'stop')=>{await fetch(`/api/v1/capture/${name}`,{method:'POST'});refresh()}
  const clear=async()=>{await fetch('/api/v1/flows',{method:'DELETE'});setFlows(new Map());refresh()}
  const debugAction=async(name:'start'|'stop')=>{await fetch(`/api/v1/debug/capture/${name}`,{method:'POST'});refresh()}
  const debugFlow=async(f:Flow)=>{const source=endpoint(f.source);const destination=endpoint(f.destination);await fetch('/api/v1/debug/capture/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({source:source.address,destination:destination.address,port:destination.port})});refresh()}

  return <main>
    <header><div><p className="eyebrow">LIVE NETWORK WINDOW</p><h1>OpenWrt Sniff</h1></div><div className="actions"><span className={`dot ${connected?'online':''}`}/><span>{connected?'实时通道已连接':'正在重连'}</span>{status?.capture.capturing?<button className="stop" onClick={()=>action('stop')}>停止观察</button>:<button onClick={()=>action('start')}>开始观察</button>}</div></header>
    {status?.capture.errors&&Object.entries(status.capture.errors).map(([name,message])=><div className="error" key={name}><strong>{name}</strong>: {message}</div>)}
    {status?.capture.nft_set_errors&&Object.entries(status.capture.nft_set_errors).map(([name,message])=><div className="warning" key={name}><strong>nft {name}</strong>: {message}</div>)}
    <section className="metrics">
      <Metric label="采集状态" value={status?.capture.capturing?'正在观察':'已停止'} accent={!!status?.capture.capturing}/>
      <Metric label="窗口连接" value={String(flows.size)}/><Metric label="已识别流量" value={String(Array.from(flows.values()).filter(f=>f.protocol).length)}/><Metric label="内核丢包" value={String(status?.capture.drops??0)} warn={(status?.capture.drops??0)>0}/>
    </section>
    <section className="capture-detail"><span>接口 {status?.capture.interfaces.join(', ')||'—'}</span><span>LAN {status?.capture.lan_prefixes?.join(', ')||'自动发现中'}</span><span>cBPF {status?.capture.bpf_enabled?'已启用':'未启用'}</span><span>nft 标记 {status?.capture.nft_set_enabled?'已启用':'未配置'}</span><span>采集 {status?.capture.packets??0} 包</span><span>解码失败 {status?.capture.diagnostics?.decode_failures??0}</span><span>非 LAN {status?.capture.diagnostics?.non_lan_packets??0}</span><span>TCP 缺口 {status?.capture.diagnostics?.tcp_sequence_gaps??0}</span><span>重传 {status?.capture.diagnostics?.tcp_retransmissions??0}</span><span>队列冻结 {status?.capture.queue_freezes??0}</span><span>推送丢弃 {status?.event_drops??0}</span></section>
    <section className="panel"><div className="toolbar"><input value={filter} onChange={e=>setFilter(e.target.value)} placeholder="搜索客户端、目标、协议、域名或 proxy"/><div className="debug-actions">{status?.capture.debug_capture?.active?<button className="ghost" onClick={()=>debugAction('stop')}>停止诊断 ({formatBytes(status.capture.debug_capture.bytes)})</button>:status?.capture.debug_capture?.ready?<a className="download" href="/api/v1/debug/capture.pcap">下载诊断 pcap</a>:<button className="ghost" disabled={!status?.capture.capturing} onClick={()=>debugAction('start')}>诊断抓包 30 秒</button>}<button className="ghost" onClick={clear}>清空窗口</button></div></div>
      <div className="table"><table><thead><tr><th>时间</th><th>客户端</th><th>目标</th><th>网络</th><th>识别</th><th>域名 / SNI</th><th>诊断</th><th>路径</th><th>采样</th></tr></thead><tbody>{rows.map(f=><tr key={f.id}><td>{new Date(f.last_seen).toLocaleTimeString()}</td><td>{f.source}</td><td>{f.destination}</td><td><span className="pill">{f.network}</span></td><td>{f.protocol||<span className="muted">待识别</span>}</td><td className="domain">{f.domain||'—'}</td><td className="diagnostic" title={f.sniff_error}><span>{diagnosticText(f)}</span>{!f.protocol&&status?.capture.capturing&&!status.capture.debug_capture?.active&&<button className="trace" onClick={()=>debugFlow(f)}>抓此目标</button>}</td><td>{f.proxy_set_match?<span className="pill proxy">代理集合</span>:<span className="muted">直连/未知</span>}</td><td>{formatBytes(f.bytes_sampled)} · {f.packets_seen} 包</td></tr>)}</tbody></table>{rows.length===0&&<div className="empty">{status?.capture.capturing?'等待 LAN 上行流量…':'点击“开始观察”开启实时窗口'}</div>}</div>
    </section><footer>v{status?.version??'…'} · 仅内存窗口，不写入磁盘</footer>
  </main>
}
function Metric({label,value,accent=false,warn=false}:{label:string;value:string;accent?:boolean;warn?:boolean}){return <div className="metric"><span>{label}</span><strong className={accent?'accent':warn?'warn':''}>{value}</strong></div>}
function formatBytes(n:number){if(n<1024)return `${n} B`;if(n<1048576)return `${(n/1024).toFixed(1)} KB`;return `${(n/1048576).toFixed(1)} MB`}
function diagnosticText(f:Flow){if(f.network!=='tcp')return f.sniff_state||'—';if(f.sniff_state==='identified')return '已识别';const bytes=f.expected_bytes?`${f.stream_bytes??0}/${f.expected_bytes} B`:`${f.stream_bytes??0} B`;const syn=f.tcp_syn_seen?'':' · 未见 SYN';const gap=f.tcp_gap_packets?` · 缺口 ${f.tcp_gap_packets}`:'';return `${f.sniff_state||'pending'} · ${bytes}${syn}${gap}`}
function endpoint(value:string){if(value.startsWith('[')){const end=value.indexOf(']');return {address:value.slice(1,end),port:Number(value.slice(end+2))}}const split=value.lastIndexOf(':');return {address:value.slice(0,split),port:Number(value.slice(split+1))}}
createRoot(document.getElementById('root')!).render(<StrictMode><App/></StrictMode>)
