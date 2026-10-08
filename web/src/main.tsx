import { StrictMode, useEffect, useMemo, useState } from 'react'
import { createRoot } from 'react-dom/client'
import './style.css'

type Flow = { id:number; first_seen:number; last_seen:number; source:string; destination:string; network:string; protocol?:string; domain?:string; packets_seen:number; bytes_sampled:number; proxy_set_match:boolean; classification:string }
type Status = { version:string; capture:{capturing:boolean;interfaces:string[];started_at?:number;error?:string}; flow_count:number; event_drops:number }

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
    ws.onmessage=e=>{ const event=JSON.parse(e.data); if(event.type==='snapshot') setFlows(new Map(event.flows.map((f:Flow)=>[f.id,f]))); else if(event.flow) setFlows(prev=>{const next=new Map(prev);next.set(event.flow.id,event.flow);return next}) }
    return()=>ws.close()
  },[])
  const rows=useMemo(()=>Array.from(flows.values()).filter(f=>`${f.source} ${f.destination} ${f.protocol} ${f.domain}`.toLowerCase().includes(filter.toLowerCase())).sort((a,b)=>b.last_seen-a.last_seen).slice(0,1000),[flows,filter])
  const action=async(name:'start'|'stop')=>{await fetch(`/api/v1/capture/${name}`,{method:'POST'});refresh()}
  const clear=async()=>{await fetch('/api/v1/flows',{method:'DELETE'});setFlows(new Map());refresh()}

  return <main>
    <header><div><p className="eyebrow">LIVE NETWORK WINDOW</p><h1>OpenWrt Sniff</h1></div><div className="actions"><span className={`dot ${connected?'online':''}`}/><span>{connected?'实时通道已连接':'正在重连'}</span>{status?.capture.capturing?<button className="stop" onClick={()=>action('stop')}>停止观察</button>:<button onClick={()=>action('start')}>开始观察</button>}</div></header>
    {status?.capture.error&&<div className="error">{status.capture.error}</div>}
    <section className="metrics">
      <Metric label="采集状态" value={status?.capture.capturing?'正在观察':'已停止'} accent={!!status?.capture.capturing}/>
      <Metric label="窗口连接" value={String(flows.size)}/><Metric label="已识别域名" value={String(Array.from(flows.values()).filter(f=>f.domain).length)}/><Metric label="推送丢弃" value={String(status?.event_drops??0)}/>
    </section>
    <section className="panel"><div className="toolbar"><input value={filter} onChange={e=>setFilter(e.target.value)} placeholder="搜索客户端、目标、协议或域名"/><div><span className="interface">{status?.capture.interfaces.join(', ')}</span><button className="ghost" onClick={clear}>清空窗口</button></div></div>
      <div className="table"><table><thead><tr><th>时间</th><th>客户端</th><th>目标</th><th>网络</th><th>识别</th><th>域名 / SNI</th><th>采样</th></tr></thead><tbody>{rows.map(f=><tr key={f.id}><td>{new Date(f.last_seen).toLocaleTimeString()}</td><td>{f.source}</td><td>{f.destination}</td><td><span className="pill">{f.network}</span></td><td>{f.protocol||<span className="muted">待识别</span>}</td><td className="domain">{f.domain||'—'}</td><td>{formatBytes(f.bytes_sampled)} · {f.packets_seen} 包</td></tr>)}</tbody></table>{rows.length===0&&<div className="empty">{status?.capture.capturing?'等待 LAN 上行流量…':'点击“开始观察”开启实时窗口'}</div>}</div>
    </section><footer>v{status?.version??'…'} · 仅内存窗口，不写入磁盘</footer>
  </main>
}
function Metric({label,value,accent=false}:{label:string;value:string;accent?:boolean}){return <div className="metric"><span>{label}</span><strong className={accent?'accent':''}>{value}</strong></div>}
function formatBytes(n:number){if(n<1024)return `${n} B`;if(n<1048576)return `${(n/1024).toFixed(1)} KB`;return `${(n/1048576).toFixed(1)} MB`}
createRoot(document.getElementById('root')!).render(<StrictMode><App/></StrictMode>)

