import { StrictMode, useEffect, useMemo, useState } from 'react'
import { createRoot } from 'react-dom/client'
import './style.css'

type Flow = { id:number; first_seen:number; last_seen:number; source:string; destination:string; network:string; connection_state?:'active'|'closed'; direction:'internal'|'outbound'|'inbound'; internal_type?:'unicast'|'multicast'|'broadcast'; protocol?:string; application?:string; protocol_transport?:string; domain?:string; domain_source?:string; protocol_version?:string; alpn?:string[]; ech?:boolean; confidence?:string; packets_seen:number; bytes_sampled:number; sent_packets:number; sent_bytes:number; received_packets:number; received_bytes:number; proxy_set_match:boolean; classification:string; sniff_state?:string; sniff_error?:string; stream_bytes?:number; expected_bytes?:number; tcp_syn_seen?:boolean; tcp_gap_packets?:number; tcp_retransmissions?:number }
type DirectionFilter = 'internal:unicast'|'internal:multicast'|'internal:broadcast'|'outbound'|'inbound'
type ConnectionStateFilter = 'all'|'active'|'closed'
const directionOptions:{value:DirectionFilter;label:string}[]=[{value:'internal:unicast',label:'内网单播'},{value:'internal:multicast',label:'内网组播'},{value:'internal:broadcast',label:'内网广播'},{value:'outbound',label:'出流量'},{value:'inbound',label:'入流量'}]
type Diagnostics = { decode_failures:number; non_lan_packets:number; tcp_sequence_gaps:number; tcp_retransmissions:number }
type DebugCapture = { active:boolean; started_at?:number; expires_at?:number; bytes:number; packets:number; max_bytes:number; ready:boolean; filter?:string }
type CaptureStatus = { capturing:boolean; interfaces:string[]; lan_prefixes:string[]; bpf_enabled:boolean; started_at?:number; errors?:Record<string,string>; packets:number; drops:number; queue_freezes:number; nft_set_enabled:boolean; nft_set_errors?:Record<string,string>; diagnostics:Diagnostics; debug_capture:DebugCapture }
type Status = { version:string; capture:CaptureStatus; flow_count:number; event_drops:number }

function Root() {
  const [authenticated,setAuthenticated]=useState<boolean|null>(null)
  useEffect(()=>{
    fetch('/api/v1/auth/session').then(r=>r.json()).then(result=>setAuthenticated(result.authenticated)).catch(()=>setAuthenticated(false))
    const expired=()=>setAuthenticated(false)
    window.addEventListener('sniffd-auth-expired',expired)
    return()=>window.removeEventListener('sniffd-auth-expired',expired)
  },[])
  if(authenticated===null)return <div className="login-shell"><div className="login-card"><p className="eyebrow">OPENWRT SNIFFD</p><h1>正在连接</h1></div></div>
  return authenticated?<App onLogout={()=>setAuthenticated(false)}/>:<Login onSuccess={()=>setAuthenticated(true)}/>
}

function Login({onSuccess}:{onSuccess:()=>void}) {
  const [token,setToken]=useState('')
  const [error,setError]=useState('')
  const [busy,setBusy]=useState(false)
  const submit=async(e:React.FormEvent)=>{e.preventDefault();setBusy(true);setError('');try{const response=await fetch('/api/v1/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token})});if(!response.ok){setError(response.status===429?'尝试次数过多，请稍后再试':'Token 无效');return}setToken('');onSuccess()}catch{setError('无法连接 sniffd')}finally{setBusy(false)}}
  return <div className="login-shell"><form className="login-card" onSubmit={submit}><p className="eyebrow">OPENWRT SNIFFD</p><h1>流量观察台</h1><p className="login-help">输入路由器上的访问 Token</p><input autoFocus autoComplete="off" type="password" value={token} onChange={e=>setToken(e.target.value)} placeholder="访问 Token"/>{error&&<div className="login-error">{error}</div>}<button disabled={busy||token.length===0}>{busy?'正在验证…':'登录'}</button><code>cat /etc/sniffd.token</code></form></div>
}

function App({onLogout}:{onLogout:()=>void}) {
  const [status,setStatus]=useState<Status|null>(null)
  const [flows,setFlows]=useState<Map<number,Flow>>(new Map())
  const [filter,setFilter]=useState('')
  const [directions,setDirections]=useState<Set<DirectionFilter>>(()=>new Set(directionOptions.map(option=>option.value)))
  const [connectionState,setConnectionState]=useState<ConnectionStateFilter>('all')
  const [connected,setConnected]=useState(false)

  const refresh=()=>apiFetch('/api/v1/status').then(r=>r.json()).then(setStatus).catch(()=>undefined)
  useEffect(()=>{ refresh(); const timer=setInterval(refresh,3000); return()=>clearInterval(timer) },[])
  useEffect(()=>{
    const scheme=location.protocol==='https:'?'wss':'ws'
    const ws=new WebSocket(`${scheme}://${location.host}/api/v1/events`)
    ws.onopen=()=>setConnected(true); ws.onclose=()=>setConnected(false)
    ws.onmessage=e=>{ const event=JSON.parse(e.data); if(event.type==='snapshot') setFlows(new Map(event.flows.map((f:Flow)=>[f.id,f]))); else if(event.flow) setFlows(prev=>{const next=new Map(prev);if(event.type==='flow.close')next.delete(event.flow.id);else next.set(event.flow.id,event.flow);return next}) }
    return()=>ws.close()
  },[])
  const rows=useMemo(()=>Array.from(flows.values()).filter(f=>directions.has(directionKey(f))&&(connectionState==='all'||f.connection_state===connectionState)&&`${f.source} ${f.destination} ${f.protocol} ${f.application} ${f.domain} ${f.proxy_set_match?'proxy':''}`.toLowerCase().includes(filter.toLowerCase())).sort((a,b)=>b.last_seen-a.last_seen).slice(0,1000),[flows,filter,directions,connectionState])
  const toggleDirection=(value:DirectionFilter)=>setDirections(previous=>{const next=new Set(previous);if(next.has(value))next.delete(value);else next.add(value);return next})
  const action=async(name:'start'|'stop')=>{await apiFetch(`/api/v1/capture/${name}`,{method:'POST'});refresh()}
  const clear=async()=>{await apiFetch('/api/v1/flows',{method:'DELETE'});setFlows(new Map());refresh()}
  const debugAction=async(name:'start'|'stop')=>{await apiFetch(`/api/v1/debug/capture/${name}`,{method:'POST'});refresh()}
  const downloadDebug=async()=>{const response=await apiFetch('/api/v1/debug/capture.pcap',{method:'POST'});const blob=await response.blob();const url=URL.createObjectURL(blob);const link=document.createElement('a');link.href=url;link.download='sniffd-debug.pcap';link.click();URL.revokeObjectURL(url);refresh()}
  const debugFlow=async(f:Flow)=>{const source=endpoint(f.source);const destination=endpoint(f.destination);await apiFetch('/api/v1/debug/capture/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({source:source.address,destination:destination.address,port:destination.port})});refresh()}
  const logout=async()=>{await fetch('/api/v1/auth/logout',{method:'POST'});onLogout()}

  return <main>
    <header><div><p className="eyebrow">LIVE NETWORK WINDOW</p><h1>OpenWrt Sniff</h1></div><div className="actions"><span className={`dot ${connected?'online':''}`}/><span>{connected?'实时通道已连接':'正在重连'}</span>{status?.capture.capturing?<button className="stop" onClick={()=>action('stop')}>停止观察</button>:<button onClick={()=>action('start')}>开始观察</button>}<button className="ghost" onClick={logout}>退出</button></div></header>
    {status?.capture.errors&&Object.entries(status.capture.errors).map(([name,message])=><div className="error" key={name}><strong>{name}</strong>: {message}</div>)}
    {status?.capture.nft_set_errors&&Object.entries(status.capture.nft_set_errors).map(([name,message])=><div className="warning" key={name}><strong>nft {name}</strong>: {message}</div>)}
    <section className="metrics">
      <Metric label="采集状态" value={status?.capture.capturing?'正在观察':'已停止'} accent={!!status?.capture.capturing}/>
      <Metric label="窗口连接" value={String(flows.size)}/><Metric label="已识别流量" value={String(Array.from(flows.values()).filter(f=>f.protocol).length)}/><Metric label="内核丢包" value={String(status?.capture.drops??0)} warn={(status?.capture.drops??0)>0}/>
    </section>
    <section className="capture-detail"><span>接口 {status?.capture.interfaces.join(', ')||'—'}</span><span>LAN {status?.capture.lan_prefixes?.join(', ')||'自动发现中'}</span><span>cBPF {status?.capture.bpf_enabled?'已启用':'未启用'}</span><span>nft 标记 {status?.capture.nft_set_enabled?'已启用':'未配置'}</span><span>采集 {status?.capture.packets??0} 包</span><span>解码失败 {status?.capture.diagnostics?.decode_failures??0}</span><span>非 LAN {status?.capture.diagnostics?.non_lan_packets??0}</span><span>TCP 缺口 {status?.capture.diagnostics?.tcp_sequence_gaps??0}</span><span>重传 {status?.capture.diagnostics?.tcp_retransmissions??0}</span><span>队列冻结 {status?.capture.queue_freezes??0}</span><span>推送丢弃 {status?.event_drops??0}</span></section>
    <section className="panel"><div className="toolbar"><div className="filters"><input value={filter} onChange={e=>setFilter(e.target.value)} placeholder="搜索源、目的、协议、域名或 proxy"/><div className="filter-row"><div className="direction-filter">{directionOptions.map(option=><label className={directions.has(option.value)?'selected':''} key={option.value}><input type="checkbox" checked={directions.has(option.value)} onChange={()=>toggleDirection(option.value)}/>{option.label}</label>)}</div><div className="connection-filter">{(['all','active','closed'] as ConnectionStateFilter[]).map(value=><button className={connectionState===value?'selected':''} key={value} onClick={()=>setConnectionState(value)}>{value==='all'?'全部连接':value}</button>)}</div></div></div><div className="debug-actions">{status?.capture.debug_capture?.active?<button className="ghost" onClick={()=>debugAction('stop')}>停止诊断 ({formatBytes(status.capture.debug_capture.bytes)})</button>:status?.capture.debug_capture?.ready?<button className="download" onClick={downloadDebug}>下载诊断 pcap</button>:<button className="ghost" disabled={!status?.capture.capturing} onClick={()=>debugAction('start')}>诊断抓包 30 秒</button>}<button className="ghost" onClick={clear}>清空窗口</button></div></div>
      <div className="table"><table><thead><tr><th>时间</th><th>方向</th><th>发起端</th><th>对端</th><th>网络</th><th>状态</th><th>识别</th><th>域名 / SNI</th><th>诊断</th><th>路径</th><th>流量</th></tr></thead><tbody>{rows.map(f=><tr key={f.id}><td>{new Date(f.last_seen).toLocaleTimeString()}</td><td><span className={`pill direction ${f.direction}`}>{directionLabel(f)}</span></td><td>{f.source}</td><td>{f.destination}</td><td><span className="pill">{f.network}</span></td><td>{f.connection_state?<span className={`pill connection ${f.connection_state}`}>{f.connection_state}</span>:<span className="muted">—</span>}</td><td title={protocolDetails(f)}>{protocolText(f)||<span className="muted">待识别</span>}{f.ech&&<span className="pill ech">ECH</span>}</td><td className="domain">{f.domain||'—'}{f.domain&&f.domain_source&&<span className={`domain-source ${f.domain_source}`}>{domainSourceLabel(f.domain_source)}</span>}</td><td className="diagnostic" title={f.sniff_error}><span>{diagnosticText(f)}</span>{!f.protocol&&status?.capture.capturing&&!status.capture.debug_capture?.active&&<button className="trace" onClick={()=>debugFlow(f)}>抓此目标</button>}</td><td>{f.proxy_set_match?<span className="pill proxy">代理集合</span>:<span className="muted">直连/未知</span>}</td><td title={`发送 ${f.sent_packets} 包，接收 ${f.received_packets} 包`}><span className="traffic-up">↑ {formatBytes(f.sent_bytes)}</span><span className="traffic-down">↓ {formatBytes(f.received_bytes)}</span></td></tr>)}</tbody></table>{rows.length===0&&<div className="empty">{status?.capture.capturing?'当前筛选条件下暂无流量':'点击“开始观察”开启实时窗口'}</div>}</div>
    </section><footer>v{status?.version??'…'} · 仅内存窗口，不写入磁盘</footer>
  </main>
}
function Metric({label,value,accent=false,warn=false}:{label:string;value:string;accent?:boolean;warn?:boolean}){return <div className="metric"><span>{label}</span><strong className={accent?'accent':warn?'warn':''}>{value}</strong></div>}
function formatBytes(n:number){if(n<1024)return `${n} B`;if(n<1048576)return `${(n/1024).toFixed(1)} KB`;return `${(n/1048576).toFixed(1)} MB`}
function diagnosticText(f:Flow){if(f.network!=='tcp')return f.sniff_state||'—';if(f.sniff_state==='identified')return '已识别';const bytes=f.expected_bytes?`${f.stream_bytes??0}/${f.expected_bytes} B`:`${f.stream_bytes??0} B`;const syn=f.tcp_syn_seen?'':' · 未见 SYN';const gap=f.tcp_gap_packets?` · 缺口 ${f.tcp_gap_packets}`:'';return `${f.sniff_state||'pending'} · ${bytes}${syn}${gap}`}
function directionKey(f:Flow):DirectionFilter{return f.direction==='internal'?`internal:${f.internal_type??'unicast'}`:f.direction}
function directionLabel(f:Flow){if(f.direction==='outbound')return '出';if(f.direction==='inbound')return '入';return f.internal_type==='broadcast'?'内网广播':f.internal_type==='multicast'?'内网组播':'内网单播'}
function protocolText(f:Flow){if(!f.protocol)return '';const app=f.application?`${f.application} · `:'';const alpn=f.alpn?.length?` · ${f.alpn.join(', ')}`:'';return `${app}${f.protocol}${alpn}`}
function protocolDetails(f:Flow){return [f.protocol_version,f.protocol_transport?`承载: ${f.protocol_transport}`:'',f.alpn?.length?`ALPN: ${f.alpn.join(', ')}`:'',f.ech?'ECH offered':'',f.confidence?`识别依据: ${f.confidence}`:''].filter(Boolean).join('\n')}
function domainSourceLabel(source:string){if(source==='tls_sni'||source==='quic_sni')return 'SNI';if(source==='http_host')return 'Host';if(source==='dns_inferred')return 'DNS 推断';if(source==='dns_question')return 'DNS';return source}
function endpoint(value:string){if(value.startsWith('[')){const end=value.indexOf(']');return {address:value.slice(1,end),port:Number(value.slice(end+2))}}const split=value.lastIndexOf(':');return {address:value.slice(0,split),port:Number(value.slice(split+1))}}
async function apiFetch(input:RequestInfo|URL,init?:RequestInit){const response=await fetch(input,init);if(response.status===401){window.dispatchEvent(new Event('sniffd-auth-expired'));throw new Error('authentication required')}return response}
createRoot(document.getElementById('root')!).render(<StrictMode><Root/></StrictMode>)
