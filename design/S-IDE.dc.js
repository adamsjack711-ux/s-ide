
class Component extends DCLogic {
  state = {
    view: 'engagements',
    theme: this.props.theme || 'midnight',
    accent: this.props.accent || '#39d98a',
    copilotOpen: this.props.copilotOpen !== false,
    settingsOpen: false,
    paletteOpen: false,
    selectedId: 'F-1042',
    filter: 'all',
  };

  themes = {
    midnight: { bg:'#0a0e15', panel:'#0d1320', panel2:'#131c2c', border:'rgba(255,255,255,.07)', bs:'rgba(255,255,255,.15)', text:'#dde3ee', dim:'#8b95a8', faint:'#586173', hover:'rgba(255,255,255,.045)' },
    graphite: { bg:'#16181d', panel:'#1c1f26', panel2:'#242832', border:'rgba(255,255,255,.08)', bs:'rgba(255,255,255,.16)', text:'#e6e9ef', dim:'#959cab', faint:'#646b79', hover:'rgba(255,255,255,.05)' },
    light: { bg:'#eef0f4', panel:'#ffffff', panel2:'#f4f6f9', border:'rgba(12,16,24,.1)', bs:'rgba(12,16,24,.22)', text:'#1a2030', dim:'#5a6475', faint:'#98a0b0', hover:'rgba(12,16,24,.04)' },
  };

  sev = {
    crit: { c:'#ff5d6c', l:'Critical' },
    high: { c:'#ff9340', l:'High' },
    med:  { c:'#ffc043', l:'Medium' },
    low:  { c:'#4d9fff', l:'Low' },
  };
  srcColors = { SAST:'#b07cff', Secret:'#ff5d6c', Dependency:'#4d9fff', Cloud:'#39d98a', Recon:'#ff9340' };

  findingsData = [
    { id:'F-1042', sev:'crit', title:'SQL injection in authentication handler', source:'SAST', loc:'api/auth/login.go:88', status:'Triaging', owner:'you', age:'5h', cvss:'9.1', cve:'CWE-89',
      desc:'User-supplied input from the login form flows unsanitized into a raw SQL string. Because the value is concatenated rather than parameterized, an attacker can inject arbitrary SQL — bypassing authentication, reading arbitrary rows, or dropping tables. This endpoint is internet-facing and unauthenticated.',
      fix:'Replace string concatenation with a parameterized query: db.Query("SELECT * FROM users WHERE name = $1", user). Add an input-validation middleware and enable the database least-privilege role. I can open a PR that applies all three.',
      flow:[ {tag:'SOURCE',label:'Untrusted HTTP form value',loc:'r.FormValue("user")'}, {tag:'PROPAGATION',label:'Concatenated into query string',loc:'login.go:88'}, {tag:'SINK',label:'Raw SQL execution',loc:'db.Query(q)'} ] },
    { id:'F-1041', sev:'crit', title:'Hardcoded AWS secret key committed to repo', source:'Secret', loc:'deploy/prod.env:14', status:'Open', owner:'unassigned', age:'2h', cvss:'9.8', cve:'CWE-798',
      desc:'A long-lived AWS access key was committed in plaintext and is present across 40+ commits in git history. The key has broad IAM permissions on production.',
      fix:'Immediately rotate the key in IAM, purge it from git history with a filter, and migrate to short-lived credentials via OIDC. I can generate the rotation runbook.',
      flow:[ {tag:'SECRET',label:'AWS access key in plaintext',loc:'prod.env:14'}, {tag:'EXPOSURE',label:'Present in 41 commits',loc:'git history'}, {tag:'IMPACT',label:'Full prod IAM access',loc:'iam/acme-deploy'} ] },
    { id:'F-1039', sev:'crit', title:'Remote code execution via insecure deserialization', source:'Recon', loc:'10.2.40.11:8080', status:'Open', owner:'r.okoye', age:'1h', cvss:'9.6', cve:'CWE-502',
      desc:'A Jenkins instance discovered during the recon sweep accepts serialized Java objects on an exposed port, allowing unauthenticated remote code execution. Confirmed reachable from the corporate VPN range.',
      fix:'Restrict the port via security group, upgrade Jenkins to the patched release, and enable agent-to-controller access control. Quarantine the host pending patch.',
      flow:[ {tag:'SOURCE',label:'Exposed serialization endpoint',loc:'10.2.40.11:8080'}, {tag:'PROPAGATION',label:'Gadget chain in classpath',loc:'CommonsCollections'}, {tag:'SINK',label:'Runtime.exec()',loc:'unauthenticated RCE'} ] },
    { id:'F-1036', sev:'high', title:'Vulnerable dependency: lodash 4.17.4', source:'Dependency', loc:'package.json', status:'Open', owner:'unassigned', age:'1d', cvss:'7.4', cve:'CVE-2021-23337',
      desc:'lodash 4.17.4 is affected by command injection through the template function. The package is a direct dependency and is bundled into the client and SSR builds.',
      fix:'Bump lodash to >= 4.17.21. The upgrade is non-breaking for your usage. I can open the dependency PR and run the test suite.',
      flow:[ {tag:'SOURCE',label:'Direct dependency',loc:'package.json'}, {tag:'PROPAGATION',label:'Bundled into SSR build',loc:'webpack'}, {tag:'SINK',label:'_.template injection',loc:'CVE-2021-23337'} ] },
    { id:'F-1034', sev:'high', title:'Server-side request forgery in image proxy', source:'SAST', loc:'services/proxy.ts:142', status:'Open', owner:'m.chen', age:'3h', cvss:'8.2', cve:'CWE-918',
      desc:'The image proxy fetches arbitrary user-supplied URLs without validation, allowing an attacker to reach internal metadata endpoints and cloud credentials.',
      fix:'Enforce an allowlist of hostnames, block link-local and private IP ranges, and disable redirects on the proxy fetch.',
      flow:[ {tag:'SOURCE',label:'User-supplied URL param',loc:'req.query.url'}, {tag:'PROPAGATION',label:'No host validation',loc:'proxy.ts:142'}, {tag:'SINK',label:'Server-side fetch',loc:'169.254.169.254'} ] },
    { id:'F-1031', sev:'high', title:'Publicly exposed S3 bucket: prod-assets', source:'Cloud', loc:'aws/s3/prod-assets', status:'Triaging', owner:'you', age:'6h', cvss:'7.7', cve:'CWE-200',
      desc:'The prod-assets bucket has a public-read ACL and contains backup database dumps. The objects are listable and downloadable without authentication.',
      fix:'Apply a Block Public Access policy at the account level, remove the public ACL, and move backups to a private encrypted bucket.',
      flow:[ {tag:'SOURCE',label:'Public-read ACL',loc:'prod-assets'}, {tag:'EXPOSURE',label:'Listable objects',loc:'47 db dumps'}, {tag:'IMPACT',label:'PII data leak',loc:'unauthenticated'} ] },
    { id:'F-1028', sev:'med', title:'Missing rate limiting on password reset', source:'SAST', loc:'api/auth/reset.go:51', status:'Open', owner:'unassigned', age:'2d', cvss:'5.3', cve:'CWE-307',
      desc:'The password reset endpoint has no rate limiting, enabling token brute-force and user enumeration via timing differences.',
      fix:'Add a per-IP and per-account rate limiter, and return a constant-time generic response regardless of account existence.',
      flow:[ {tag:'SOURCE',label:'Unthrottled endpoint',loc:'reset.go:51'}, {tag:'PROPAGATION',label:'No backoff',loc:'no limiter'}, {tag:'SINK',label:'Token brute-force',loc:'account takeover'} ] },
    { id:'F-1024', sev:'med', title:'Deprecated TLS 1.0 enabled on load balancer', source:'Cloud', loc:'aws/alb/listener', status:'Open', owner:'m.chen', age:'4d', cvss:'5.9', cve:'CWE-326',
      desc:'The application load balancer negotiates TLS 1.0, which is vulnerable to known downgrade and cipher attacks and fails PCI compliance.',
      fix:'Set the listener security policy to ELBSecurityPolicy-TLS13-1-2 to require TLS 1.2+.',
      flow:[ {tag:'SOURCE',label:'Weak TLS policy',loc:'alb/listener'}, {tag:'PROPAGATION',label:'TLS 1.0 accepted',loc:'downgrade'}, {tag:'SINK',label:'Cipher attack surface',loc:'PCI fail'} ] },
    { id:'F-1019', sev:'low', title:'Verbose error responses leak stack traces', source:'SAST', loc:'api/middleware.go:33', status:'Fixed', owner:'r.okoye', age:'5d', cvss:'3.1', cve:'CWE-209',
      desc:'Unhandled errors return full stack traces and internal file paths to clients, aiding reconnaissance.',
      fix:'Return a generic error body in production and log details server-side only.',
      flow:[ {tag:'SOURCE',label:'Unhandled panic',loc:'middleware.go:33'}, {tag:'PROPAGATION',label:'Trace in response',loc:'stderr → body'}, {tag:'SINK',label:'Recon disclosure',loc:'client'} ] },
  ];

  // login.go editor source
  codeRaw = [
    [['package ','kw'],['auth','txt']],
    [],
    [['import','kw'],[' (','punct']],
    [['  "database/sql"','str']],
    [['  "net/http"','str']],
    [[')','punct']],
    [],
    [['func','kw'],[' Login','fn'],['(w http.ResponseWriter, r *http.Request) {','txt']],
    [['  user','txt'],[' := r.','punct'],['FormValue','fn'],['("user")','str']],
    [['  pass','txt'],[' := r.','punct'],['FormValue','fn'],['("pass")','str']],
    [['  q','txt'],[' := ','punct'],['"SELECT * FROM users WHERE name=\'"','str'],[' + user + ','punct'],['"\'"','str']],
    [['  row','txt'],[' := db.','punct'],['Query','fn'],['(q)','txt']],
    [['  ','txt'],['if','kw'],[' !','punct'],['verify','fn'],['(row, pass) {','txt']],
    [['    http.','punct'],['Error','fn'],['(w, ','txt'],['"unauthorized"','str'],[', ','punct'],['401','num'],[')','txt']],
    [['  }','punct']],
    [['}','punct']],
  ];
  markLine = 10; // 0-indexed -> line 11

  snippetRaw = [
    { n:86, segs:[['func','kw'],[' Login','fn'],['(w, r) {','txt']] },
    { n:87, segs:[['  user','txt'],[' := r.','punct'],['FormValue','fn'],['("user")','str']] },
    { n:88, segs:[['  q','txt'],[' := ','punct'],['"SELECT * FROM users WHERE name=\'"','str'],[' + user','punct']], mark:true },
    { n:89, segs:[['  row','txt'],[' := db.','punct'],['Query','fn'],['(q)','txt']] },
    { n:90, segs:[['  ','txt'],['if','kw'],[' !','punct'],['verify','fn'],['(row, pass) { ... }','txt']] },
  ];

  fileTreeData = [
    { name:'api', glyph:'▾', depth:0, dir:true },
    { name:'auth', glyph:'▾', depth:1, dir:true },
    { name:'login.go', glyph:'·', depth:2, active:true, badge:'1' },
    { name:'reset.go', glyph:'·', depth:2, badge:'1' },
    { name:'middleware.go', glyph:'·', depth:1 },
    { name:'services', glyph:'▾', depth:0, dir:true },
    { name:'proxy.ts', glyph:'·', depth:1, badge:'1' },
    { name:'deploy', glyph:'▸', depth:0, dir:true, badge:'1' },
    { name:'package.json', glyph:'·', depth:0, badge:'2' },
  ];

  termRaw = [
    { text:'s-ide ❯ s-ide scan --target 10.2.40.0/24 --recon', type:'cmd' },
    { text:'[*] Initializing recon module — 254 hosts in scope', type:'info' },
    { text:'[*] Host discovery (ARP + ICMP)...', type:'dim' },
    { text:'[+] 12 live hosts found', type:'ok' },
    { text:'[*] Scanning 10.2.40.11 ...', type:'dim' },
    { text:'      8080/tcp  open   http-proxy   Jenkins 2.289.1', type:'out' },
    { text:'      22/tcp    open   ssh          OpenSSH 7.4', type:'out' },
    { text:'[!] CVE-2017-1000353  Jenkins unauthenticated RCE — CRITICAL', type:'err' },
    { text:'[!] Verifying deserialization gadget chain...', type:'warn' },
    { text:'[+] Exploit confirmed: arbitrary command execution', type:'err' },
    { text:'[*] Created finding F-1039 · severity CRITICAL · CVSS 9.6', type:'crit' },
    { text:'[*] Scan complete — 1 critical, 0 high, 2 info  (4.2s)', type:'ok' },
    { text:'', type:'dim' },
  ];

  graphRaw = {
    nodes: [
      { id:'app', label:'acme-web', x:40, y:208, root:true },
      { id:'express', label:'express', x:280, y:84 },
      { id:'lodash', label:'lodash 4.17.4', x:280, y:208, vuln:'high', cve:'CVE-2021-23337', fid:'F-1036' },
      { id:'axios', label:'axios', x:280, y:332 },
      { id:'jwt', label:'jsonwebtoken', x:540, y:48, vuln:'med', cve:'CVE-2022-23541' },
      { id:'qs', label:'qs', x:540, y:144 },
      { id:'minimist', label:'minimist 1.2.0', x:540, y:248, vuln:'crit', cve:'CVE-2021-44906' },
      { id:'follow', label:'follow-redirects', x:540, y:352, vuln:'high', cve:'CVE-2023-26159' },
      { id:'mime', label:'mime', x:770, y:120 },
      { id:'tunnel', label:'tunnel-agent', x:770, y:336, vuln:'low', cve:'CVE-2017-16100' },
    ],
    edges: [ ['app','express'],['app','lodash'],['app','axios'],['express','jwt'],['express','qs'],['lodash','minimist'],['axios','follow'],['axios','mime'],['follow','tunnel'] ],
  };

  copilotData = [
    { role:'ai', text:'I flagged F-1042 — a SQL injection in the authentication handler. Input from r.FormValue("user") flows unsanitized into a raw SQL query on line 88.' },
    { role:'user', text:'How would an attacker exploit this?' },
    { role:'ai', text:"Submitting user=' OR '1'='1 makes the WHERE clause always true, bypassing auth entirely. I can generate a parameterized-query fix plus an exploit test to confirm. Want me to open a PR?" },
  ];
  chipsData = ['Generate fix','Write exploit test','Find similar patterns','Explain CVSS'];

  engagementsData = [
    { id:'ENG-204', name:'acme-prod · external', target:'acme.com · 10.2.40.0/24', mode:'engagement', status:'running', lead:'AV', started:'2d ago', coverage:64, crit:3, high:3, med:2, low:1, tools:['DNS','Port Scan','TLS','HTTP','SQLi'], activeTool:'SQLi probe · login.go' },
    { id:'ENG-198', name:'saas-api-audit', target:'api.acme.io', mode:'engagement', status:'scanning', lead:'MC', started:'6h ago', coverage:38, crit:1, high:2, med:1, low:0, tools:['HTTP','JWT','GraphQL'], activeTool:'GraphQL introspection' },
    { id:'LAB-07', name:'Juice Shop', target:'lab-container:3000', mode:'lab', status:'running', lead:'AV', started:'1h ago', coverage:22, crit:0, high:1, med:2, low:3, tools:['XSS','SQLi','HTTP'], activeTool:'XSS fuzz · /search' },
    { id:'ENG-187', name:'internal-ad-q2', target:'corp.acme.local', mode:'engagement', status:'paused', lead:'RO', started:'5d ago', coverage:51, crit:1, high:1, med:0, low:0, tools:['LDAP','SMB','Kerberoast'] },
    { id:'ENG-176', name:'edge-vpn-review', target:'vpn.acme.com', mode:'engagement', status:'completed', lead:'AV', started:'12d ago', coverage:100, crit:0, high:0, med:1, low:2, tools:['TLS','Port Scan'] },
  ];

  toolsUsedData = [
    { name:'Port Scanner', runs:42, findings:6 },
    { name:'HTTP Probe', runs:38, findings:4 },
    { name:'SQL Injection', runs:21, findings:3 },
    { name:'TLS Auditor', runs:18, findings:2 },
    { name:'DNS Recon', runs:16, findings:1 },
    { name:'XSS Fuzzer', runs:14, findings:2 },
    { name:'Kerberoast', runs:7, findings:1 },
  ];

  codePalette(theme){
    return { kw:'#c792ea', fn:'#82aaff', str:'#a5d96b', num:'#f78c6c', com:'var(--faint)', txt:'var(--text)', punct:'var(--dim)' };
  }

  hexA(hex,a){ const n=parseInt(hex.slice(1),16); return `rgba(${(n>>16)&255},${(n>>8)&255},${n&255},${a})`; }

  icon(name,s=18){
    const E=React.createElement;
    const props={width:s,height:s,viewBox:'0 0 24 24',fill:'none',stroke:'currentColor',strokeWidth:1.7,strokeLinecap:'round',strokeLinejoin:'round'};
    const P={
      grid:[['rect',{x:3,y:3,width:7,height:7,rx:1.5}],['rect',{x:14,y:3,width:7,height:7,rx:1.5}],['rect',{x:14,y:14,width:7,height:7,rx:1.5}],['rect',{x:3,y:14,width:7,height:7,rx:1.5}]],
      code:[['polyline',{points:'16 18 22 12 16 6'}],['polyline',{points:'8 6 2 12 8 18'}]],
      filter:[['polygon',{points:'21 4 3 4 10 12.4 10 19 14 21 14 12.4 21 4'}]],
      search:[['circle',{cx:11,cy:11,r:7}],['line',{x1:21,y1:21,x2:16.65,y2:16.65}]],
      share:[['circle',{cx:18,cy:5,r:2.6}],['circle',{cx:6,cy:12,r:2.6}],['circle',{cx:18,cy:19,r:2.6}],['line',{x1:8.2,y1:13.3,x2:15.8,y2:17.7}],['line',{x1:15.8,y1:6.3,x2:8.2,y2:10.7}]],
      terminal:[['polyline',{points:'4 17 10 11 4 5'}],['line',{x1:12,y1:19,x2:20,y2:19}]],
      sliders:[['line',{x1:4,y1:21,x2:4,y2:14}],['line',{x1:4,y1:10,x2:4,y2:3}],['line',{x1:12,y1:21,x2:12,y2:12}],['line',{x1:12,y1:8,x2:12,y2:3}],['line',{x1:20,y1:21,x2:20,y2:16}],['line',{x1:20,y1:12,x2:20,y2:3}],['circle',{cx:4,cy:12,r:2}],['circle',{cx:12,cy:10,r:2}],['circle',{cx:20,cy:14,r:2}]],
      sparkle:[['path',{d:'M12 3 L13.5 9.2 L20 11 L13.5 12.8 L12 19 L10.5 12.8 L4 11 L10.5 9.2 Z'}]],
      shield:[['path',{d:'M12 3 L20 6 V11 C20 16 16.5 19.5 12 21 C7.5 19.5 4 16 4 11 V6 Z'}]],
      close:[['line',{x1:18,y1:6,x2:6,y2:18}],['line',{x1:6,y1:6,x2:18,y2:18}]],
      send:[['line',{x1:22,y1:2,x2:11,y2:13}],['polygon',{points:'22 2 15 22 11 13 2 9 22 2'}]],
      bolt:[['polygon',{points:'13 2 4 14 11 14 10 22 20 10 13 10 13 2'}]],
      target:[['circle',{cx:12,cy:12,r:8}],['line',{x1:12,y1:1,x2:12,y2:4}],['line',{x1:12,y1:20,x2:12,y2:23}],['line',{x1:1,y1:12,x2:4,y2:12}],['line',{x1:20,y1:12,x2:23,y2:12}],['circle',{cx:12,cy:12,r:1.6}]],
      chart:[['line',{x1:3,y1:21,x2:21,y2:21}],['rect',{x:4,y:12,width:3.6,height:8,rx:1}],['rect',{x:10.2,y:7,width:3.6,height:13,rx:1}],['rect',{x:16.4,y:3,width:3.6,height:17,rx:1}]],
    };
    return E('svg',props,...(P[name]||[]).map((it,i)=>E(it[0],{key:i,...it[1]})));
  }

  setView(v){ this.setState({ view:v, settingsOpen:false, paletteOpen:false }); }

  renderVals(){
    const s=this.state, t=this.themes[s.theme]||this.themes.midnight, ac=s.accent, P=this.codePalette();
    const isLight = s.theme==='light';

    const rootStyle = {
      '--bg':t.bg,'--panel':t.panel,'--panel2':t.panel2,'--border':t.border,'--bs':t.bs,
      '--text':t.text,'--dim':t.dim,'--faint':t.faint,'--hover':t.hover,'--accent':ac,
      '--crit':this.sev.crit.c,'--high':this.sev.high.c,'--med':this.sev.med.c,'--low':this.sev.low.c,
      '--accent-bar':this.hexA(ac, isLight?0.9:0.85),'--status-fg':isLight?'#062012':'#06120c',
      height:'100vh', width:'100%', display:'flex', flexDirection:'column', overflow:'hidden',
      background:t.bg, color:t.text, position:'relative',
      fontFamily:"'IBM Plex Sans',system-ui,sans-serif", fontSize:'14px',
    };

    // findings + counts
    const counts={crit:0,high:0,med:0,low:0};
    const statusColor=(st)=> st==='Fixed'?this.sev.low.c : st==='Triaging'?ac : st==='Open'?'var(--dim)':'var(--faint)';
    const findings=this.findingsData.map(f=>{
      counts[f.sev]=(counts[f.sev]||0)+1;
      const sc=this.sev[f.sev], bg=this.hexA(sc.c,0.13);
      return { ...f, sevColor:sc.c, sevLabel:sc.l, srcColor:this.srcColors[f.source]||'var(--dim)',
        ownerColor: f.owner==='unassigned'?'var(--faint)': f.owner==='you'?ac:'var(--text)',
        onSelect:()=>this.setState({selectedId:f.id, view:'investigation'}),
        pillStyle:{display:'inline-flex',alignItems:'center',padding:'3px 9px',borderRadius:'6px',background:bg,color:sc.c,border:`1px solid ${this.hexA(sc.c,0.3)}`,font:"600 10.5px 'IBM Plex Mono',monospace",letterSpacing:'.3px'},
        statusStyle:{display:'inline-flex',alignItems:'center',gap:'5px',font:"500 11.5px 'IBM Plex Sans',sans-serif",color:statusColor(f.status)},
      };
    });
    const total=findings.length;
    const filtered = s.filter==='all'?findings:findings.filter(f=>f.sev===s.filter);
    const sel = findings.find(f=>f.id===s.selectedId) || findings[0];

    // code line builder
    const buildSegs=(arr)=> (arr||[]).map(([txt,col])=>({t:txt, style:{color:P[col]||'var(--text)'}}));
    const critBg=this.hexA(this.sev.crit.c,0.1);
    const codeLines=this.codeRaw.map((segs,i)=>({
      n:i+1, mark:i===this.markLine, bg:i===this.markLine?critBg:'transparent',
      markEl:i===this.markLine?React.createElement('span',{style:{width:6,height:6,borderRadius:'50%',background:this.sev.crit.c,display:'block'}}):'',
      segs:buildSegs(segs),
    }));
    const snippet=this.snippetRaw.map(l=>({ n:l.n, bg:l.mark?critBg:'transparent', segs:buildSegs(l.segs) }));

    // dashboard
    const donut=`conic-gradient(${this.sev.crit.c} 0 ${counts.crit/total*100}%, ${this.sev.high.c} ${counts.crit/total*100}% ${(counts.crit+counts.high)/total*100}%, ${this.sev.med.c} ${(counts.crit+counts.high)/total*100}% ${(counts.crit+counts.high+counts.med)/total*100}%, ${this.sev.low.c} ${(counts.crit+counts.high+counts.med)/total*100}% 100%)`;
    const legend=[{label:'Critical',count:counts.crit,color:this.sev.crit.c},{label:'High',count:counts.high,color:this.sev.high.c},{label:'Medium',count:counts.med,color:this.sev.med.c},{label:'Low',count:counts.low,color:this.sev.low.c}];
    const metrics=[
      { label:'Open Findings', value:'47', delta:'+6 today', valueStyle:{font:"700 30px 'IBM Plex Mono',monospace",color:'var(--text)',lineHeight:1}, deltaStyle:{font:"500 11.5px 'IBM Plex Sans',sans-serif",color:'var(--dim)',marginTop:'8px'} },
      { label:'Critical', value:String(counts.crit), delta:'2 unassigned', valueStyle:{font:"700 30px 'IBM Plex Mono',monospace",color:this.sev.crit.c,lineHeight:1}, deltaStyle:{font:"500 11.5px 'IBM Plex Sans',sans-serif",color:this.sev.crit.c,marginTop:'8px'} },
      { label:'Mean Time to Remediate', value:'2.4d', delta:'▼ 0.6d this week', valueStyle:{font:"700 30px 'IBM Plex Mono',monospace",color:'var(--text)',lineHeight:1}, deltaStyle:{font:"500 11.5px 'IBM Plex Sans',sans-serif",color:ac,marginTop:'8px'} },
      { label:'Scan Coverage', value:'94%', delta:'1.2M LOC · 38 accounts', valueStyle:{font:"700 30px 'IBM Plex Mono',monospace",color:'var(--text)',lineHeight:1}, deltaStyle:{font:"500 11.5px 'IBM Plex Sans',sans-serif",color:'var(--dim)',marginTop:'8px'} },
    ];
    const trendVals=[6,4,9,7,12,8,5,11,7,18,14,9,12,8];
    const tmax=Math.max(...trendVals);
    const trendBars=trendVals.map((v,i)=>({ v, style:{height:`${v/tmax*100}%`,width:'100%',borderRadius:'4px 4px 0 0',background: i===9?this.sev.crit.c : this.hexA(ac,0.55)} }));
    const actSev={crit:this.sev.crit.c,high:this.sev.high.c,med:this.sev.med.c,low:this.sev.low.c,info:'var(--faint)'};
    const activity=[
      {t:'2m',color:this.sev.crit.c,text:'New critical: SQL injection detected in api/auth/login.go'},
      {t:'18m',color:'var(--faint)',text:'Full scan completed — 3,412 files, 1.2M LOC analyzed'},
      {t:'1h',color:this.sev.crit.c,text:'RCE confirmed on 10.2.40.11 during recon session'},
      {t:'3h',color:this.sev.low.c,text:'r.okoye marked F-1019 (stack-trace leak) as fixed'},
      {t:'5h',color:this.sev.med.c,text:'Cloud posture drift: TLS 1.0 re-enabled on alb/listener'},
    ];
    const assetsRaw=[{name:'api/auth',score:92,sev:'crit',count:4},{name:'10.2.40.11 (jenkins)',score:88,sev:'crit',count:2},{name:'services/proxy.ts',score:74,sev:'high',count:3},{name:'aws/s3/prod-assets',score:69,sev:'high',count:1},{name:'package.json',score:61,sev:'high',count:6}];
    const topAssets=assetsRaw.map(a=>({...a, sevColor:this.sev[a.sev].c, barStyle:{height:'100%',width:`${a.score}%`,borderRadius:'3px',background:this.sev[a.sev].c}}));

    // engagements
    const statusMeta={ running:{l:'Running',c:ac,pulse:true}, scanning:{l:'Scanning',c:this.sev.low.c,pulse:true}, paused:{l:'Paused',c:this.sev.med.c,pulse:false}, completed:{l:'Completed',c:'var(--faint)',pulse:false} };
    const engagements=this.engagementsData.map(e=>{
      const sm=statusMeta[e.status];
      const chips=[['C','crit',e.crit],['H','high',e.high],['M','med',e.med],['L','low',e.low]].filter(x=>x[2]>0).map(([lab,sk,n])=>({lab,n,style:{display:'inline-flex',alignItems:'center',gap:'4px',padding:'2px 7px',borderRadius:'6px',font:"600 10.5px 'IBM Plex Mono',monospace",color:this.sev[sk].c,background:this.hexA(this.sev[sk].c,0.13)}}));
      return { ...e, statusLabel:sm.l, statusColor:sm.c, isActive:(e.status==='running'||e.status==='scanning'), onOpen:()=>this.setView('findings'),
        modeLabel:e.mode==='lab'?'LAB':'ENGAGEMENT',
        modeStyle:{display:'inline-flex',alignItems:'center',padding:'2px 9px',borderRadius:'6px',font:"600 9.5px 'IBM Plex Mono',monospace",letterSpacing:'.5px',color:e.mode==='lab'?this.sev.low.c:ac,background:e.mode==='lab'?this.hexA(this.sev.low.c,0.13):this.hexA(ac,0.13),border:`1px solid ${e.mode==='lab'?this.hexA(this.sev.low.c,0.3):this.hexA(ac,0.3)}`},
        statusStyleD:{display:'inline-flex',alignItems:'center',gap:'6px',font:"600 11px 'IBM Plex Sans',sans-serif",color:sm.c},
        dotStyle:{width:'7px',height:'7px',borderRadius:'50%',flex:'0 0 7px',background:sm.c,animation:sm.pulse?'spulse 1.6s infinite':'none'},
        covStyle:{height:'100%',width:`${e.coverage}%`,borderRadius:'3px',background:ac},
        chips, toolsLabel:e.tools.join(' · ') };
    });
    const engRunning=engagements.filter(x=>x.isActive).length;
    const engPaused=engagements.filter(x=>x.status==='paused').length;
    const engDone=engagements.filter(x=>x.status==='completed').length;
    const engSummary=`${engRunning} active · ${engPaused} paused · ${engDone} completed`;
    const engCrit=this.engagementsData.reduce((a,e)=>a+e.crit,0);
    const engTotal=this.engagementsData.reduce((a,e)=>a+e.crit+e.high+e.med+e.low,0);
    const avgCov=Math.round(this.engagementsData.reduce((a,e)=>a+e.coverage,0)/this.engagementsData.length);
    const mv=(c)=>({font:"700 30px 'IBM Plex Mono',monospace",color:c,lineHeight:1});
    const md=(c)=>({font:"500 11.5px 'IBM Plex Sans',sans-serif",color:c,marginTop:'8px'});
    const repMetrics=[
      {label:'Total Findings', value:String(engTotal), delta:`across ${this.engagementsData.length} engagements`, valueStyle:mv('var(--text)'), deltaStyle:md('var(--dim)')},
      {label:'Critical Fails', value:String(engCrit), delta:'require remediation', valueStyle:mv(this.sev.crit.c), deltaStyle:md(this.sev.crit.c)},
      {label:'Active Engagements', value:String(engRunning), delta:`${engDone} completed`, valueStyle:mv(ac), deltaStyle:md('var(--dim)')},
      {label:'Avg Coverage', value:avgCov+'%', delta:'WSTG + PTES', valueStyle:mv('var(--text)'), deltaStyle:md('var(--dim)')},
    ];
    const maxRuns=Math.max(...this.toolsUsedData.map(t=>t.runs));
    const toolsUsed=this.toolsUsedData.map(t=>({ ...t, barStyle:{height:'7px',width:`${Math.round(t.runs/maxRuns*100)}%`,borderRadius:'4px',background:this.hexA(ac,0.55)}, findColor:t.findings>=3?this.sev.crit.c:(t.findings>=1?this.sev.high.c:'var(--faint)') }));
    const critEngMap={'F-1042':'acme-prod · external','F-1041':'acme-prod · external','F-1039':'acme-prod · external'};
    const criticalFails=findings.filter(f=>f.sev==='crit').map(f=>({ ...f, eng:critEngMap[f.id]||'acme-prod · external' }));

    // nav
    const views=[['engagements','Engagements','target'],['reporting','Reporting','chart'],['editor','Editor','code'],['findings','Triage Queue','filter'],['investigation','Investigation','search'],['graph','Supply Chain','share'],['terminal','Console','terminal']];
    const navItems=views.map(([key,label,ic])=>{
      const active=s.view===key;
      return { key, label, active, iconEl:this.icon(ic,20), onClick:()=>this.setView(key),
        style:{ width:'42px',height:'42px',display:'flex',alignItems:'center',justifyContent:'center',borderRadius:'11px',cursor:'pointer',position:'relative',transition:'all .14s',
          color: active?ac:'var(--faint)', background: active?this.hexA(ac,0.12):'transparent', border:`1px solid ${active?this.hexA(ac,0.22):'transparent'}` } };
    });

    // sidebar
    const showSidebar = ['editor','findings','investigation'].includes(s.view);
    const sidebarTitle = s.view==='editor'?'Explorer' : s.view==='findings'?'Filters' : s.view==='investigation'?'Outline' : '';
    const fileTree=this.fileTreeData.map(f=>({ ...f,
      glyph:f.glyph,
      style:{ display:'flex',alignItems:'center',gap:'7px',padding:'5px 8px',paddingLeft:`${8+f.depth*15}px`,borderRadius:'7px',cursor:'pointer',font:"400 12.5px 'IBM Plex Mono',monospace",
        color: f.active?'var(--text)':'var(--dim)', background: f.active?this.hexA(ac,0.1):'transparent' },
      badgeStyle:{ fontSize:'10px',fontWeight:600,color:this.sev.crit.c,background:this.hexA(this.sev.crit.c,0.16),borderRadius:'5px',padding:'1px 6px' } }));
    const sourceFacets=[{label:'SAST',count:4,color:this.srcColors.SAST},{label:'Dependency',count:1,color:this.srcColors.Dependency},{label:'Cloud',count:2,color:this.srcColors.Cloud},{label:'Secret',count:1,color:this.srcColors.Secret},{label:'Recon',count:1,color:this.srcColors.Recon}];
    const statusFacets=[{label:'Open',count:5},{label:'Triaging',count:2},{label:'Fixed',count:1},{label:'Ignored',count:0}];
    const outline=[['Description',true],['Data Flow',false],['Vulnerable Code',false],['Remediation',false],['History',false]].map(([label,act])=>({label,style:{padding:'7px 10px',borderRadius:'7px',cursor:'pointer',font:"400 12.5px 'IBM Plex Sans',sans-serif",color:act?'var(--text)':'var(--dim)',background:act?this.hexA(ac,0.1):'transparent',borderLeft:`2px solid ${act?ac:'transparent'}`}}));
    const related=findings.filter(f=>f.id!==sel.id && (f.source===sel.source||f.sev===sel.sev)).slice(0,3);

    // filter chips
    const chipData=[['all','All',total],['crit','Critical',counts.crit],['high','High',counts.high],['med','Medium',counts.med],['low','Low',counts.low]];
    const filterChips=chipData.map(([key,label,n])=>{
      const active=s.filter===key;
      return { key,label,n, onClick:()=>this.setState({filter:key}),
        style:{ display:'flex',alignItems:'center',height:'30px',padding:'0 12px',borderRadius:'8px',cursor:'pointer',font:"500 12px 'IBM Plex Sans',sans-serif",
          color:active?(isLight?'#06120c':'#06120c'):'var(--dim)', background:active?ac:'var(--panel2)', border:`1px solid ${active?ac:'var(--border)'}` } };
    });

    // meta cards (investigation)
    const metaCards=[
      {label:'CVSS',value:sel.cvss,color:sel.sevColor},
      {label:'Type',value:sel.source,color:'var(--text)'},
      {label:'Status',value:sel.status,color:'var(--text)'},
      {label:'Owner',value:sel.owner,color:sel.owner==='you'?ac:'var(--text)'},
    ];
    const flowTagColor={SOURCE:this.sev.crit.c,PROPAGATION:this.sev.high.c,SINK:this.sev.crit.c,SECRET:this.sev.crit.c,EXPOSURE:this.sev.high.c,IMPACT:this.sev.crit.c};
    const flow=(sel.flow||[]).map((f,i,arr)=>{
      const c=flowTagColor[f.tag]||ac;
      return {...f, arrow:i<arr.length-1, border:i===arr.length-1?this.hexA(this.sev.crit.c,0.4):'var(--border)',
        tagStyle:{font:"600 9.5px 'IBM Plex Mono',monospace",letterSpacing:'.6px',color:c,background:this.hexA(c,0.14),padding:'2px 7px',borderRadius:'5px'} };
    });

    // terminal
    const termColor={cmd:'var(--text)',info:ac,dim:'var(--dim)',ok:this.sev.low.c,out:'var(--dim)',err:this.sev.crit.c,warn:this.sev.high.c,crit:this.sev.crit.c};
    const termLines=this.termRaw.map(l=>({ text:l.text||'\u00a0', style:{color:termColor[l.type]||'var(--dim)', fontWeight:l.type==='cmd'?500:400, whiteSpace:'pre'} }));

    // graph
    const gnodeColor=(v)=> v?this.sev[v].c:null;
    const nodeMap={};
    const NW=130, NH=v=>v?44:34;
    const graphNodes=this.graphRaw.nodes.map(n=>{
      const vc=gnodeColor(n.vuln);
      nodeMap[n.id]={x:n.x+NW/2, y:n.y+(n.vuln?22:17)};
      return { ...n, dot: vc||(n.root?ac:'var(--faint)'),
        onSelect: n.fid?()=>this.setState({selectedId:n.fid,view:'investigation'}):()=>{},
        style:{ position:'absolute',left:n.x+'px',top:n.y+'px',width:NW+'px',padding:'8px 11px',borderRadius:'9px',zIndex:2,cursor:'pointer',
          background: n.root?this.hexA(ac,0.13):'var(--panel2)',
          border:`1px solid ${vc||(n.root?this.hexA(ac,0.4):'var(--border)')}`,
          boxShadow: vc?`0 0 0 1px ${vc}, 0 8px 22px ${this.hexA(vc,0.22)}`:'0 2px 8px rgba(0,0,0,.28)',
          font:"500 11.5px 'IBM Plex Mono',monospace", color:'var(--text)' } };
    });
    const graphEdges=this.graphRaw.edges.map(([a,b])=>{
      const A=nodeMap[a],B=nodeMap[b], tgt=this.graphRaw.nodes.find(n=>n.id===b);
      const vc=gnodeColor(tgt.vuln);
      return { x1:A.x,y1:A.y,x2:B.x,y2:B.y, color:vc?this.hexA(vc,0.5):'var(--border)', w:vc?1.6:1 };
    });
    const vulnPkgs=this.graphRaw.nodes.filter(n=>n.vuln).map(n=>({ name:n.label, cve:n.cve, color:this.sev[n.vuln].c, via:n.id==='minimist'?'lodash':n.id==='tunnel'?'axios':'direct', onSelect:n.fid?()=>this.setState({selectedId:n.fid,view:'investigation'}):()=>{} }));

    // copilot
    const copilotMsgs=this.copilotData.map(m=>({ text:m.text,
      wrapStyle:{display:'flex',justifyContent:m.role==='user'?'flex-end':'flex-start'},
      bubbleStyle: m.role==='user'
        ? {maxWidth:'85%',padding:'10px 13px',borderRadius:'12px 12px 3px 12px',background:this.hexA(ac,0.16),border:`1px solid ${this.hexA(ac,0.3)}`,color:'var(--text)',font:"400 12.5px/1.55 'IBM Plex Sans',sans-serif"}
        : {maxWidth:'90%',padding:'11px 13px',borderRadius:'12px 12px 12px 3px',background:'var(--bg)',border:'1px solid var(--border)',color:'var(--text)',font:"400 12.5px/1.6 'IBM Plex Sans',sans-serif"} }));

    // theme + accent pickers
    const themesArr=[['midnight','Midnight'],['graphite','Graphite'],['light','Light']].map(([key,label])=>({ label,
      onClick:()=>this.setState({theme:key}),
      style:{ flex:1,textAlign:'center',padding:'8px 0',borderRadius:'8px',cursor:'pointer',font:"500 11.5px 'IBM Plex Sans',sans-serif",
        color:s.theme===key?'var(--text)':'var(--dim)', background:s.theme===key?this.hexA(ac,0.14):'var(--bg)', border:`1px solid ${s.theme===key?this.hexA(ac,0.4):'var(--border)'}` } }));
    const accentList=[['Matrix','#39d98a'],['Signal','#4d9fff'],['Vapor','#b07cff'],['Alert','#ff5d6c'],['Amber','#ffb020']];
    const accentsArr=accentList.map(([name,hex])=>({ name, onClick:()=>this.setState({accent:hex}),
      style:{ width:'28px',height:'28px',borderRadius:'50%',cursor:'pointer',background:hex, boxShadow: s.accent===hex?`0 0 0 2px var(--panel2), 0 0 0 4px ${hex}`:'none', transition:'box-shadow .12s' } }));
    const accentName=(accentList.find(a=>a[1]===ac)||['Custom'])[0];

    // command palette
    const ico=(n)=>this.icon(n,16);
    const cmd=(label,hint,key,iconName,fn)=>({label,hint,key,iconEl:ico(iconName),onClick:()=>{fn();this.setState({paletteOpen:false});}});
    const paletteCmds=[
      cmd('Go to Engagements','home · running engagements','E','target',()=>this.setView('engagements')),
      cmd('Open Reporting','findings · tools · analytics','R','chart',()=>this.setView('reporting')),
      cmd('Open Triage Queue','9 findings','F','filter',()=>this.setView('findings')),
      cmd('Run full scan','SAST + secrets + cloud + recon','⌘R','bolt',()=>this.setView('terminal')),
      cmd('Open recon console','interactive shell','T','terminal',()=>this.setView('terminal')),
      cmd('View supply-chain graph','dependency tree','G','share',()=>this.setView('graph')),
      cmd('Investigate F-1042','SQL injection · Critical','↵','search',()=>this.setState({selectedId:'F-1042',view:'investigation'})),
    ];

    return {
      rootStyle,
      shieldIcon:this.icon('shield',16), shieldIconSm:this.icon('shield',13),
      searchIcon:this.icon('search',15), slidersIcon:this.icon('sliders',18),
      sparkleIcon:this.icon('sparkle',17), boltIcon:this.icon('bolt',14),
      closeIcon:this.icon('close',16), sendIcon:this.icon('send',16),
      gearBtnStyle:{ width:'30px',height:'30px',display:'flex',alignItems:'center',justifyContent:'center',borderRadius:'8px',cursor:'pointer',color:s.settingsOpen?ac:'var(--dim)' },
      copilotBtnStyle:{ width:'30px',height:'30px',display:'flex',alignItems:'center',justifyContent:'center',borderRadius:'8px',cursor:'pointer',color:s.copilotOpen?ac:'var(--dim)' },

      isEngagements:s.view==='engagements', isReporting:s.view==='reporting', isEditor:s.view==='editor', isFindings:s.view==='findings',
      isInvestigation:s.view==='investigation', isGraph:s.view==='graph', isTerminal:s.view==='terminal',
      showSidebar, sidebarTitle, navItems, fileTree, sourceFacets, statusFacets, outline, related,

      findings, filtered, total, totalFindings:total, filteredCount:filtered.length, counts,
      filterChips, sel, metaCards, flow, snippet, codeLines,

      donut, legend, metrics:repMetrics, trendBars, activity, topAssets,
      engagements, engSummary, toolsUsed, criticalFails,
      graphNodes, graphEdges, vulnPkgs, termLines,
      copilotMsgs, chips:this.chipsData,
      themesArr, accentsArr, accentName, paletteCmds,

      settingsOpen:s.settingsOpen, copilotOpen:s.copilotOpen, paletteOpen:s.paletteOpen,
      toggleSettings:()=>this.setState({settingsOpen:!s.settingsOpen}),
      toggleCopilot:()=>this.setState({copilotOpen:!s.copilotOpen}),
      openPalette:()=>this.setState({paletteOpen:true}),
      closePalette:()=>this.setState({paletteOpen:false}),
      stop:(e)=>e.stopPropagation(),
      runScan:()=>this.setView('terminal'),
      goFindings:()=>this.setView('findings'),
      newEngagement:()=>this.setView('findings'),
      openSqli:()=>this.setState({selectedId:'F-1042',view:'investigation'}),
      askFix:()=>this.setState({copilotOpen:true}),
    };
  }

  componentDidMount(){
    this._kd=(e)=>{
      if((e.metaKey||e.ctrlKey)&&e.key.toLowerCase()==='k'){ e.preventDefault(); this.setState(s=>({paletteOpen:!s.paletteOpen})); }
      if(e.key==='Escape') this.setState({paletteOpen:false,settingsOpen:false});
    };
    window.addEventListener('keydown',this._kd);
  }
  componentWillUnmount(){ window.removeEventListener('keydown',this._kd); }
}
