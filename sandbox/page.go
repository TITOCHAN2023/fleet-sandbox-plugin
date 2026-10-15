package sandbox

const Page = `<html><head><meta charset="utf-8"><style>
:root{color-scheme:light dark}body{font:14px system-ui;margin:20px}label{display:block;margin:12px 0}input,textarea,button{font:inherit;padding:8px}input,textarea{width:90%;box-sizing:border-box}button{margin-right:8px}pre{white-space:pre-wrap;overflow-wrap:anywhere}small{display:block}
</style></head><body>
<h2>原生沙箱 / Native sandbox</h2>
<p>每次执行使用独立工作区，禁止外连。原件不会自动回写。采集覆盖以检测结果为准。<br>Each run uses a private workspace with no network. Input files are never automatically updated. Check coverage below.</p>
<pre id="capability"></pre>
<label>授权输入目录 / Authorized input directory<input id="root" placeholder="Absolute device path"></label>
<label>文件视图 / File view<select id="viewMode"><option value="copy">独立副本 / Private copy</option><option value="demand">按需加密文件层（Linux） / Demand file layer (Linux)</option></select></label>
<small>按需模式在任务结束时固化输入；源变化或中断可能产生明确标注的恢复缺口。<br>Demand mode checkpoints at completion; changed sources or interruptions may leave reported recovery gaps.</small>
<button id="configure">保存本地策略 / Save local policy</button>
<label>本机程序 / Native program<input id="command" placeholder="/bin/sh or C:\Windows\System32\cmd.exe"></label>
<label>参数数组 / Arguments JSON<textarea id="args">[]</textarea></label>
<label>工作区内目录 / Relative working directory<input id="cwd"></label>
<button id="run">执行 / Run</button>
<label>沙箱编号 / Sandbox ID<input id="sandboxId"></label>
<button id="encryptStorage">加密已有工作区 / Encrypt stored workspaces</button>
<button id="list">工作区列表 / List workspaces</button>
<label>新导出目录 / New export directory<input id="destination" placeholder="Absolute new directory"></label>
<button id="export">导出结果 / Export result</button>
<button id="inspect">查看结果 / Inspect</button><button id="discard">丢弃 / Discard</button>
<pre id="result"></pre>
<script>
let port,seq=0;const calls=new Map();const $=id=>document.getElementById(id);
function call(action,input={}){return new Promise((resolve,reject)=>{const id=String(++seq);calls.set(id,{resolve,reject});port.postMessage({type:'fleet.call',id,action,input});});}
async function show(action,input){try{$('result').textContent='等待授权或执行中 / Waiting for approval or running…';const result=await call(action,input);if(result.sandbox_id)$('sandboxId').value=result.sandbox_id;$('result').textContent=JSON.stringify(result,null,2);}catch(error){$('result').textContent=error.message;}}
window.addEventListener('message',async event=>{if(port||event.source!==parent||event.data?.type!=='fleet.init'||!event.ports[0])return;port=event.ports[0];document.documentElement.style.colorScheme=event.data.theme==='dark'?'dark':'light';port.onmessage=({data})=>{if(data.type==='fleet.settings'){document.documentElement.style.colorScheme=data.theme==='dark'?'dark':'light';document.documentElement.lang=data.locale||'en';return;}const pending=calls.get(data.id);if(!pending)return;calls.delete(data.id);data.error?pending.reject(new Error(data.error)):pending.resolve(data.result);};
try{const cap=await call('probe');$('capability').textContent=JSON.stringify(cap,null,2);$('viewMode').options[1].disabled=!cap.backend?.startsWith('linux-');const cfg=await call('config');$('root').value=cfg.root||'';$('viewMode').value=cfg.view_mode||'copy';}catch(error){$('result').textContent=error.message;}});
$('configure').onclick=()=>show('configure',{root:$('root').value,view_mode:$('viewMode').value});
$('run').onclick=()=>{try{const args=JSON.parse($('args').value);if(!Array.isArray(args)||args.some(x=>typeof x!=='string'))throw new Error('args must be a string array');show('run',{command:$('command').value,args,cwd:$('cwd').value});}catch(error){$('result').textContent=error.message;}};
$('encryptStorage').onclick=()=>show('encrypt_storage',{});
$('list').onclick=()=>show('list',{});$('export').onclick=()=>show('export',{sandbox_id:$('sandboxId').value,destination:$('destination').value});
$('inspect').onclick=()=>show('inspect',{sandbox_id:$('sandboxId').value});$('discard').onclick=()=>show('discard',{sandbox_id:$('sandboxId').value});
</script></body></html>`
