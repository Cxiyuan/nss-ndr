package main

import "net/http"

func handleUI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}

const indexHTML = `<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<title>NSS-NDR Detections</title>
<style>
body{font-family:system-ui,sans-serif;margin:2rem;background:#111;color:#ddd}
table{border-collapse:collapse;width:100%}
td,th{border:1px solid #333;padding:6px;text-align:left}
pre{white-space:pre-wrap;font-size:12px;max-width:60ch}
input,textarea{background:#222;color:#ddd;border:1px solid #555;padding:4px}
button{cursor:pointer}
</style>
</head>
<body>
<h1>NSS-NDR Detections</h1>
<div id="status"></div>
<h2>新增规则</h2>
<input id="name" placeholder="规则名" size="24">
<label><input type="checkbox" id="enabled" checked> 启用</label><br>
<textarea id="rule" rows="4" cols="80" placeholder="Suricata 规则，如：alert tcp any any -> any any (msg:&quot;test&quot;; sid:9000001; rev:1;)"></textarea><br>
<input id="threshold" size="60" placeholder="可选阈值/抑制：如 type limit, track by_src, count 1, seconds 60"><br>
<button onclick="createRule()">提交</button>
<h2>规则列表</h2>
<table id="rules">
<tr><th>ID</th><th>名称</th><th>类型</th><th>状态</th><th>规则</th><th>操作</th></tr>
</table>
<script>
async function load() {
  var r = await fetch('/api/rules');
  var d = await r.json();
  var h = await (await fetch('/api/health')).json();
  document.getElementById('status').textContent = '探针: ' + h.probe_id;
  var t = document.getElementById('rules');
  t.querySelectorAll('tr:not(:first-child)').forEach(function(x){x.remove();});
  d.rules.forEach(function(x){
    var tr = document.createElement('tr');
    var td = '<td>'+x.id+'</td><td>'+x.name+'</td><td>'+x.type+'</td><td>'+x.enabled+'</td>';
    td += '<td><pre>'+x.rule.slice(0,200)+'</pre></td>';
    td += '<td><button onclick="toggle(\''+x.id+'\','+!x.enabled+')">'+(x.enabled?'禁用':'启用')+'</button> ';
    td += '<button onclick="del(\''+x.id+'\')">删除</button></td>';
    tr.innerHTML = td;
    t.appendChild(tr);
  });
}
async function createRule() {
  var body = {name: document.getElementById('name').value, rule: document.getElementById('rule').value, threshold: document.getElementById('threshold').value, enabled: document.getElementById('enabled').checked};
  var r = await fetch('/api/rules', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
  if (r.status === 201) { alert('已添加并重载'); document.getElementById('rule').value=''; }
  else { alert((await r.json()).error || '失败'); }
  load();
}
async function toggle(id, e) {
  await fetch('/api/rules/'+id+(e?'/enable':'/disable'), {method:'POST'});
  load();
}
async function del(id) {
  if (!confirm('删除该规则？')) return;
  await fetch('/api/rules/'+id, {method:'DELETE'});
  load();
}
load();
</script>
</body>
</html>`
