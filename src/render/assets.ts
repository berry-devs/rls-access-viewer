/**
 * CSS / JS embedded in the viewer. The CSP allows them by SHA-256 hash, so never interpolate
 * dynamic values into these strings (the hash would no longer match and the browser would block them).
 * Inline style attributes and on* handlers are blocked by the CSP as well, so do not use them.
 */

export const STYLE = `
:root{--bg:#fff;--fg:#1f2328;--muted:#656d76;--line:#d0d7de;--panel:#f6f8fa;--ok:#1a7f37;--warn:#9a6700;--danger:#cf222e;--link:#0969da;--tag:#8250df}
@media (prefers-color-scheme: dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#8d96a0;--line:#30363d;--panel:#161b22;--ok:#3fb950;--warn:#d29922;--danger:#f85149;--link:#4493f8;--tag:#a371f7}}
*{box-sizing:border-box}
body{margin:0;padding:0 16px 48px;background:var(--bg);color:var(--fg);font:14px/1.55 system-ui,-apple-system,"Hiragino Sans","Noto Sans JP",sans-serif}
a{color:var(--link)}
header{padding:16px 0 8px;border-bottom:1px solid var(--line)}
h1{font-size:20px;margin:0 0 4px}h1 small{font-weight:normal;color:var(--muted);font-size:14px}
h2{font-size:18px;margin:28px 0 8px}h3{font-size:16px;margin:20px 0 6px}h4{font-size:14px;margin:14px 0 4px}h5{font-size:13px;margin:0 0 6px}
.meta,.muted,.legend{color:var(--muted)}
.warnings{display:flex;gap:12px;flex-wrap:wrap;list-style:none;padding:0;margin:8px 0}
.warnings li{padding:4px 10px;border:1px solid var(--line);border-radius:6px}
.warnings li.warn{border-color:var(--danger)}.warnings li.warn a{color:var(--danger);font-weight:bold}
.tabs{position:sticky;top:0;z-index:2;display:flex;gap:4px;flex-wrap:wrap;background:var(--bg);padding:8px 0;border-bottom:1px solid var(--line)}
.tabs a{padding:6px 12px;border:1px solid var(--line);border-radius:6px;text-decoration:none}
.tabs a.active{background:var(--panel);font-weight:bold}
.js .tab{display:none}.js .tab.active{display:block}
.scroll{overflow-x:auto}
table{border-collapse:collapse}
th,td{border:1px solid var(--line);padding:4px 8px;vertical-align:top;text-align:left}
.matrix th:first-child{position:sticky;left:0;background:var(--bg)}
.matrix td{min-width:110px}
.row-danger th,.row-danger td{background:color-mix(in srgb,var(--danger) 10%,transparent)}
a.cell{display:block;text-decoration:none;color:inherit}
.badge{display:inline-block;padding:0 6px;border:1px solid var(--line);border-radius:10px;font-size:12px;white-space:nowrap}
.badge.ok{color:var(--ok);border-color:var(--ok)}.badge.warn{color:var(--warn);border-color:var(--warn)}
.badge.danger{color:#fff;background:var(--danger);border-color:var(--danger)}
.danger-text{color:var(--danger);font-weight:bold}
.note{color:var(--warn);margin:4px 0}
.tag{display:inline-block;margin-left:6px;padding:0 6px;border-radius:4px;font-size:12px;color:#fff;background:var(--tag)}
.table-detail{border-top:2px solid var(--line);margin-top:24px}
.cell-detail{border-left:3px solid var(--line);padding-left:12px;margin:12px 0}
.cell-detail:target,.table-detail:target>h2,.fn:target{outline:2px solid var(--link);outline-offset:4px}
.roles{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:8px}
.role{border:1px solid var(--line);border-radius:6px;padding:8px;background:var(--panel)}
.composition{margin:6px 0}.clabel{font-weight:bold;margin-bottom:4px}
.grp{border-left:3px solid var(--line);padding:2px 0 2px 8px;margin:4px 0}
.grp.and{border-left-color:var(--warn)}.grp.or{border-left-color:var(--ok)}
.grp ul{margin:2px 0;padding-left:16px}
.op-label{font-size:12px;color:var(--muted)}
.and-join{font-weight:bold;color:var(--warn);margin:2px 0}
.cond{margin:2px 0;padding:2px 4px;border-radius:4px;background:var(--bg)}
.cond.raw{border:1px dashed var(--warn)}
.pname{font-weight:bold}
code,pre{font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}
pre{white-space:pre-wrap;word-break:break-word;background:var(--panel);padding:8px;border-radius:6px;margin:4px 0}
code .k{color:#cf222e;font-weight:bold}code .s{color:#0a3069}code .n{color:#0550ae}code .f{color:#8250df}code .t,code .o{color:var(--muted)}
@media (prefers-color-scheme: dark){code .k{color:#ff7b72}code .s{color:#a5d6ff}code .n{color:#79c0ff}code .f{color:#d2a8ff}}
.fn{border-top:1px solid var(--line)}.fn-warn h3{color:var(--danger)}
.hidden{display:none!important}
.fn-rules{border-left:3px solid var(--tag);padding:2px 0 2px 10px;margin:6px 0}
.fn-rules .sub{font-weight:bold;margin:8px 0 2px}
.helper{border-top:1px dashed var(--line);margin-top:6px;padding-top:4px}
.via{font-size:12px;color:var(--tag);font-weight:bold}
pre.comment{background:none;border-left:2px solid var(--line);padding:2px 8px;color:var(--muted);white-space:pre-wrap}
ol.path{margin:2px 0;padding-left:0;list-style:none}
ul.guards>li{margin-bottom:8px}
.raise{color:var(--danger)}
.flags{margin:2px 0}
.pfn{margin:2px 0}.pfn>summary{cursor:pointer}.pfn[open]>summary{margin-bottom:4px}
input[type=search]{width:min(420px,100%);padding:6px 8px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg)}
`;

/**
 * Kept as its own constant so tests can evaluate it. A malformed hash such as "#%" makes decodeURIComponent
 * throw; falling back to the raw text lets route() still show the default tab instead of hiding every tab.
 */
export const DECODE_HASH_SOURCE = `function decodeHash(hash){
  var raw=hash.charAt(0)==="#"?hash.slice(1):hash;
  try{return decodeURIComponent(raw)}catch(e){return raw}
}`;

export const SCRIPT = `
${DECODE_HASH_SOURCE}
(function(){
  var root=document.documentElement;root.classList.add("js");
  var tabs=[].slice.call(document.querySelectorAll(".tab"));
  var links=[].slice.call(document.querySelectorAll(".tabs a"));
  function show(id){
    tabs.forEach(function(t){t.classList.toggle("active",t.id===id)});
    links.forEach(function(a){a.classList.toggle("active",a.getAttribute("data-tab")===id)});
  }
  function route(){
    var h=decodeHash(location.hash);
    var el=h?document.getElementById(h):null;
    var tab=el?(el.classList.contains("tab")?el:el.closest(".tab")):null;
    show(tab?tab.id:"tab-matrix");
    if(el&&!el.classList.contains("tab")){
      var d=el.closest("details");if(d)d.open=true;
      el.scrollIntoView();
    }
  }
  window.addEventListener("hashchange",route);route();
  var filter=document.getElementById("filter");
  if(filter){filter.addEventListener("input",function(){
    var q=filter.value.trim().toLowerCase();
    [].forEach.call(document.querySelectorAll("#tab-matrix .matrix tbody tr,#tab-matrix .table-detail"),function(el){
      var n=(el.getAttribute("data-name")||"").toLowerCase();
      el.classList.toggle("hidden",q!==""&&n.indexOf(q)<0);
    });
  });}
  var secdef=document.getElementById("fn-secdef-only"),warn=document.getElementById("fn-warn-only");
  function applyFn(){
    [].forEach.call(document.querySelectorAll("#fn-list .fn"),function(el){
      var hide=(secdef&&secdef.checked&&!el.classList.contains("fn-secdef"))||(warn&&warn.checked&&!el.classList.contains("fn-warn"));
      el.classList.toggle("hidden",!!hide);
    });
  }
  if(secdef)secdef.addEventListener("change",applyFn);
  if(warn)warn.addEventListener("change",applyFn);
})();
`;
