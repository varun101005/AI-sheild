// Run: cd dashboard/tests && npm install jsdom && node smoke.js   (opens the dashboard in a fake browser and clicks through it)
const {JSDOM}=require("jsdom");const fs=require("fs");
const html=fs.readFileSync(require("path").join(__dirname,"..","index.html"),"utf8");
const dom=new JSDOM(html,{runScripts:"dangerously",url:"file:///dash/index.html",pretendToBeVisual:true,
  beforeParse(w){w.matchMedia=()=>({matches:true});w.addEventListener("error",e=>{console.log("PAGE ERROR:",e.message);process.exitCode=1})}});
const w=dom.window,d=w.document,$=id=>d.getElementById(id),sleep=ms=>new Promise(r=>setTimeout(r,ms));
(async()=>{
  const ok=(c,m)=>{console.log((c?"PASS ":"FAIL ")+m);if(!c)process.exitCode=1};
  ok(w.eval("CFG.useMock")===true,"file:// => mock mode");
  $("sample").click(); ok($("code").value.includes("API_KEY"),"sample loads");
  ok($("gut").textContent.split("\n").length>5,"line numbers");
  $("run").click(); await sleep(3200);
  ok(d.querySelectorAll("tr.f").length===4,"4 finding rows");
  d.querySelector("tr.f").click(); ok($("detail").innerHTML.includes("Suggested fix"),"detail shows fix");
  ok($("detail").innerHTML.includes("Verified after"),"verified message");
  $("showd").click(); ok(d.querySelectorAll("tr.dis").length===2,"dismissed rows");
  d.querySelector("tr.dis").click(); ok($("detail").innerHTML.includes("Why it was dismissed"),"dismissed detail");
  for(const t of ["github","files","paste"]){d.querySelector('.tab[data-m="'+t+'"]').click();ok(!$("m-"+t).hidden,"tab "+t)}
  d.querySelector('.tab[data-m="github"]').click(); $("repo").value="notaurl"; $("run").click(); await sleep(50);
  ok($("err").textContent.includes("GitHub URL"),"bad repo url message");
  $("nav-build").click(); ok(!$("builder").hidden&&$("scanner").hidden,"builder tab opens");
  $("bgo").click(); ok($("berr").textContent.includes("Describe"),"empty prompt message");
  $("prompt").value="a coffee shop site"; $("bgo").click(); await sleep(50);
  ok(!$("bout").hidden&&$("bfiles").querySelectorAll(".ftab").length===2,"mock build renders tabs");
  ok($("pv").srcdoc.includes("Demo prototype"),"preview iframe gets srcdoc"); ok($("pv").getAttribute("sandbox")==="allow-scripts","iframe sandboxed");
  d.querySelectorAll("#bfiles .ftab")[1].click(); ok($("bcode").textContent.includes("Demo prototype"),"code view");
  $("nav-scan").click(); ok(!$("scanner").hidden,"back to scanner");
  // no-patch finding renders safely
  w.eval(`state={findings:[{id:"F-9",file:"a.py",line:1,cwe:"CWE-1",type:"T",severity:"low",confidence:.5,signals:{static:{hit:true,note:"r"},llm:{verdict:"unsure",score:0},clf:{score:null}},consistency:{runs:0,same:0},explanation:"e",code:["x"],fix:{patch:[],verified:false,attempts:0}}],dismissed:[]};selected="F-9";renderDetail()`);
   ok($("detail").innerHTML.includes("No fix was generated")&&$("detail").innerHTML.includes("Not available"),"empty-patch and null-classifier render");
  process.exit(process.exitCode||0);
})();
