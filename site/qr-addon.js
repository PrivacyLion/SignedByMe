(function(){
  const API = "https://api.beta.privacy-lion.com";
  function $(s,r=document){return r.querySelector(s)}
  function ready(f){document.readyState!=="loading"?f():document.addEventListener("DOMContentLoaded",f)}
  function renderQR(target, text){
    target.innerHTML="";
    try{
      if (window.QRCode && typeof window.QRCode.toCanvas==="function"){
        window.QRCode.toCanvas(text,{width:256},(e,cv)=>{ if(e){target.textContent=text;} else target.appendChild(cv);}); return;
      }
      if (typeof window.QRCode==="function"){ const d=document.createElement("div"); target.appendChild(d); new window.QRCode(d,{text,width:256,height:256}); return; }
    }catch(_){}
    const pre=document.createElement("pre"); pre.textContent=text; target.appendChild(pre);
  }
  ready(function(){
    const qr=$("#qr"), l1=$("#status-line-1"), l2=$("#status-line-2"), pre=$("#login-status-json");
    const bQR=$("#btn-demo-qr"), bREAL=$("#btn-demo-real"), bSTAT=$("#btn-demo-status"), bPRE=$("#btn-demo-preimg");
    const bPING=$("#btn-ping"), bOA=$("#btn-openapi"), bINV=$("#btn-invoice");
    let cid=null, phash=null, poll=null;

    if(bQR) bQR.onclick = async ()=>{
      try{
        const r=await fetch(`${API}/v1/login/start`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({did_pubkey:"npub1abc",amount_sats:21})});
        const j=await r.json(); cid=j.login_challenge_id||cid; phash=j.payment_hash||phash;
        l1.textContent=`Challenge: ${cid||""}`; l2.textContent=`Payment hash: ${phash||""}`;
        renderQR(qr, j.invoice||""); pre.textContent=JSON.stringify(j,null,2); startPoll();
      }catch(e){ alert("Start failed"); console.error(e); }
    };

    if(bREAL) bREAL.onclick = async ()=>{
      const inv=prompt("Paste BOLT-11 invoice:"); if(!inv) return;
      try{
        const r=await fetch(`${API}/v1/login/start`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({did_pubkey:"npub1abc",amount_sats:21,invoice:inv})});
        const j=await r.json(); cid=j.login_challenge_id||cid; phash=j.payment_hash||phash;
        l1.textContent=`Challenge: ${cid||""}`; l2.textContent=`Payment hash: ${phash||""}`;
        renderQR(qr, j.invoice||inv); pre.textContent=JSON.stringify(j,null,2); startPoll();
      }catch(e){ alert("Start (REAL) failed"); console.error(e); }
    };

    if(bSTAT) bSTAT.onclick = async ()=>{
      if(!cid){ alert("No challenge yet"); return; }
      try{ const r=await fetch(`${API}/v1/login/${cid}`); pre.textContent=JSON.stringify(await r.json(),null,2); }catch(e){ alert("Status failed"); console.error(e); }
    };

    if(bPRE) bPRE.onclick = async ()=>{
      if(!phash){ alert("No payment hash yet"); return; }
      const preimg=prompt("Enter 64-hex preimage:"); if(!preimg) return;
      try{
        const r=await fetch(`${API}/v1/login/verify`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({payment_hash:phash,preimage:preimg})});
        pre.textContent=JSON.stringify(await r.json(),null,2);
      }catch(e){ alert("Verify failed"); console.error(e); }
    };

    if(bPING) bPING.onclick = async ()=>{ try{ const r=await fetch(`${API}/healthz`); l1.textContent=`healthz: ${r.status}`; l2.textContent=await r.text(); }catch(e){ l2.textContent=String(e);} };
    if(bOA)   bOA.onclick   = async ()=>{ try{ const r=await fetch(`${API}/openapi.json`); pre.textContent=JSON.stringify(await r.json(),null,2);}catch(e){pre.textContent=String(e);} };
    if(bINV)  bINV.onclick  = async ()=>{ try{ const r=await fetch(`${API}/v1/invoice`); pre.textContent=await r.text(); }catch(e){ pre.textContent=String(e);} };

    function startPoll(){
      if(poll) clearInterval(poll);
      if(!cid) return;
      poll=setInterval(async ()=>{
        try{
          const r=await fetch(`${API}/v1/login/${cid}`);
          const j=await r.json(); pre.textContent=JSON.stringify(j,null,2);
          if((j.status||"").toLowerCase()==="paid") clearInterval(poll);
        }catch(_){}
      },2000);
    }
  });
})();
