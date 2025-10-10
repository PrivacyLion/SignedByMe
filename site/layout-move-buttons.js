(function(){
  function onLoaded(fn){
    if (document.readyState === "complete") { setTimeout(fn,0); }
    else window.addEventListener("load", fn, { once:true });
  }
  function findDemoCard(){
    const lg = Array.from(document.querySelectorAll("legend"))
      .find(el => /signedbyme\s+demo/i.test((el.textContent||"")));
    return lg ? (lg.parentElement || lg) : null;
  }
  function findByExactText(pattern){
    const want = pattern.toLowerCase();
    const els = Array.from(document.querySelectorAll("button, a, .btn"));
    return els.find(el => ((el.textContent||"").trim().toLowerCase() === want));
  }

  onLoaded(function(){
    try {
      const card = findDemoCard();
      if (!card) return;

      // Create a toolbar in the demo card (first child area) to hold the 2 real buttons
      let bar = card.querySelector("#demo-toolbar");
      if (!bar) {
        bar = document.createElement("div");
        bar.id = "demo-toolbar";
        bar.style.display = "flex";
        bar.style.flexWrap = "wrap";
        bar.style.gap = "8px";
        bar.style.margin = "6px 0 10px 0";
        // Put it at the top of the card, before existing demo buttons row
        card.insertBefore(bar, card.firstElementChild.nextElementSibling || card.firstChild);
      }

      // Find the ORIGINAL top buttons by exact label
      const startPay = findByExactText("Start EA Login (pay user)");
      const verify   = findByExactText("Verify payment");

      // Re-parent in requested order: Start then Verify (only if found & not already moved)
      if (startPay && !startPay.dataset.movedIntoDemo) {
        bar.appendChild(startPay);
        startPay.dataset.movedIntoDemo = "1";
      }
      if (verify && !verify.dataset.movedIntoDemo) {
        bar.appendChild(verify);
        verify.dataset.movedIntoDemo = "1";
      }
    } catch (e) {
      console.error("layout-move-buttons failed:", e);
    }
  });
})();
