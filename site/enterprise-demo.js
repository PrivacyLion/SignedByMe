/**
 * SignedByMe Enterprise Demo
 * Tests the stateless authentication flow with Strike API integration
 */
(function() {
  const API = "https://api.beta.privacy-lion.com";
  
  // State
  let state = {
    sessionToken: null,
    sessionId: null,
    qrData: null,
    invoice: null,
    did: null,
    stwoVerified: false,
    bindingVerified: false,
    idToken: null,
    amountSats: 100,
    strikeApiKey: null
  };

  // DOM helpers
  const $ = (sel) => document.querySelector(sel);
  const show = (id) => document.getElementById(id)?.classList.remove('hidden');
  const hide = (id) => document.getElementById(id)?.classList.add('hidden');
  
  function setStep(n) {
    for (let i = 1; i <= 4; i++) {
      const el = $(`#step${i}`);
      el.classList.remove('active', 'done');
      if (i < n) el.classList.add('done');
      if (i === n) el.classList.add('active');
    }
  }

  function setStatus(id, msg, type = '') {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = typeof msg === 'string' ? msg : JSON.stringify(msg, null, 2);
    el.className = 'status ' + type;
    show(id);
  }

  async function apiPost(path, body) {
    const resp = await fetch(`${API}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await resp.json();
    if (!resp.ok) throw data;
    return data;
  }

  async function apiGet(path) {
    const resp = await fetch(`${API}${path}`);
    const data = await resp.json();
    if (!resp.ok) throw data;
    return data;
  }

  // Strike API
  async function strikePayInvoice(invoice) {
    if (!state.strikeApiKey) throw new Error('Strike API key not configured');
    
    // Create payment quote
    const quoteResp = await fetch('https://api.strike.me/v1/payment-quotes/lightning', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${state.strikeApiKey}`
      },
      body: JSON.stringify({
        lnInvoice: invoice,
        sourceCurrency: 'BTC'
      })
    });
    
    if (!quoteResp.ok) {
      const err = await quoteResp.json();
      throw new Error(err.data?.message || err.message || 'Strike quote failed');
    }
    
    const quote = await quoteResp.json();
    
    // Execute payment
    const payResp = await fetch(`https://api.strike.me/v1/payment-quotes/${quote.paymentQuoteId}/execute`, {
      method: 'PATCH',
      headers: {
        'Authorization': `Bearer ${state.strikeApiKey}`
      }
    });
    
    if (!payResp.ok) {
      const err = await payResp.json();
      throw new Error(err.data?.message || err.message || 'Strike payment failed');
    }
    
    const payment = await payResp.json();
    
    // Get the preimage from the completed payment
    // Strike returns it in the payment result
    if (payment.preimage) {
      return payment.preimage;
    }
    
    // If not immediately available, poll for completion
    // (Strike payments are usually instant)
    throw new Error('Payment sent but preimage not returned. Check Strike dashboard.');
  }

  // Create session
  async function createSession() {
    const name = $('#enterprise-name').value || 'Acme Corp';
    const amount = parseInt($('#amount-sats').value) || 100;
    const strikeKey = $('#strike-api-key').value.trim();
    
    state.amountSats = amount;
    state.strikeApiKey = strikeKey || null;

    try {
      setStatus('status-create', 'Creating session...', 'pending');
      
      const resp = await apiPost('/v1/enterprise/session', {
        enterprise_id: 'demo-' + Date.now(),
        enterprise_name: name,
        amount_sats: amount,
        callback_url: 'https://httpbin.org/post', // Test callback
        domain: window.location.hostname || 'signedby.me'
      });

      state.sessionToken = resp.session_token;
      state.sessionId = resp.session_id;
      state.qrData = resp.qr_data;

      setStatus('status-create', `✓ Session created!\nID: ${resp.session_id}\nAmount: ${amount} sats\nExpires: ${new Date(resp.expires_at * 1000).toLocaleString()}`, 'success');

      // Show QR card
      setTimeout(() => showQR(), 500);
      setStep(2);

    } catch (e) {
      console.error(e);
      setStatus('status-create', '✗ Error: ' + (e.detail || e.message || JSON.stringify(e)), 'error');
    }
  }

  function showQR() {
    hide('card-create');
    show('card-qr');

    // Generate QR
    const container = $('#qr-container');
    container.innerHTML = '';
    new QRCode(container, {
      text: state.qrData,
      width: 220,
      height: 220,
      colorDark: '#3B82F6',
      colorLight: '#ffffff'
    });

    // Show deep link
    $('#deep-link').textContent = state.qrData;

    // Update status
    let statusMsg = `Session: ${state.sessionId}\n\nWaiting for user to scan QR and submit invoice...\n\n`;
    if (state.strikeApiKey) {
      statusMsg += '✓ Strike API configured — real payments enabled!';
    } else {
      statusMsg += 'ℹ No Strike API key — using manual/simulated payments';
    }
    setStatus('status-waiting', statusMsg, 'pending');
  }

  function copyDeepLink() {
    navigator.clipboard.writeText(state.qrData);
    const btn = $('#btn-copy-link');
    const original = btn.textContent;
    btn.textContent = '✓ Copied!';
    setTimeout(() => btn.textContent = original, 2000);
  }

  function newSession() {
    state = { 
      sessionToken: null, sessionId: null, qrData: null, 
      invoice: null, did: null, stwoVerified: false, 
      bindingVerified: false, idToken: null, amountSats: 100,
      strikeApiKey: state.strikeApiKey // Keep API key
    };
    hide('card-qr');
    hide('card-invoice');
    hide('card-verified');
    show('card-create');
    hide('status-create');
    setStep(1);
  }

  // Manually enter invoice (since we can't receive webhooks in browser)
  function showInvoiceEntry() {
    const invoice = prompt('Enter the BOLT11 invoice from the mobile app:');
    if (!invoice) return;
    
    const did = prompt('Enter the user DID:', 'did:btcr:02...');
    if (!did) return;

    state.invoice = invoice.trim();
    state.did = did.trim();
    state.stwoVerified = true;
    state.bindingVerified = true;

    showInvoiceCard();
  }

  function showInvoiceCard() {
    hide('card-qr');
    show('card-invoice');
    setStep(3);

    $('#invoice-display').textContent = state.invoice;
    $('#user-did').value = state.did;
    $('#stwo-status').value = state.stwoVerified ? '✓ STWO Verified' : '⚠ Not verified';
    $('#amount-display').textContent = state.amountSats;

    // Show Strike section if API key is configured
    if (state.strikeApiKey) {
      show('strike-pay-section');
    } else {
      hide('strike-pay-section');
    }
  }

  async function payWithStrike() {
    if (!state.strikeApiKey) {
      alert('Strike API key not configured');
      return;
    }

    const btn = $('#btn-strike-pay');
    const originalText = btn.textContent;
    btn.textContent = 'Paying...';
    btn.disabled = true;

    try {
      setStatus('status-invoice', '⚡ Sending payment via Strike...', 'pending');
      
      const preimage = await strikePayInvoice(state.invoice);
      
      $('#preimage-input').value = preimage;
      setStatus('status-invoice', `✓ Payment sent!\nPreimage: ${preimage}\n\nConfirming with API...`, 'success');
      
      // Auto-confirm
      await confirmPayment();

    } catch (e) {
      console.error(e);
      setStatus('status-invoice', '✗ Strike payment failed: ' + e.message, 'error');
    } finally {
      btn.textContent = originalText;
      btn.disabled = false;
    }
  }

  async function confirmPayment() {
    const preimage = $('#preimage-input').value.trim();
    
    if (!preimage || preimage.length !== 64) {
      setStatus('status-invoice', '⚠ Please enter a valid 64-character hex preimage', 'error');
      return;
    }

    try {
      setStatus('status-invoice', 'Confirming payment...', 'pending');

      const resp = await apiPost('/v1/login/confirm', {
        session_token: state.sessionToken,
        preimage: preimage
      });

      if (resp.verified) {
        state.idToken = resp.id_token;
        setStatus('status-invoice', '✓ Payment verified!', 'success');
        setTimeout(() => showVerified(), 500);
      } else {
        setStatus('status-invoice', '✗ Verification failed: ' + JSON.stringify(resp), 'error');
      }

    } catch (e) {
      console.error(e);
      setStatus('status-invoice', '✗ Error: ' + (e.detail || e.message || JSON.stringify(e)), 'error');
    }
  }

  function simulatePayment() {
    // Generate a random "preimage" for testing
    const randomBytes = new Uint8Array(32);
    crypto.getRandomValues(randomBytes);
    const preimage = Array.from(randomBytes).map(b => b.toString(16).padStart(2, '0')).join('');
    
    $('#preimage-input').value = preimage;
    setStatus('status-invoice', `🧪 Test preimage generated.\n\nNote: This won't verify against the real payment_hash.\nFor real testing, pay the invoice and use the actual preimage.`, 'pending');
  }

  function showVerified() {
    hide('card-invoice');
    show('card-verified');
    setStep(4);

    $('#id-token').value = state.idToken;
  }

  function decodeToken() {
    try {
      const parts = state.idToken.split('.');
      if (parts.length !== 3) throw new Error('Invalid JWT');
      
      const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
      const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
      
      setStatus('status-verified', `Header:\n${JSON.stringify(header, null, 2)}\n\nPayload:\n${JSON.stringify(payload, null, 2)}`, 'success');
    } catch (e) {
      setStatus('status-verified', '✗ Error decoding: ' + e.message, 'error');
    }
  }

  // API status checks
  async function checkHealth() {
    try {
      const data = await apiGet('/healthz');
      setStatus('api-status', '✓ API is healthy\n' + JSON.stringify(data, null, 2), 'success');
    } catch (e) {
      setStatus('api-status', '✗ Error: ' + JSON.stringify(e), 'error');
    }
  }

  async function getInfo() {
    try {
      const data = await apiGet('/v1/enterprise/info');
      setStatus('api-status', JSON.stringify(data, null, 2), 'success');
    } catch (e) {
      setStatus('api-status', '✗ Error: ' + JSON.stringify(e), 'error');
    }
  }

  // Initialize
  document.addEventListener('DOMContentLoaded', () => {
    // Bind buttons
    $('#btn-create-session')?.addEventListener('click', createSession);
    $('#btn-copy-link')?.addEventListener('click', copyDeepLink);
    $('#btn-new-session')?.addEventListener('click', newSession);
    $('#btn-confirm')?.addEventListener('click', confirmPayment);
    $('#btn-simulate-pay')?.addEventListener('click', simulatePayment);
    $('#btn-strike-pay')?.addEventListener('click', payWithStrike);
    $('#btn-decode-token')?.addEventListener('click', decodeToken);
    $('#btn-start-over')?.addEventListener('click', newSession);
    $('#btn-health')?.addEventListener('click', checkHealth);
    $('#btn-info')?.addEventListener('click', getInfo);

    // Add manual invoice entry button to QR card
    const qrCard = $('#card-qr');
    if (qrCard) {
      const btn = document.createElement('button');
      btn.className = 'btn btn-secondary';
      btn.textContent = '📝 Enter Invoice Manually';
      btn.style.marginTop = '12px';
      btn.style.display = 'block';
      btn.style.width = '100%';
      btn.addEventListener('click', showInvoiceEntry);
      qrCard.appendChild(btn);
    }

    setStep(1);
    console.log('SignedByMe Enterprise Demo initialized');
  });
})();
