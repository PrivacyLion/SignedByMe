/**
 * Acme Corp SignedByMe Integration
 * 
 * Handles:
 * 1. Session creation via POST /v1/session
 * 2. QR code generation
 * 3. Session polling until completion
 */

// Configuration
const API_BASE = 'https://api.beta.privacy-lion.com';
const API_KEY = 'acme-test-key-2026';
const REDIRECT_URI = 'https://acme.beta.privacy-lion.com/callback';
const POLL_INTERVAL = 2000; // 2 seconds

// State
let currentSession = null;
let pollTimer = null;
let expireTimer = null;
let expiresAt = 0;

// DOM Elements
const loginView = document.getElementById('login-view');
const qrView = document.getElementById('qr-view');
const successView = document.getElementById('success-view');
const signedByBtn = document.getElementById('signedby-btn');
const backBtn = document.getElementById('back-btn');
// QR code container (qrcodejs creates elements inside)
const rewardAmount = document.getElementById('reward-amount');
const statusText = document.getElementById('status-text');
const spinner = document.getElementById('spinner');
const expireTimerEl = document.getElementById('expire-timer');

// Success view elements
const successDid = document.getElementById('success-did');
const payoutAmount = document.getElementById('payout-amount');
const payoutInfo = document.getElementById('payout-info');
const payoutError = document.getElementById('payout-error');
const payoutErrorMsg = document.getElementById('payout-error-msg');

// Event Listeners
signedByBtn.addEventListener('click', startSignedByLogin);
backBtn.addEventListener('click', cancelLogin);

/**
 * Start SignedByMe login flow
 */
async function startSignedByLogin() {
    try {
        signedByBtn.disabled = true;
        signedByBtn.textContent = 'Starting...';
        
        // Create session
        const response = await fetch(`${API_BASE}/v1/session`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-API-Key': API_KEY
            },
            body: JSON.stringify({
                redirect_uri: REDIRECT_URI
            })
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to create session');
        }
        
        currentSession = await response.json();
        console.log('Session created:', currentSession);
        
        // Update UI
        rewardAmount.textContent = currentSession.amount_sats;
        expiresAt = currentSession.expires_at;
        
        // Generate QR code
        const qrContainer = document.getElementById('qr-container');
        qrContainer.innerHTML = ''; // Clear previous
        new QRCode(qrContainer, {
            text: currentSession.qr_data,
            width: 250,
            height: 250,
            colorDark: '#1a56db',
            colorLight: '#ffffff'
        });
        
        // Show QR view
        loginView.classList.add('hidden');
        qrView.classList.remove('hidden');
        
        // Start polling
        startPolling();
        
        // Start expire timer
        startExpireTimer();
        
    } catch (error) {
        console.error('Error starting login:', error);
        alert('Failed to start login: ' + error.message);
    } finally {
        signedByBtn.disabled = false;
        signedByBtn.innerHTML = `
            <span class="icon">⚡</span>
            <div class="btn-text">
                Sign in with SignedByMe
                <span class="reward-badge">GET PAID TO LOG IN</span>
            </div>
        `;
    }
}

/**
 * Cancel login and go back
 */
function cancelLogin() {
    stopPolling();
    stopExpireTimer();
    currentSession = null;
    
    qrView.classList.add('hidden');
    loginView.classList.remove('hidden');
}

/**
 * Start polling for session completion
 */
function startPolling() {
    stopPolling();
    pollSession();
    pollTimer = setInterval(pollSession, POLL_INTERVAL);
}

/**
 * Stop polling
 */
function stopPolling() {
    if (pollTimer) {
        clearInterval(pollTimer);
        pollTimer = null;
    }
}

/**
 * Poll session status
 */
async function pollSession() {
    if (!currentSession) return;
    
    try {
        const response = await fetch(
            `${API_BASE}/v1/session/${currentSession.session_id}`
        );
        
        if (!response.ok) {
            console.error('Poll error:', response.status);
            return;
        }
        
        const status = await response.json();
        console.log('Session status:', status);
        
        if (status.status === 'completed') {
            stopPolling();
            stopExpireTimer();
            showSuccess(status);
        } else if (status.status === 'expired') {
            stopPolling();
            stopExpireTimer();
            statusText.textContent = 'Session expired. Please try again.';
            spinner.style.display = 'none';
        }
        
    } catch (error) {
        console.error('Poll error:', error);
    }
}

/**
 * Start expire countdown timer
 */
function startExpireTimer() {
    stopExpireTimer();
    updateExpireTimer();
    expireTimer = setInterval(updateExpireTimer, 1000);
}

/**
 * Stop expire timer
 */
function stopExpireTimer() {
    if (expireTimer) {
        clearInterval(expireTimer);
        expireTimer = null;
    }
}

/**
 * Update expire timer display
 */
function updateExpireTimer() {
    const now = Math.floor(Date.now() / 1000);
    const remaining = Math.max(0, expiresAt - now);
    
    const minutes = Math.floor(remaining / 60);
    const seconds = remaining % 60;
    
    expireTimerEl.textContent = `${minutes}:${seconds.toString().padStart(2, '0')}`;
    
    if (remaining <= 0) {
        stopExpireTimer();
    }
}

/**
 * Show success view
 */
function showSuccess(status) {
    // Format DID for display
    const did = status.did || 'Unknown';
    const shortDid = did.length > 40 
        ? did.substring(0, 20) + '...' + did.substring(did.length - 16)
        : did;
    successDid.textContent = shortDid;
    
    // Handle payout result
    if (status.payout) {
        if (status.payout.status === 'success') {
            payoutAmount.textContent = status.payout.amount_sats || currentSession.amount_sats;
            payoutInfo.classList.remove('hidden');
            payoutError.classList.add('hidden');
        } else if (status.payout.status === 'failed') {
            payoutErrorMsg.textContent = status.payout.error || 'Payment processing error';
            payoutError.classList.remove('hidden');
            payoutInfo.classList.add('hidden');
        } else {
            // Skipped or other status
            payoutInfo.classList.add('hidden');
            payoutError.classList.add('hidden');
        }
    } else {
        // No payout configured
        payoutInfo.classList.add('hidden');
        payoutError.classList.add('hidden');
    }
    
    // Show success view
    qrView.classList.add('hidden');
    successView.classList.remove('hidden');
}

// Handle page visibility (pause/resume polling)
document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
        stopPolling();
    } else if (currentSession && qrView.classList.contains('hidden') === false) {
        startPolling();
    }
});
