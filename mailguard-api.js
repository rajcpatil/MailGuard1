/**
 * MailGuard1 Backend Integration Script
 *
 * Connects existing frontend controls to the FastAPI backend, SQLite database,
 * Google OAuth 2.0 authentication, and Gmail read-only security analysis.
 */

(function () {
  'use strict';

  // Determine API base URL (relative when served by FastAPI on port 8000, absolute when opened via file:// or other dev servers)
  const API_BASE = (window.location.protocol.startsWith('http') && (window.location.port === '8000' || window.location.port === ''))
    ? '/api'
    : 'http://127.0.0.1:8000/api';

  let backendAvailable = false;
  let currentUser = null;
  let gmailStatus = { connected: false, email: null };

  // Verify backend connectivity and initialize authentication state
  async function checkBackend() {
    try {
      const res = await fetch(`${API_BASE}/health`, { method: 'GET' });
      if (res.ok) {
        backendAvailable = true;
        console.log('[MailGuard] Connected to backend API');
        await syncAuthStatus();
        await syncInitialData();
        checkUrlNotifications();

        // If Gmail is connected, automatically sync recent emails in the background so MailGuard always has the latest info
        if (gmailStatus && gmailStatus.connected) {
          triggerAutoGmailSync();
        }
      }
    } catch (err) {
      console.warn('[MailGuard] Backend not reachable at ' + API_BASE + '. Running in offline simulation mode.', err);
    }
  }

  // Automatic background Gmail sync on load (throttled to avoid exhausting Gmail API quotas)
  async function triggerAutoGmailSync() {
    try {
      const lastSync = parseInt(sessionStorage.getItem('mailguard_last_auto_sync') || '0', 10);
      const now = Date.now();
      // Only auto-sync if at least 60 seconds have elapsed since last check
      if (now - lastSync < 60000) {
        return;
      }
      sessionStorage.setItem('mailguard_last_auto_sync', String(now));

      const res = await fetch(`${API_BASE}/gmail/scan?max_results=20`, {
        method: 'POST',
        credentials: 'include',
      });
      if (res.ok) {
        const summary = await res.json();
        if (summary.newly_scanned > 0) {
          console.log(`[MailGuard] Auto-synced ${summary.newly_scanned} new Gmail messages`);
          await syncInitialData();
          if (typeof renderDash === 'function') await renderDash();
          if (typeof toast2 === 'function') {
            toast2(`Gmail auto-sync: ${summary.newly_scanned} new email(s) analyzed.`);
          }
        }
      }
    } catch (err) {
      console.debug('[MailGuard] Background Gmail sync check:', err);
    }
  }

  // Centralized Gmail Scanning Function
  async function scanGmailNow(btnElement) {
    if (!backendAvailable || !gmailStatus.connected) return;
    const origText = btnElement ? btnElement.textContent : 'Scan Gmail';
    if (btnElement) {
      btnElement.textContent = 'Scanning Gmail...';
      btnElement.disabled = true;
    }

    try {
      // Mark timestamp to prevent immediate auto-sync collision
      sessionStorage.setItem('mailguard_last_auto_sync', String(Date.now()));

      const res = await fetch(`${API_BASE}/gmail/scan?max_results=25`, {
        method: 'POST',
        credentials: 'include',
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        let errMsg = errData.detail || 'Failed to scan Gmail';
        if (errMsg.toLowerCase().includes('quota') || errMsg.toLowerCase().includes('rate limit')) {
          errMsg = 'Google API rate limit reached. Please wait a minute before scanning again.';
        }
        throw new Error(errMsg);
      }

      const scanSummary = await res.json();
      console.log('[MailGuard] Gmail scan complete:', scanSummary);

      if (typeof toast2 === 'function') {
        if (scanSummary.newly_scanned > 0) {
          toast2(`Gmail scan complete: ${scanSummary.newly_scanned} new email(s) analyzed. ${scanSummary.threats_blocked} quarantined.`);
        } else {
          toast2(`Gmail scan complete: Mailbox is up to date (${scanSummary.total_fetched} emails verified).`);
        }
      }

      // Refresh both Inbox/Quarantine and Dashboard with the latest data
      await syncInitialData();
      if (typeof renderDash === 'function') await renderDash();
    } catch (err) {
      console.error('[MailGuard] Gmail scan error:', err);
      if (typeof toast === 'function') {
        toast(`Gmail Scan: ${err.message}`);
      }
    } finally {
      if (btnElement) {
        btnElement.textContent = origText;
        btnElement.disabled = false;
      }
    }
  }

  // Check URL query parameters for OAuth redirect notifications
  function checkUrlNotifications() {
    const params = new URLSearchParams(window.location.search);
    if (params.get('login_success')) {
      if (typeof toast2 === 'function') toast2('Welcome back! Signed in with Google.');
    } else if (params.get('gmail_connected')) {
      if (typeof toast2 === 'function') toast2('Gmail connected! Scanning your inbox for threats...');
      scanGmailNow(document.getElementById('btnGmail'));
    } else if (params.get('gmail_error')) {
      if (typeof toast === 'function') toast('Gmail authorization was cancelled or failed.');
    }
    // Clean URL without reloading
    if (window.history && window.history.replaceState && (params.get('login_success') || params.get('gmail_connected') || params.get('gmail_error'))) {
      const cleanUrl = window.location.pathname;
      window.history.replaceState({}, document.title, cleanUrl);
    }
  }

  // Synchronize authentication status and update header controls
  async function syncAuthStatus() {
    if (!backendAvailable) return;
    try {
      const res = await fetch(`${API_BASE}/auth/me`, { method: 'GET', credentials: 'include' });
      if (res.ok) {
        const data = await res.json();
        if (data.authenticated && data.user) {
          currentUser = data.user;
          gmailStatus = data.gmail || { connected: false };
          renderAuthControls(true);
        } else {
          currentUser = null;
          gmailStatus = { connected: false };
          renderAuthControls(false);
        }
      }
    } catch (err) {
      console.warn('[MailGuard] Could not check auth status:', err);
      renderAuthControls(false);
    }
  }

  // Render header authentication and Gmail buttons
  function renderAuthControls(isLoggedIn) {
    const userBadge = document.getElementById('userBadge');
    const btnGmail = document.getElementById('btnGmail');
    const linkLogin = document.getElementById('linkLogin');
    const btnLogout = document.getElementById('btnLogout');

    if (isLoggedIn && currentUser) {
      if (linkLogin) linkLogin.style.display = 'none';

      if (userBadge) {
        userBadge.style.display = 'inline-block';
        userBadge.textContent = currentUser.email.split('@')[0];
        userBadge.title = `Signed in as ${currentUser.email}`;
      }

      if (btnGmail) {
        btnGmail.style.display = 'inline-flex';
        if (gmailStatus.connected) {
          btnGmail.textContent = 'Scan Gmail';
          btnGmail.title = `Connected to ${gmailStatus.email || 'Gmail'}. Click to scan recent messages.`;
          btnGmail.classList.remove('ghost');
        } else {
          btnGmail.textContent = 'Connect Gmail';
          btnGmail.title = 'Authorize read-only access to scan your Gmail messages for threats.';
          btnGmail.classList.add('ghost');
        }
      }

      if (btnLogout) {
        btnLogout.style.display = 'inline-flex';
      }

      const recvBtn = document.getElementById('recv');
      if (recvBtn && gmailStatus.connected) {
        recvBtn.textContent = 'Sync Gmail';
        recvBtn.title = 'Fetch and scan latest emails from your connected Gmail';
      }
    } else {
      if (linkLogin) linkLogin.style.display = 'inline-flex';
      if (userBadge) userBadge.style.display = 'none';
      if (btnGmail) btnGmail.style.display = 'none';
      if (btnLogout) btnLogout.style.display = 'none';
      const recvBtn = document.getElementById('recv');
      if (recvBtn) {
        recvBtn.textContent = 'Receive email';
        recvBtn.title = 'Receive sample email';
      }
    }
  }

  // Set up Header Auth and Gmail Click Listeners
  function setupAuthListeners() {
    const btnGmail = document.getElementById('btnGmail');
    if (btnGmail) {
      btnGmail.addEventListener('click', async function (e) {
        e.preventDefault();
        if (!backendAvailable) return;

        if (!gmailStatus.connected) {
          // Initiate Gmail OAuth 2.0 Authorization Flow
          window.location.href = `${API_BASE}/gmail/connect`;
        } else {
          await scanGmailNow(btnGmail);
        }
      });
    }

    const btnLogout = document.getElementById('btnLogout');
    if (btnLogout) {
      btnLogout.addEventListener('click', async function (e) {
        e.preventDefault();
        try {
          await fetch(`${API_BASE}/auth/logout`, { method: 'POST', credentials: 'include' });
          currentUser = null;
          gmailStatus = { connected: false };
          renderAuthControls(false);
          if (typeof toast === 'function') toast('Signed out successfully.');
          await syncInitialData();
        } catch (err) {
          console.error('[MailGuard] Logout error:', err);
        }
      });
    }
  }

  // Synchronize state with SQLite database records
  async function syncInitialData() {
    if (!backendAvailable) return;
    try {
      const res = await fetch(`${API_BASE}/history?box=all&limit=100`, { credentials: 'include' });
      if (res.ok) {
        const data = await res.json();
        if (data.emails && data.emails.length > 0) {
          state.emails = data.emails;
          const currentVisible = state.emails.filter(e => state.box === 'quar' ? e.action === 'blocked' : e.action !== 'blocked');
          const first = currentVisible[0] || state.emails[0];
          state.sel = first ? first.id : null;
          if (typeof renderList === 'function') renderList();
          if (typeof renderDetail === 'function') renderDetail();
        } else {
          state.emails = [];
          state.sel = null;
          if (typeof renderList === 'function') renderList();
          if (typeof renderDetail === 'function') renderDetail();
        }
      }
    } catch (err) {
      console.error('[MailGuard] Failed to fetch initial history:', err);
    }
  }

  // Intercept the Scan Form Submit
  const originalForm = document.getElementById('form');
  if (originalForm) {
    originalForm.addEventListener('submit', async function (ev) {
      if (!backendAvailable) return;

      ev.preventDefault();
      ev.stopImmediatePropagation();

      const btn = originalForm.querySelector('button[type="submit"]');
      const origText = btn ? btn.textContent : '';
      if (btn) {
        btn.textContent = 'Checking...';
        btn.disabled = true;
      }

      const payload = {
        from: document.getElementById('fFrom')?.value.trim() || '',
        replyTo: document.getElementById('fReply')?.value.trim() || null,
        subject: document.getElementById('fSub')?.value || '',
        body: document.getElementById('fBody')?.value || '',
        attach: document.getElementById('fAtt')?.value.trim() || null,
        threshold: state.threshold || 0.5,
      };

      try {
        const res = await fetch(`${API_BASE}/scan`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify(payload),
        });

        if (!res.ok) {
          const errData = await res.json().catch(() => ({}));
          throw new Error(errData.detail || 'Server rejected scan request');
        }

        const scanResult = await res.json();

        // Update Scan Output Pane using the existing detailHTML function
        const scanOut = document.getElementById('scanOut');
        if (scanOut && typeof detailHTML === 'function') {
          scanOut.innerHTML = detailHTML(scanResult).replace(/<div style="margin-top:14px">.*?<\/div>/s, '');
        }

        // Add to local state and update counters
        state.emails.unshift(scanResult);
        state.scanned = (state.scanned || 0) + 1;
        if (scanResult.ms) state.times.push(+scanResult.ms);

        if (scanResult.action === 'blocked') {
          const d = state.days[6];
          if (d) d[scanResult.type === 'fraud' ? 1 : 0]++;
          const k = scanResult.from.split('@')[1];
          if (k) state.offenders[k] = (state.offenders[k] || 0) + 1;
          if (typeof toast === 'function') {
            toast(`${scanResult.type === 'fraud' ? 'Fraud attempt' : 'Spam'} blocked from ${k}`);
          }
        }

        if (typeof renderList === 'function') renderList();
      } catch (err) {
        console.error('[MailGuard] Backend scan error:', err);
        if (typeof toast === 'function') {
          toast(`Scan failed: ${err.message || 'Check backend connection'}`);
        }
      } finally {
        if (btn) {
          btn.textContent = origText;
          btn.disabled = false;
        }
      }
    }, true);
  }

  // Intercept the Receive Email Button
  const recvBtn = document.getElementById('recv');
  if (recvBtn) {
    recvBtn.addEventListener('click', async function (ev) {
      if (!backendAvailable) return;

      ev.preventDefault();
      ev.stopImmediatePropagation();

      if (gmailStatus.connected) {
        await scanGmailNow(recvBtn);
        return;
      }

      try {
        const res = await fetch(`${API_BASE}/scan/receive`, { method: 'POST', credentials: 'include' });
        if (!res.ok) throw new Error('Failed to receive incoming sample from server');
        const email = await res.json();

        state.emails.unshift(email);
        state.scanned = (state.scanned || 0) + 1;
        if (email.ms) state.times.push(+email.ms);

        state.sel = email.id;
        state.box = email.action === 'blocked' ? 'quar' : 'inbox';

        document.querySelectorAll('#box button').forEach(x => {
          x.classList.toggle('on', x.dataset.b === state.box);
        });

        if (typeof renderList === 'function') renderList();
        if (typeof renderDetail === 'function') renderDetail();

        if (email.action === 'blocked') {
          const d = state.days[6];
          if (d) d[email.type === 'fraud' ? 1 : 0]++;
          const k = email.from.split('@')[1];
          if (k) state.offenders[k] = (state.offenders[k] || 0) + 1;
          if (typeof toast === 'function') {
            toast(`${email.type === 'fraud' ? 'Fraud attempt' : 'Spam'} blocked from ${k}`);
          }
        }
      } catch (err) {
        console.error('[MailGuard] Receive error:', err);
      }
    }, true);
  }

  // Intercept the Restore to Inbox Button
  const detailPanel = document.getElementById('detail');
  if (detailPanel) {
    detailPanel.addEventListener('click', async function (ev) {
      const btn = ev.target.closest('[data-restore]');
      if (!btn || !backendAvailable) return;

      const scanId = btn.dataset.restore;
      if (!scanId) return;

      ev.preventDefault();
      ev.stopImmediatePropagation();

      try {
        const res = await fetch(`${API_BASE}/scan/${scanId}/restore`, { method: 'POST', credentials: 'include' });
        if (!res.ok) throw new Error('Failed to restore quarantined email');
        const updated = await res.json();

        const local = state.emails.find(x => x.id == scanId);
        if (local) {
          local.action = 'delivered';
        }

        state.box = 'inbox';
        document.querySelectorAll('#box button').forEach(x => {
          x.classList.toggle('on', x.dataset.b === 'inbox');
        });

        if (typeof renderList === 'function') renderList();
        if (typeof renderDetail === 'function') renderDetail();
        if (typeof toast2 === 'function') {
          toast2('Restored to Inbox. Sender kept on watch.');
        }
      } catch (err) {
        console.error('[MailGuard] Restore error:', err);
      }
    }, true);
  }

  // Hook Dashboard rendering to load live database metrics
  const originalRenderDash = window.renderDash;
  window.renderDash = async function () {
    if (backendAvailable) {
      try {
        const res = await fetch(`${API_BASE}/dashboard/stats`, { credentials: 'include' });
        if (res.ok) {
          const data = await res.json();
          // Store all real metrics on state so renderDash() uses live numbers
          state.scanned = data.scanned;
          state.days = data.days;
          state.offenders = data.offenders;
          state.threshold = data.threshold;
          // Store pre-computed KPI values from server (avoids re-deriving from baseline)
          state._threatsBlocked = data.threats_blocked_7d;
          state._fraudPct = data.fraud_pct;
          state._threatMix = data.threat_mix; // {spam: N, fraud: N}
        }
      } catch (err) {
        console.warn('[MailGuard] Could not refresh dashboard stats from backend:', err);
      }
    }

    if (typeof originalRenderDash === 'function') {
      originalRenderDash();
    }

    const thrInput = document.getElementById('thr');
    if (thrInput && backendAvailable) {
      // Remove any previous listener by replacing the element clone
      const fresh = thrInput.cloneNode(true);
      thrInput.parentNode.replaceChild(fresh, thrInput);
      fresh.addEventListener('change', async function (e) {
        const newThreshold = parseFloat(e.target.value) / 100;
        state.threshold = newThreshold;
        try {
          await fetch(`${API_BASE}/dashboard/threshold`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ threshold: newThreshold }),
          });
        } catch (err) {
          console.warn('[MailGuard] Could not persist threshold setting:', err);
        }
      });
    }
  };

  // Run initial backend probe and bind listeners
  function init() {
    setupAuthListeners();
    checkBackend();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
