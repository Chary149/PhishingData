class PhishGuardProtection {
  constructor() {
    this.keyloggerBlocked = false;
    this.threatInfo = null;
    this.init();
  }

  async init() {
    await this.checkCurrentSite();
    this.setupKeyloggerProtection();
    this.setupFormProtection();
    this.monitorDOMChanges();
  }

  async checkCurrentSite() {
    try {
      // Get current tab id
      const tabId = await this.getTabId();

      // Query background if current URL is phishing
      const response = await new Promise(resolve => {
        chrome.runtime.sendMessage({ type: 'CHECK_URL', url: window.location.href }, resolve);
      });

      if (response && response.threat) {
        this.threatInfo = response.threat;
        await this.showThreatWarning();
      }

      // Get session threat from background
      const sessionThreatResp = await new Promise(resolve => {
        chrome.runtime.sendMessage({ type: 'GET_SESSION_THREAT', tabId }, resolve);
      });
      if (sessionThreatResp && sessionThreatResp.threat) {
        this.threatInfo = sessionThreatResp.threat;
        await this.showThreatWarning();
      }
    } catch (error) {
      console.error('Site check failed:', error);
    }
  }

  getTabId() {
    return new Promise(resolve => {
      chrome.runtime.sendMessage({ type: 'GET_TAB_ID' }, response => {
        resolve(response?.tabId || 0);
      });
    });
  }

setupKeyloggerProtection() {
  const protectedEvents = ['keydown', 'keypress', 'keyup', 'input', 'paste'];
  protectedEvents.forEach(eventType => {
    document.addEventListener(eventType, (event) => {
      if (this.threatInfo && this.detectSuspiciousKeylogging(event)) {
        event.stopImmediatePropagation();
        event.preventDefault();
        this.showKeyloggerBlocked();
        chrome.runtime.sendMessage({
          type: 'REPORT_BLOCKED',
          eventType,
          target: event.target.tagName
        });
      }
    }, true);
  });
}


  detectSuspiciousKeylogging(event, lastEventTime) {
    return (
      event.timeStamp - lastEventTime < 10 ||
      (event.target && event.target.tagName === 'INPUT' && event.target.type === 'password' && !event.isTrusted)
    );
  }

  setupFormProtection() {
    document.querySelectorAll('form').forEach(form => {
      form.addEventListener('submit', event => {
        if (this.threatInfo) {
          event.preventDefault();
          this.showFormProtectionWarning();
        }
      });
    });
  }

 async showThreatWarning() {
  // Wait until document.body is ready
  if (!document.body) {
    await new Promise(resolve => {
      if (document.readyState === "complete" || document.readyState === "interactive") {
        resolve();
      } else {
        window.addEventListener('DOMContentLoaded', resolve, { once: true });
      }
    });
  }

  const overlay = this.createOverlay();
  document.body.appendChild(overlay);
  requestAnimationFrame(() => {
    overlay.classList.add('phishguard-show');
  });
}


  createOverlay() {
    const div = document.createElement('div');
    div.className = 'phishguard-threat-overlay';
    div.innerHTML = `
      <div class="phishguard-warning-content">
        <h1>Phishing Attack Warning!</h1>
        <p>This site may steal your credentials and harm your privacy.</p>
        <button id="phishguard-close">Close</button>
      </div>
    `;
    div.querySelector('#phishguard-close').addEventListener('click', () => {
      div.remove();
    });
    return div;
  }

  showKeyloggerBlocked() {
    if (this.keyloggerBlocked) return;
    this.keyloggerBlocked = true;
    const notification = document.createElement('div');
    notification.className = 'phishguard-keylogger-blocked';
    notification.textContent = 'Keylogger Blocked!';
    document.body.appendChild(notification);
    setTimeout(() => {
      notification.remove();
      this.keyloggerBlocked = false;
    }, 3000);
  }

  showFormProtectionWarning() {
    const warning = document.createElement('div');
    warning.className = 'phishguard-form-warning';
    warning.textContent = 'Form submission blocked due to security risk!';
    document.body.appendChild(warning);
    setTimeout(() => warning.remove(), 5000);
  }

  monitorDOMChanges() {
    // Optional: monitor DOM to detect dynamic injections, etc.
  }
}

new PhishGuardProtection();
