// background.js for PhishGuard Pro with heuristic + dataset layered check

class PhishingDatabase {
  constructor() {
    this.phishingData = new Map();
    this.loadDatabase();
  }

  async loadDatabase() {
    try {
      // Fetch phishing dataset from remote JSON (update URL accordingly)
      const response = await fetch('https://raw.githubusercontent.com/Chary149/PhishingData/92290c/data.json');
      const data = await response.json();

      this.phishingData = new Map();
      data.forEach(entry => this.phishingData.set(entry.url, entry));

      console.log('Phishing database loaded:', this.phishingData.size, 'entries');
    } catch (error) {
      console.error('Failed to load phishing database:', error);
      // Optional fallback sample data
      const sampleData = [
        {
          phish_id: 1,
          url: "malicious-bank-site.com",
          phish_detail_url: "http://openphish.com/phish_detail.html?id=1",
          submission_time: "2024-01-01T10:00:00Z",
          verified: "yes",
          verification_time: "2024-01-01T11:00:00Z",
          online: "yes",
          target: "Banking"
        }
      ];
      this.phishingData = new Map();
      sampleData.forEach(entry => this.phishingData.set(entry.url, entry));
      console.log('Sample phishing database loaded');
    }
  }

  async heuristicCheck(hostname) {
    const suspiciousPatterns = [
      /\b(\d{1,3}\.){3}\d{1,3}\b/,               // IP addresses
      /[a-z]+-[a-z]+-[a-z]+\.(tk|ml|ga|cf)/,    // Suspicious TLDs
      /-secure-|security-|verify-|update-/,      // Keywords common in phishing
      /[a-z]{20,}/,                              // Very long subdomains
    ];

    for (const pattern of suspiciousPatterns) {
      if (pattern.test(hostname)) {
        return {
          phish_id: 'heuristic',
          url: hostname,
          target: 'Unknown',
          verified: 'heuristic',
          online: 'yes',
          risk_level: 'medium'
        };
      }
    }
    return null;
  }

  async checkUrl(url) {
    try {
      const hostname = new URL(url).hostname;

      // 1) Heuristic check — quickly detect suspicious patterns
      const heuristicThreat = await this.heuristicCheck(hostname);
      if (heuristicThreat) return heuristicThreat;

      // 2) Dataset check — exact or subdomain match
      if (this.phishingData.has(hostname)) {
        return this.phishingData.get(hostname);
      }
      for (let [knownUrl, data] of this.phishingData) {
        if (hostname === knownUrl || hostname.endsWith('.' + knownUrl)) {
          return data;
        }
      }

      return null;
    } catch (error) {
      console.error('URL check error:', error);
      return null;
    }
  }
}

const phishingDB = new PhishingDatabase();

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId === 0) {
    const threat = await phishingDB.checkUrl(details.url);
    if (threat) {
      await chrome.storage.session.set({
        [`threat_${details.tabId}`]: {
          ...threat,
          currentUrl: details.url,
          timestamp: Date.now(),
        },
      });
    }
  }
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  switch (request.type) {
    case 'CHECK_URL':
      phishingDB.checkUrl(request.url)
        .then(result => sendResponse({ threat: result }))
        .catch(error => sendResponse({ error: error.message }));
      return true; // async response

    case 'REPORT_BLOCKED':
      console.log('Keylogger blocked on:', sender.tab?.url);
      break;

    case 'USER_EDUCATED':
      chrome.storage.local.get(['educationStats'], result => {
        let stats = result.educationStats || { totalEducated: 0, byTarget: {} };
        stats.totalEducated++;
        stats.byTarget[request.target] = (stats.byTarget[request.target] || 0) + 1;
        chrome.storage.local.set({ educationStats: stats });
      });
      break;

    case 'GET_SESSION_THREAT':
      chrome.storage.session.get(`threat_${request.tabId}`).then(result => {
        sendResponse({ threat: result[`threat_${request.tabId}`] || null });
      });
      return true;

    case 'GET_TAB_ID':
      sendResponse({ tabId: sender.tab ? sender.tab.id : null });
      return true;

    default:
      break;
  }
});

chrome.tabs.onActivated.addListener(async (activeInfo) => {
  const threat = await chrome.storage.session.get(`threat_${activeInfo.tabId}`);
  if (threat[`threat_${activeInfo.tabId}`]) {
    chrome.action.setBadgeText({ text: '!', tabId: activeInfo.tabId });
    chrome.action.setBadgeBackgroundColor({ color: '#ff4444' });
  } else {
    chrome.action.setBadgeText({ text: '', tabId: activeInfo.tabId });
  }
});
