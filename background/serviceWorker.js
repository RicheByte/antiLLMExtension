const BADGE_SETTINGS = {
  none: { text: "", color: "#4a4a4a" },
  low: { text: "OK", color: "#2e7d32" },
  medium: { text: "!", color: "#f9a825" },
  high: { text: "!!", color: "#c62828" }
};

const CACHE_TTL = 60 * 60 * 1000;
const tabAssessments = new Map();

chrome.runtime.onInstalled.addListener(async () => {
  await chrome.action.setBadgeText({ text: "" });
  await chrome.action.setBadgeBackgroundColor({ color: BADGE_SETTINGS.none.color });
  
  // Schedule daily signature updates
  chrome.alarms.create('updateSignatures', { 
    periodInMinutes: 1440 // 24 hours
  });
  
  // Trigger initial signature check
  updateThreatSignatures();
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !message.type) {
    return;
  }

  switch (message.type) {
    case "DETECTION_RESULT":
      handleDetectionResult(message.payload, sender.tab?.id);
      break;
    case "GET_TAB_ASSESSMENT":
      getAssessmentForTab(message.tabId).then(sendResponse);
      return true;
    case "REQUEST_DOMAIN_REPUTATION":
      resolveDomainReputation(message.domain).then(sendResponse);
      return true;
    case "UPSERT_API_KEY":
      chrome.storage.local.set({ [message.key]: message.value });
      sendResponse({ success: true });
      break;
    case "SUBMIT_FEEDBACK":
      handleFeedback(message.feedback).then(sendResponse);
      return true;
    case "GET_SIGNATURES":
      getSignatures().then(sendResponse);
      return true;
    default:
      break;
  }
});

// Handle alarm for signature updates
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'updateSignatures') {
    updateThreatSignatures();
  }
});

chrome.tabs.onRemoved.addListener(async (tabId) => {
  tabAssessments.delete(tabId);
  await chrome.storage.local.remove(`assessment:${tabId}`);
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  const assessment = await getAssessmentForTab(tabId);
  applyBadgeState(tabId, assessment?.riskLevel ?? "none");
});

async function handleDetectionResult(payload, tabId) {
  if (!tabId || !payload) {
    return;
  }

  const enriched = { ...payload, tabId, lastUpdated: Date.now() };
  tabAssessments.set(tabId, enriched);
  await chrome.storage.local.set({ [`assessment:${tabId}`]: enriched });
  applyBadgeState(tabId, payload.riskLevel);
}

async function getAssessmentForTab(tabId) {
  if (!tabId) {
    return null;
  }

  if (tabAssessments.has(tabId)) {
    return tabAssessments.get(tabId);
  }

  const stored = await chrome.storage.local.get(`assessment:${tabId}`);
  if (stored[`assessment:${tabId}`]) {
    tabAssessments.set(tabId, stored[`assessment:${tabId}`]);
    return stored[`assessment:${tabId}`];
  }

  return null;
}

async function resolveDomainReputation(domain) {
  if (!domain) {
    return { error: "No domain provided." };
  }

  const cacheKey = `domain:${domain}`;
  const cachedWrapper = await chrome.storage.local.get(cacheKey);
  const cached = cachedWrapper[cacheKey];
  if (cached && Date.now() - cached.cachedAt < CACHE_TTL) {
    return cached.data;
  }

  const localSignals = await buildLocalSignals(domain);
  const remoteSignals = await fetchRemoteSignals(domain);
  const data = {
    domain,
    localSignals,
    remoteSignals,
    computedRisk: scoreDomainRisk(localSignals, remoteSignals)
  };

  await chrome.storage.local.set({
    [cacheKey]: { cachedAt: Date.now(), data }
  });

  return data;
}

async function buildLocalSignals(domain) {
  return {
    typosquatLikelihood: computeTyposquat(domain),
    entropy: domainEntropy(domain),
    isPunycode: domain.startsWith("xn--"),
    parts: domain.split(".")
  };
}

async function fetchRemoteSignals(domain) {
  const { vtApiKey, gsbApiKey } = await chrome.storage.local.get([
    "vtApiKey",
    "gsbApiKey"
  ]);

  const [vtResult, gsbResult] = await Promise.all([
    vtApiKey ? queryVirusTotal(domain, vtApiKey) : null,
    gsbApiKey ? querySafeBrowsing(domain, gsbApiKey) : null
  ]);

  return {
    vtResult,
    gsbResult
  };
}

function scoreDomainRisk(localSignals, remoteSignals) {
  let score = 0;
  if (localSignals.typosquatLikelihood > 0.6) {
    score += 35;
  }
  if (localSignals.entropy > 4) {
    score += 15;
  }
  if (localSignals.isPunycode) {
    score += 25;
  }
  if (remoteSignals.vtResult?.malicious > 0) {
    score += 30;
  }
  if (remoteSignals.gsbResult?.matches?.length) {
    score += 30;
  }
  return Math.min(score, 100);
}

async function queryVirusTotal(domain, apiKey) {
  try {
    const response = await fetch(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`, {
      headers: {
        "x-apikey": apiKey
      }
    });
    if (!response.ok) {
      return { error: `VT ${response.status}` };
    }
    const json = await response.json();
    const stats = json?.data?.attributes?.last_analysis_stats ?? {};
    return {
      harmless: stats.harmless ?? 0,
      malicious: stats.malicious ?? 0,
      suspicious: stats.suspicious ?? 0
    };
  } catch (error) {
    return { error: error.message };
  }
}

async function querySafeBrowsing(domain, apiKey) {
  try {
    const body = {
      client: { clientId: "antillm", clientVersion: "0.2.1" },
      threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url: `http://${domain}` }, { url: `https://${domain}` }]
      }
    };
    const response = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      }
    );
    if (!response.ok) {
      return { error: `GSB ${response.status}` };
    }
    const json = await response.json();
    return json;
  } catch (error) {
    return { error: error.message };
  }
}

function computeTyposquat(domain) {
  const referenceDomains = ["google", "facebook", "microsoft", "apple", "amazon", "bankofamerica", "wellsfargo", "paypal"];
  const name = domain.split(".")[0];
  let best = 1;
  for (const ref of referenceDomains) {
    const distance = levenshtein(name, ref);
    const normalized = distance / Math.max(name.length, ref.length, 1);
    best = Math.min(best, normalized);
  }
  return 1 - best;
}

function domainEntropy(domain) {
  const counts = {};
  for (const char of domain) {
    counts[char] = (counts[char] ?? 0) + 1;
  }
  const len = domain.length || 1;
  let entropy = 0;
  for (const count of Object.values(counts)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(2));
}

function applyBadgeState(tabId, level) {
  const settings = BADGE_SETTINGS[level] ?? BADGE_SETTINGS.none;
  chrome.action.setBadgeText({ tabId, text: settings.text });
  chrome.action.setBadgeBackgroundColor({ tabId, color: settings.color });
}

function levenshtein(a, b) {
  const matrix = Array.from({ length: a.length + 1 }, () => new Array(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i += 1) {
    matrix[i][0] = i;
  }
  for (let j = 0; j <= b.length; j += 1) {
    matrix[0][j] = j;
  }
  for (let i = 1; i <= a.length; i += 1) {
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,
        matrix[i][j - 1] + 1,
        matrix[i - 1][j - 1] + cost
      );
    }
  }
  return matrix[a.length][b.length];
}

// Challenge 4: Auto-updateable threat signatures
async function updateThreatSignatures() {
  try {
    console.log("[AntiLLM] Checking for signature updates...");
    const signatureUrl = "https://raw.githubusercontent.com/yourusername/antillm/main/signatures/threat-signatures.json";
    
    const response = await fetch(signatureUrl, {
      cache: 'no-cache',
      headers: { 'Accept': 'application/json' }
    });

    if (!response.ok) {
      console.warn("[AntiLLM] Signature update failed:", response.status);
      return;
    }

    const signatures = await response.json();
    
    // Validate and store
    if (signatures.version && signatures.signatures) {
      await chrome.storage.local.set({
        threatSignatures: signatures,
        signaturesLastUpdated: Date.now()
      });
      console.log("[AntiLLM] Signatures updated to version:", signatures.version);
    }
  } catch (error) {
    console.error("[AntiLLM] Signature update error:", error);
  }
}

async function getSignatures() {
  const { threatSignatures } = await chrome.storage.local.get('threatSignatures');
  return threatSignatures || getDefaultSignatures();
}

function getDefaultSignatures() {
  // Embedded fallback
  return {
    version: "1.0.0-embedded",
    signatures: {
      jailbreak: [],
      llm: {},
      phishing: {}
    },
    thresholds: {
      compositeRisk: { high: 80, medium: 50, low: 30 }
    }
  };
}

// Challenge 1: Community feedback for continuous improvement
async function handleFeedback(feedback) {
  try {
    const { feedbackQueue = [] } = await chrome.storage.local.get('feedbackQueue');
    
    feedbackQueue.push({
      ...feedback,
      timestamp: Date.now(),
      version: chrome.runtime.getManifest().version
    });
    
    // Keep last 100 feedback items
    const trimmed = feedbackQueue.slice(-100);
    await chrome.storage.local.set({ feedbackQueue: trimmed });
    
    console.log("[AntiLLM] Feedback recorded:", feedback.type);
    return { success: true, queued: trimmed.length };
  } catch (error) {
    console.error("[AntiLLM] Feedback error:", error);
    return { success: false, error: error.message };
  }
}

