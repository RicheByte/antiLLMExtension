document.addEventListener("DOMContentLoaded", init);

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const assessment = tab ? await chrome.runtime.sendMessage({ type: "GET_TAB_ASSESSMENT", tabId: tab.id }) : null;
  renderAssessment(assessment);
  await hydrateApiForm();
  hookApiForm();
  hookFeedbackButtons(tab, assessment);
  await loadBlockedItems(tab);
  await loadReadLLMQueue();
  await loadSettings();
  hookBlockerControls();
  hookSettingsControls();
}

function renderAssessment(assessment) {
  const pill = document.getElementById("risk-pill");
  const grid = document.getElementById("signal-grid");
  const summary = document.getElementById("domain-summary");
  const recommendations = document.getElementById("recommendations");
  
  grid.innerHTML = "";
  recommendations.innerHTML = "";

  if (!assessment) {
    pill.textContent = "Idle";
    pill.className = "pill pill-low";
    summary.innerHTML = "<em>No analysis yet. Navigate to a page to view threat intelligence.</em>";
    return;
  }

  applyPillState(pill, assessment.riskLevel);
  
  const ai = assessment.aiResult || {};
  const llm = assessment.llmResult || {};
  const domain = assessment.domainResult || {};
  const breakdown = assessment.breakdown || {};

  // Enhanced metrics with detailed breakdowns
  const metrics = [
    {
      label: "Composite Risk Score",
      value: `${assessment.compositeScore || 0}/100`,
      helper: `Overall threat level (${assessment.riskLevel})`,
      important: true
    },
    {
      label: "AI Detection",
      value: formatPercent((ai.probability || 0) * 100),
      helper: ai.confidence ? `Confidence: ${formatPercent(ai.confidence * 100)}` : "Pattern-based analysis",
      breakdown: breakdown.aiAnalysis
    },
    {
      label: "LLM Fingerprint",
      value: formatPercent((llm.score || 0) * 100),
      helper: llm.likelyModel 
        ? `Model: ${llm.likelyModel.type} (${formatPercent(llm.likelyModel.confidence * 100)})`
        : `${llm.totalHits || 0} AI patterns detected`,
      breakdown: breakdown.llmFingerprint
    },
    {
      label: "Urgency Tactics",
      value: formatPercent((ai.urgencyScore || 0) * 100),
      helper: ai.urgencyIndicators?.length 
        ? `${ai.urgencyIndicators.length} urgency signals`
        : "No pressure tactics detected",
      breakdown: breakdown.urgency
    },
    {
      label: "Persuasion Score",
      value: formatPercent((ai.persuasionScore || 0) * 100),
      helper: ai.persuasionFlags?.length 
        ? `${ai.persuasionFlags.length} manipulation keywords`
        : "Low persuasion detected",
      breakdown: breakdown.persuasion
    },
    {
      label: "Domain Risk",
      value: `${domain.riskScore || 0}/100`,
      helper: domain.advancedAnalysis?.typosquatting?.isTyposquat
        ? `⚠️ May spoof "${domain.advancedAnalysis.typosquatting.likelyTarget}"`
        : domain.domain || "Current domain",
      breakdown: breakdown.domainReputation
    },
    {
      label: "Prompt Injection",
      value: assessment.jailbreakHits || 0,
      helper: assessment.jailbreakDetails?.critical 
        ? `${assessment.jailbreakDetails.critical} critical attempts`
        : "Script payload monitoring",
      breakdown: breakdown.jailbreakAttempts
    },
    {
      label: "Credibility",
      value: formatPercent((ai.credibilityScore || 1) * 100),
      helper: ai.credibilityFactors?.length 
        ? `${ai.credibilityFactors.length} factors analyzed`
        : "Authenticity assessment",
      breakdown: breakdown.credibilityPenalty
    }
  ];

  metrics.forEach((metric) => grid.appendChild(metricTile(metric)));

  // Enhanced domain summary
  renderDomainSummary(summary, domain, assessment);

  // Enhanced recommendations
  renderRecommendations(recommendations, domain, ai, llm, assessment);
}

function renderDomainSummary(container, domain, assessment) {
  container.innerHTML = "";

  // Create summary sections
  const summaryHTML = [];

  // Domain info
  if (domain.domain) {
    summaryHTML.push(`<div class="summary-section"><strong>Domain:</strong> ${domain.domain}</div>`);
  }

  // Risk score
  if (domain.riskScore !== undefined) {
    const riskClass = domain.riskScore >= 70 ? 'risk-high' : domain.riskScore >= 40 ? 'risk-medium' : 'risk-low';
    summaryHTML.push(`<div class="summary-section"><strong>Domain Risk:</strong> <span class="${riskClass}">${domain.riskScore}/100</span></div>`);
  }

  // Typosquatting warning
  if (domain.advancedAnalysis?.typosquatting?.isTyposquat) {
    const typo = domain.advancedAnalysis.typosquatting;
    summaryHTML.push(`
      <div class="summary-section warning-box">
        <strong>⚠️ SPOOFING ALERT</strong><br>
        This domain may impersonate <strong>"${typo.likelyTarget}"</strong><br>
        Technique: ${typo.technique || 'similarity'} | Confidence: ${formatPercent(typo.confidence * 100)}
      </div>
    `);
  }

  // Homoglyph attack
  if (domain.advancedAnalysis?.homoglyphAttack?.detected) {
    const homo = domain.advancedAnalysis.homoglyphAttack;
    summaryHTML.push(`
      <div class="summary-section warning-box">
        <strong>⚠️ NON-ASCII CHARACTERS</strong><br>
        Type: ${homo.type} | Risk: ${homo.risk}
      </div>
    `);
  }

  // Suspicious TLD
  if (domain.advancedAnalysis?.suspiciousTLD?.suspicious) {
    summaryHTML.push(`
      <div class="summary-section info-box">
        <strong>ℹ️ Suspicious TLD</strong><br>
        ${domain.advancedAnalysis.suspiciousTLD.reason}
      </div>
    `);
  }

  // LLM Model detection
  if (assessment.llmResult?.likelyModel) {
    const model = assessment.llmResult.likelyModel;
    summaryHTML.push(`
      <div class="summary-section info-box">
        <strong>🤖 AI Model Detected</strong><br>
        Type: ${model.type} | Confidence: ${formatPercent(model.confidence * 100)}
      </div>
    `);
  }

  // Text statistics
  if (assessment.aiResult?.textStats) {
    const stats = assessment.aiResult.textStats;
    summaryHTML.push(`
      <div class="summary-section stats-box">
        <strong>📊 Content Analysis</strong><br>
        ${stats.wordCount} words | ${stats.sentenceCount} sentences<br>
        Readability: ${stats.readabilityScore || 'N/A'}
      </div>
    `);
  }

  container.innerHTML = summaryHTML.join('');
}

function renderRecommendations(container, domain, ai, llm, assessment) {
  container.innerHTML = "";

  const recommendations = [];

  // Gather recommendations from domain
  if (domain.recommendations && Array.isArray(domain.recommendations)) {
    domain.recommendations.forEach(rec => {
      if (typeof rec === 'string') {
        recommendations.push({ severity: 'info', message: rec });
      } else if (rec.message) {
        recommendations.push(rec);
      }
    });
  }

  // Add AI-specific recommendations
  if (ai.manipulationTechniques && ai.manipulationTechniques.length > 0) {
    recommendations.push({
      severity: 'warning',
      message: `${ai.manipulationTechniques.length} psychological manipulation technique(s) detected`
    });
  }

  // Add LLM-specific recommendations
  if (llm.riskFactors && llm.riskFactors.length > 0) {
    llm.riskFactors.forEach(factor => {
      if (factor.severity === 'high' || factor.severity === 'critical') {
        recommendations.push({
          severity: factor.severity,
          message: factor.description
        });
      }
    });
  }

  // Jailbreak warnings
  if (assessment.jailbreakDetails?.critical > 0) {
    recommendations.push({
      severity: 'critical',
      message: `${assessment.jailbreakDetails.critical} critical prompt injection attempts detected on this page`
    });
  }

  // Default message
  if (recommendations.length === 0) {
    recommendations.push({
      severity: 'info',
      message: 'No immediate threats detected. Continue monitoring.'
    });
  }

  recommendations.forEach((rec) => {
    const li = document.createElement("li");
    li.className = `recommendation-item severity-${rec.severity || 'info'}`;
    
    const icon = getSeverityIcon(rec.severity);
    li.innerHTML = `${icon} ${rec.message}`;
    
    container.appendChild(li);
  });
}

function getSeverityIcon(severity) {
  switch (severity) {
    case 'critical': return '🚨';
    case 'high': return '⚠️';
    case 'warning': return '⚠️';
    case 'medium': return '⚡';
    case 'info': return 'ℹ️';
    default: return '•';
  }
}

function applyPillState(pill, level) {
  pill.className = "pill";
  switch (level) {
    case "high":
      pill.classList.add("pill-high");
      pill.textContent = "High Risk";
      break;
    case "medium":
      pill.classList.add("pill-medium");
      pill.textContent = "Medium Risk";
      break;
    case "low":
    default:
      pill.classList.add("pill-low");
      pill.textContent = "Low Risk";
      break;
  }
}

function metricTile({ label, value, helper, important, breakdown }) {
  const card = document.createElement("div");
  card.className = important ? "metric metric-important" : "metric";
  
  const title = document.createElement("strong");
  title.textContent = label;
  
  const val = document.createElement("span");
  val.textContent = value;
  
  const hint = document.createElement("small");
  hint.textContent = helper;
  
  card.append(title, val, hint);
  
  // Add breakdown contribution if available
  if (breakdown !== undefined && breakdown !== null) {
    const contrib = document.createElement("div");
    contrib.className = "contribution";
    contrib.textContent = `Weight: ${Number(breakdown).toFixed(1)}`;
    card.appendChild(contrib);
  }
  
  return card;
}

function formatPercent(value) {
  return `${Math.round(value)}%`;
}

async function hydrateApiForm() {
  const stored = await chrome.storage.local.get(["vtApiKey", "gsbApiKey"]);
  const form = document.getElementById("api-form");
  form.elements.vtApiKey.value = stored.vtApiKey || "";
  form.elements.gsbApiKey.value = stored.gsbApiKey || "";
}

function hookApiForm() {
  const form = document.getElementById("api-form");
  const status = document.getElementById("api-status");
  
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    
    const vtApiKey = form.elements.vtApiKey.value.trim();
    const gsbApiKey = form.elements.gsbApiKey.value.trim();
    
    await Promise.all([
      chrome.runtime.sendMessage({ type: "UPSERT_API_KEY", key: "vtApiKey", value: vtApiKey }),
      chrome.runtime.sendMessage({ type: "UPSERT_API_KEY", key: "gsbApiKey", value: gsbApiKey })
    ]);
    
    status.textContent = "✓ API keys saved successfully";
    status.style.color = "#059669";
    
    setTimeout(() => {
      status.textContent = "";
    }, 3000);
  });
}

// Challenge 1 & 4: Community feedback for continuous improvement
function hookFeedbackButtons(tab, assessment) {
  const btnFalsePositive = document.getElementById("btn-false-positive");
  const btnConfirmThreat = document.getElementById("btn-confirm-threat");
  const btnMarkSafe = document.getElementById("btn-mark-safe");
  const status = document.getElementById("feedback-status");

  if (!tab || !assessment) {
    btnFalsePositive.disabled = true;
    btnConfirmThreat.disabled = true;
    btnMarkSafe.disabled = true;
    return;
  }

  btnFalsePositive.addEventListener("click", async () => {
    await submitFeedback({
      type: "false_positive",
      url: tab.url,
      domain: new URL(tab.url).hostname,
      riskLevel: assessment.riskLevel,
      compositeScore: assessment.compositeScore,
      signals: assessment.independentSignals,
      timestamp: Date.now()
    }, status);
  });

  btnConfirmThreat.addEventListener("click", async () => {
    await submitFeedback({
      type: "confirm_threat",
      url: tab.url,
      domain: new URL(tab.url).hostname,
      riskLevel: assessment.riskLevel,
      compositeScore: assessment.compositeScore,
      signals: assessment.independentSignals,
      timestamp: Date.now()
    }, status);
  });

  btnMarkSafe.addEventListener("click", async () => {
    await submitFeedback({
      type: "mark_safe",
      url: tab.url,
      domain: new URL(tab.url).hostname,
      riskLevel: assessment.riskLevel,
      compositeScore: assessment.compositeScore,
      timestamp: Date.now()
    }, status);
  });
}

async function submitFeedback(feedback, statusElement) {
  try {
    const response = await chrome.runtime.sendMessage({
      type: "SUBMIT_FEEDBACK",
      feedback
    });

    if (response && response.success) {
      statusElement.textContent = `✓ Feedback submitted (${response.queued} total)`;
      statusElement.style.color = "#059669";
      setTimeout(() => {
        statusElement.textContent = "";
      }, 3000);
    } else {
      throw new Error(response?.error || "Unknown error");
    }
  } catch (error) {
    statusElement.textContent = `✗ Error: ${error.message}`;
    statusElement.style.color = "#dc2626";
    setTimeout(() => {
      statusElement.textContent = "";
    }, 5000);
  }
}

// Blocked Items Management
async function loadBlockedItems(tab) {
  try {
    const response = await chrome.runtime.sendMessage({ type: 'GET_BLOCKED_ITEMS' });
    const blockedItems = response?.blockedItems || [];
    
    // Filter for current domain if tab available
    const currentDomain = tab ? new URL(tab.url).hostname : null;
    const relevantItems = currentDomain 
      ? blockedItems.filter(item => item.domain === currentDomain)
      : blockedItems;
    
    const count = document.getElementById('blocked-count');
    const list = document.getElementById('blocked-list');
    
    count.textContent = relevantItems.length;
    list.innerHTML = '';
    
    if (relevantItems.length === 0) {
      return; // CSS will show "No items"
    }
    
    relevantItems.forEach(item => {
      const card = createItemCard(item, 'blocked');
      list.appendChild(card);
    });
  } catch (error) {
    console.error('[Popup] Error loading blocked items:', error);
  }
}

async function loadReadLLMQueue() {
  try {
    const response = await chrome.runtime.sendMessage({ type: 'GET_READ_LLM_QUEUE' });
    const queue = response?.queue || [];
    
    const count = document.getElementById('queue-count');
    const list = document.getElementById('read-llm-list');
    
    count.textContent = queue.length;
    list.innerHTML = '';
    
    if (queue.length === 0) {
      return; // CSS will show "No items"
    }
    
    queue.forEach(item => {
      const card = createItemCard(item, 'queue');
      list.appendChild(card);
    });
  } catch (error) {
    console.error('[Popup] Error loading Read LLM queue:', error);
  }
}

function createItemCard(item, type) {
  const card = document.createElement('div');
  card.className = 'item-card';
  
  const header = document.createElement('div');
  header.className = 'item-header';
  
  const domain = document.createElement('div');
  domain.className = 'item-domain';
  domain.textContent = item.domain || 'Unknown';
  
  const time = document.createElement('div');
  time.className = 'item-time';
  time.textContent = formatTimeAgo(item.timestamp || item.addedAt || item.blockedAt);
  
  header.appendChild(domain);
  header.appendChild(time);
  
  const excerpt = document.createElement('div');
  excerpt.className = 'item-excerpt';
  excerpt.textContent = item.excerpt || 'No excerpt';
  
  const scores = document.createElement('div');
  scores.className = 'item-scores';
  
  if (item.aiScore !== undefined) {
    const aiTag = document.createElement('span');
    aiTag.className = 'score-tag';
    aiTag.textContent = `AI: ${formatPercent(item.aiScore * 100)}`;
    scores.appendChild(aiTag);
  }
  
  if (item.llmScore !== undefined) {
    const llmTag = document.createElement('span');
    llmTag.className = 'score-tag';
    llmTag.textContent = `LLM: ${formatPercent(item.llmScore * 100)}`;
    scores.appendChild(llmTag);
  }
  
  if (item.reason) {
    const reasonTag = document.createElement('span');
    reasonTag.className = 'score-tag';
    reasonTag.textContent = item.reason;
    scores.appendChild(reasonTag);
  }
  
  const actions = document.createElement('div');
  actions.className = 'item-actions';
  
  if (type === 'blocked') {
    const unblockBtn = document.createElement('button');
    unblockBtn.className = 'btn-item';
    unblockBtn.textContent = 'Unblock';
    unblockBtn.addEventListener('click', async () => {
      await unblockItem(item.id);
      card.remove();
      updateBlockedCount(-1);
    });
    actions.appendChild(unblockBtn);
    
    const viewBtn = document.createElement('button');
    viewBtn.className = 'btn-item';
    viewBtn.textContent = 'View URL';
    viewBtn.addEventListener('click', () => {
      chrome.tabs.create({ url: item.url });
    });
    actions.appendChild(viewBtn);
  } else if (type === 'queue') {
    const removeBtn = document.createElement('button');
    removeBtn.className = 'btn-item danger';
    removeBtn.textContent = 'Remove';
    removeBtn.addEventListener('click', async () => {
      await removeFromQueue(item.id);
      card.remove();
      updateQueueCount(-1);
    });
    actions.appendChild(removeBtn);
    
    const viewBtn = document.createElement('button');
    viewBtn.className = 'btn-item';
    viewBtn.textContent = 'View URL';
    viewBtn.addEventListener('click', () => {
      chrome.tabs.create({ url: item.url });
    });
    actions.appendChild(viewBtn);
  }
  
  card.appendChild(header);
  card.appendChild(excerpt);
  card.appendChild(scores);
  card.appendChild(actions);
  
  return card;
}

async function unblockItem(itemId) {
  try {
    await chrome.runtime.sendMessage({
      type: 'UNBLOCK_ITEM',
      itemId
    });
  } catch (error) {
    console.error('[Popup] Error unblocking item:', error);
  }
}

async function removeFromQueue(itemId) {
  try {
    await chrome.runtime.sendMessage({
      type: 'REMOVE_FROM_READ_LLM',
      itemId
    });
  } catch (error) {
    console.error('[Popup] Error removing from queue:', error);
  }
}

function updateBlockedCount(delta) {
  const count = document.getElementById('blocked-count');
  const current = parseInt(count.textContent) || 0;
  count.textContent = Math.max(0, current + delta);
}

function updateQueueCount(delta) {
  const count = document.getElementById('queue-count');
  const current = parseInt(count.textContent) || 0;
  count.textContent = Math.max(0, current + delta);
}

function formatTimeAgo(timestamp) {
  const seconds = Math.floor((Date.now() - timestamp) / 1000);
  
  if (seconds < 60) return 'Just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function hookBlockerControls() {
  const btnClearBlocked = document.getElementById('btn-clear-blocked');
  const btnExportQueue = document.getElementById('btn-export-queue');
  const btnClearQueue = document.getElementById('btn-clear-queue');
  
  btnClearBlocked?.addEventListener('click', async () => {
    if (confirm('Clear all blocked items for this domain?')) {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      const currentDomain = tab ? new URL(tab.url).hostname : null;
      
      const response = await chrome.runtime.sendMessage({ type: 'GET_BLOCKED_ITEMS' });
      const blockedItems = response?.blockedItems || [];
      
      for (const item of blockedItems) {
        if (!currentDomain || item.domain === currentDomain) {
          await unblockItem(item.id);
        }
      }
      
      await loadBlockedItems(tab);
    }
  });
  
  btnExportQueue?.addEventListener('click', async () => {
    const response = await chrome.runtime.sendMessage({ type: 'GET_READ_LLM_QUEUE' });
    const queue = response?.queue || [];
    
    const json = JSON.stringify(queue, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `read-llm-queue-${Date.now()}.json`;
    a.click();
    
    URL.revokeObjectURL(url);
  });
  
  btnClearQueue?.addEventListener('click', async () => {
    if (confirm('Clear entire Read LLM queue?')) {
      const response = await chrome.runtime.sendMessage({ type: 'GET_READ_LLM_QUEUE' });
      const queue = response?.queue || [];
      
      for (const item of queue) {
        await removeFromQueue(item.id);
      }
      
      await loadReadLLMQueue();
    }
  });
}

// Settings Management
async function loadSettings() {
  try {
    const response = await chrome.runtime.sendMessage({ type: 'GET_SETTINGS' });
    const settings = response?.settings || {};
    
    const toggleBlockers = document.getElementById('toggle-blockers');
    const toggleAutoBlock = document.getElementById('toggle-auto-block');
    const aiThreshold = document.getElementById('ai-threshold');
    const llmThreshold = document.getElementById('llm-threshold');
    const aiValue = document.getElementById('ai-threshold-value');
    const llmValue = document.getElementById('llm-threshold-value');
    
    if (toggleBlockers) toggleBlockers.checked = settings.blockersEnabled !== false;
    if (toggleAutoBlock) toggleAutoBlock.checked = settings.autoBlock === true;
    if (aiThreshold) {
      aiThreshold.value = settings.aiProbabilityThreshold || 0.75;
      if (aiValue) aiValue.textContent = (settings.aiProbabilityThreshold || 0.75).toFixed(2);
    }
    if (llmThreshold) {
      llmThreshold.value = settings.llmScoreThreshold || 0.65;
      if (llmValue) llmValue.textContent = (settings.llmScoreThreshold || 0.65).toFixed(2);
    }
  } catch (error) {
    console.error('[Popup] Error loading settings:', error);
  }
}

function hookSettingsControls() {
  const toggleBlockers = document.getElementById('toggle-blockers');
  const toggleAutoBlock = document.getElementById('toggle-auto-block');
  const aiThreshold = document.getElementById('ai-threshold');
  const llmThreshold = document.getElementById('llm-threshold');
  const aiValue = document.getElementById('ai-threshold-value');
  const llmValue = document.getElementById('llm-threshold-value');
  
  toggleBlockers?.addEventListener('change', async (e) => {
    await chrome.runtime.sendMessage({
      type: 'UPDATE_SETTINGS',
      settings: { blockersEnabled: e.target.checked }
    });
  });
  
  toggleAutoBlock?.addEventListener('change', async (e) => {
    await chrome.runtime.sendMessage({
      type: 'UPDATE_SETTINGS',
      settings: { autoBlock: e.target.checked }
    });
  });
  
  aiThreshold?.addEventListener('input', (e) => {
    if (aiValue) aiValue.textContent = parseFloat(e.target.value).toFixed(2);
  });
  
  aiThreshold?.addEventListener('change', async (e) => {
    await chrome.runtime.sendMessage({
      type: 'UPDATE_SETTINGS',
      settings: { aiProbabilityThreshold: parseFloat(e.target.value) }
    });
  });
  
  llmThreshold?.addEventListener('input', (e) => {
    if (llmValue) llmValue.textContent = parseFloat(e.target.value).toFixed(2);
  });
  
  llmThreshold?.addEventListener('change', async (e) => {
    await chrome.runtime.sendMessage({
      type: 'UPDATE_SETTINGS',
      settings: { llmScoreThreshold: parseFloat(e.target.value) }
    });
  });
}

