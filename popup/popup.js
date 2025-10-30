document.addEventListener("DOMContentLoaded", init);

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const assessment = tab ? await chrome.runtime.sendMessage({ type: "GET_TAB_ASSESSMENT", tabId: tab.id }) : null;
  renderAssessment(assessment);
  await hydrateApiForm();
  hookApiForm();
  hookFeedbackButtons(tab, assessment);
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

