(async function bootstrap() {
  if (window.__vigilInitialized) {
    return;
  }
  window.__vigilInitialized = true;

  // Initialize all detection modules
  const notifier = new ThreatNotifier();
  const domainReputation = new DomainReputation();
  const aiAnalyzer = new AITextAnalyzer();
  const llmFingerprinter = new LLMFingerprinter();
  const jailbreakDetector = new JailbreakDetector(notifier);
  const credentialGuard = new CredentialGuard(domainReputation, notifier);
  const formMonitor = new FormBehaviorMonitor(notifier, domainReputation);
  
  FormBehaviorMonitor.registerInstance(formMonitor);

  // Activate guards
  credentialGuard.init();
  formMonitor.interceptFormSubmissions();

  let lastPayloadSignature = null;
  let analysisCount = 0;
  let lastAnalysisTime = 0;
  const MIN_ANALYSIS_INTERVAL = 3000; // Increased from 1000ms to 3000ms to prevent spam

  // Debounced page scan with adaptive timing
  const scheduleScan = VigilUtils.debounce(() => {
    const now = Date.now();
    // Prevent analysis spam with stronger check
    if (now - lastAnalysisTime < MIN_ANALYSIS_INTERVAL) {
      return;
    }
    
    analyzePage().catch((error) => {
      console.error("[AntiLLM] Analysis error:", error);
      // Don't show error notifications to users
    });
  }, 1500);  // Increased from 800ms to 1500ms

  async function analyzePage() {
    try {
      lastAnalysisTime = Date.now();
      analysisCount++;

      const currentDomain = window.location.hostname;
      
      // Challenge 1: Check whitelist first (reduce false positives)
      if (window.signatureManager && window.signatureManager.isWhitelisted(currentDomain)) {
        console.log("[AntiLLM] Domain whitelisted, skipping aggressive checks:", currentDomain);
        // Still do basic analysis but with relaxed thresholds
      }

      // Collect visible text with improved extraction
      const textContent = VigilUtils.trunc(
        VigilUtils.collectVisibleText(document.body), 
        20000
      );

      if (!textContent || textContent.length < 50) {
        console.log("[Vigil] Insufficient content for analysis");
        return;
      }

      // Parallel analysis for better performance
      const [aiResult, llmResult, jailbreakResult, domainResult] = await Promise.all([
        Promise.resolve(aiAnalyzer.analyzeText(textContent)),
        Promise.resolve(llmFingerprinter.detectAIPhishing(textContent)),
        Promise.resolve(jailbreakDetector.scanPage()),
        domainReputation.checkDomain(currentDomain)
      ]);

      // Extract jailbreak hits
      const jailbreakHits = typeof jailbreakResult === 'number' 
        ? jailbreakResult 
        : (jailbreakResult?.totalHits || 0);

      // Calculate enhanced composite score
      const compositeScore = computeAdvancedCompositeScore({
        aiProbability: aiResult.aiProbability,
        aiConfidence: aiResult.confidence,
        urgencyScore: aiResult.urgencyScore,
        persuasionScore: aiResult.persuasionScore,
        persuasionCount: aiResult.persuasionFlags?.length || 0,
        llmScore: llmResult.score,
        llmRiskFactors: llmResult.riskFactors?.length || 0,
        domainRisk: domainResult?.riskScore ?? 0,
        jailbreakHits,
        jailbreakCritical: jailbreakResult?.criticalHits || 0,
        manipulationTechniques: aiResult.manipulationTechniques?.length || 0,
        credibilityScore: aiResult.credibilityScore || 1
      });

      // Challenge 1: Require multiple independent signals
      const independentSignals = countIndependentSignals({
        aiResult,
        llmResult,
        domainResult,
        jailbreakHits,
        urgencyScore: aiResult.urgencyScore,
        credentialRisk: domainResult?.riskScore || 0
      });

      const riskLevel = deriveEnhancedRiskLevel(
        compositeScore, 
        aiResult, 
        llmResult, 
        domainResult, 
        jailbreakHits,
        independentSignals
      );

      // Create comprehensive payload
      const payload = {
        url: window.location.href,
        domain: window.location.hostname,
        riskLevel,
        compositeScore: Math.round(compositeScore.total),
        breakdown: compositeScore.breakdown,
        
        // AI Analysis
        aiResult: {
          probability: aiResult.aiProbability,
          confidence: aiResult.confidence,
          breakdown: aiResult.breakdown,
          persuasionFlags: aiResult.persuasionFlags,
          persuasionScore: aiResult.persuasionScore,
          urgencyScore: aiResult.urgencyScore,
          urgencyIndicators: aiResult.urgencyIndicators,
          manipulationTechniques: aiResult.manipulationTechniques,
          credibilityScore: aiResult.credibilityScore,
          textStats: aiResult.textStats
        },
        
        // LLM Fingerprinting
        llmResult: {
          score: llmResult.score,
          totalHits: llmResult.totalHits,
          matches: llmResult.matches,
          likelyModel: llmResult.likelyModel,
          riskFactors: llmResult.riskFactors,
          contextMultiplier: llmResult.contextMultiplier
        },
        
        // Jailbreak Detection
        jailbreakHits,
        jailbreakDetails: jailbreakResult?.detections ? {
          total: jailbreakResult.totalHits,
          critical: jailbreakResult.criticalHits,
          riskScore: jailbreakResult.riskScore,
          detections: jailbreakResult.detections.slice(0, 5) // Limit for payload size
        } : null,
        
        // Domain Reputation
        domainResult: domainResult ? {
          riskScore: domainResult.riskScore,
          recommendations: domainResult.recommendations,
          advancedAnalysis: domainResult.advancedAnalysis,
          breakdown: domainResult.breakdown
        } : null,
        
        // Challenge 1: Independent signal count
        independentSignals,
        confidenceScore: aiResult.confidence,
        
        timestamp: Date.now(),
        analysisCount
      };

      // Only send if significantly changed (reduce noise)
      const signature = JSON.stringify([
        riskLevel,
        Math.round(compositeScore.total / 5) * 5, // Round to nearest 5
        Math.round(aiResult.aiProbability * 20) / 20, // Round to 0.05
        Math.round(llmResult.score * 20) / 20,
        jailbreakHits,
        Math.round((domainResult?.riskScore || 0) / 10) * 10
      ]);

      if (signature !== lastPayloadSignature) {
        chrome.runtime.sendMessage({ type: "DETECTION_RESULT", payload });
        lastPayloadSignature = signature;
        
        console.log(`[AntiLLM] Analysis #${analysisCount} completed:`, {
          risk: riskLevel,
          score: Math.round(compositeScore.total),
          ai: Math.round(aiResult.aiProbability * 100),
          llm: Math.round(llmResult.score * 100),
          domain: domainResult?.riskScore || 0,
          jailbreak: jailbreakHits
        });
      }

      // User notifications based on risk - more conservative
      // Challenge 1: Only show if multiple independent signals detected
      if (riskLevel === "high" && compositeScore.total >= 80 && independentSignals.count >= 2) {
        notifier.warn(
          `🚨 HIGH RISK: Multiple phishing indicators detected (${independentSignals.count} signals, score: ${Math.round(compositeScore.total)}/100). Avoid entering credentials.`
        );
      } else if (riskLevel === "medium" && compositeScore.total >= 60 && independentSignals.count >= 2) {
        // Only show medium warnings if multiple signals AND score is significant
        notifier.info(
          `⚠️ Potential social engineering detected (${independentSignals.count} indicators). Review carefully. (Risk: ${Math.round(compositeScore.total)}/100)`
        );
      }

      // Specific warnings for critical findings ONLY
      if (jailbreakHits >= 5 && jailbreakResult?.criticalHits >= 2) {
        notifier.warn(
          `🔒 Multiple critical prompt injection attempts detected. This page may be compromised.`
        );
      }

      if (llmResult.likelyModel && llmResult.likelyModel.confidence > 0.8) {
        const modelType = llmResult.likelyModel.type;
        if ((modelType === "Phishing" || modelType === "Impersonation") && compositeScore.total >= 60) {
          notifier.warn(
            `⚠️ AI-generated phishing patterns detected with high confidence.`
          );
        }
      }

      if (domainResult && domainResult.advancedAnalysis?.typosquatting?.isTyposquat) {
        const typo = domainResult.advancedAnalysis.typosquatting;
        if (typo.confidence > 0.85) {
          notifier.warn(
            `🎭 SPOOFING: This domain may impersonate "${typo.likelyTarget}". Verify the URL!`
          );
        }
      }

    } catch (error) {
      console.error("[AntiLLM] Fatal analysis error:", error);
      throw error;
    }
  }

  function computeAdvancedCompositeScore(metrics) {
    const weights = {
      aiProbability: 20,      // Reduced from 25
      urgencyScore: 12,       // Reduced from 15
      persuasionScore: 10,    // Reduced from 12
      llmScore: 15,           // Reduced from 20
      domainRisk: 25,         // Increased from 18 (domain is more reliable)
      jailbreakBase: 12,      // Reduced from 15
      manipulation: 8,        // Reduced from 10
      credibility: -12        // Reduced penalty from -15
    };

    let breakdown = {};
    let total = 0;

    // AI Probability (weighted by confidence) - require higher confidence
    const aiContribution = metrics.aiProbability * Math.pow(metrics.aiConfidence, 1.5) * weights.aiProbability;
    breakdown.aiAnalysis = Number(aiContribution.toFixed(2));
    total += aiContribution;

    // Urgency Score - only count if significant
    const urgencyContribution = metrics.urgencyScore > 0.3 
      ? metrics.urgencyScore * weights.urgencyScore 
      : 0;
    breakdown.urgency = Number(urgencyContribution.toFixed(2));
    total += urgencyContribution;

    // Persuasion Score - require minimum threshold
    const persuasionContribution = metrics.persuasionScore > 0.2
      ? Math.min(metrics.persuasionScore, 1) * weights.persuasionScore
      : 0;
    breakdown.persuasion = Number(persuasionContribution.toFixed(2));
    total += persuasionContribution;

    // LLM Fingerprinting (with risk factor multiplier) - cap multiplier
    const llmMultiplier = 1 + Math.min(metrics.llmRiskFactors * 0.15, 0.5);
    const llmContribution = metrics.llmScore > 0.25 
      ? metrics.llmScore * weights.llmScore * llmMultiplier
      : 0;
    breakdown.llmFingerprint = Number(llmContribution.toFixed(2));
    total += llmContribution;

    // Domain Risk - most reliable signal
    const domainContribution = (metrics.domainRisk / 100) * weights.domainRisk;
    breakdown.domainReputation = Number(domainContribution.toFixed(2));
    total += domainContribution;

    // Jailbreak Detection - only if present
    if (metrics.jailbreakHits > 0) {
      const jailbreakMultiplier = metrics.jailbreakCritical > 0 ? 1.8 : 1;
      const jailbreakContribution = Math.min(metrics.jailbreakHits * 2.5, weights.jailbreakBase) * jailbreakMultiplier;
      breakdown.jailbreakAttempts = Number(jailbreakContribution.toFixed(2));
      total += jailbreakContribution;
    } else {
      breakdown.jailbreakAttempts = 0;
    }

    // Manipulation Techniques - only severe ones
    const severeManipulation = metrics.manipulationTechniques;
    const manipulationContribution = severeManipulation > 0
      ? Math.min(severeManipulation * 2, weights.manipulation)
      : 0;
    breakdown.manipulationTactics = Number(manipulationContribution.toFixed(2));
    total += manipulationContribution;

    // Credibility (inverse - high credibility reduces score)
    const credibilityPenalty = metrics.credibilityScore < 0.7
      ? (1 - metrics.credibilityScore) * Math.abs(weights.credibility)
      : 0;
    breakdown.credibilityPenalty = Number(credibilityPenalty.toFixed(2));
    total += credibilityPenalty;

    return {
      total: Math.min(total, 100),
      breakdown,
      confidence: metrics.aiConfidence
    };
  }

  // Challenge 1: Count independent risk signals
  function countIndependentSignals(data) {
    const signals = [];
    
    // Signal 1: High AI probability with confidence
    if (data.aiResult.aiProbability > 0.7 && data.aiResult.confidence > 0.6) {
      signals.push({
        type: "high_ai_probability",
        value: data.aiResult.aiProbability,
        confidence: data.aiResult.confidence
      });
    }
    
    // Signal 2: High urgency tactics
    if (data.urgencyScore > 0.6) {
      signals.push({
        type: "high_urgency",
        value: data.urgencyScore
      });
    }
    
    // Signal 3: Domain risk
    if (data.domainResult && data.domainResult.riskScore > 60) {
      signals.push({
        type: "domain_risk",
        value: data.domainResult.riskScore
      });
    }
    
    // Signal 4: Jailbreak detected
    if (data.jailbreakHits >= 2) {
      signals.push({
        type: "jailbreak_detected",
        value: data.jailbreakHits
      });
    }
    
    // Signal 5: LLM fingerprint with risk factors
    if (data.llmResult.score > 0.6 && data.llmResult.riskFactors?.length > 0) {
      signals.push({
        type: "llm_phishing_pattern",
        value: data.llmResult.score,
        riskFactors: data.llmResult.riskFactors.length
      });
    }
    
    // Signal 6: Credential context risk
    if (data.credentialRisk > 70) {
      signals.push({
        type: "credential_risk",
        value: data.credentialRisk
      });
    }
    
    return {
      count: signals.length,
      signals,
      description: signals.map(s => s.type).join(", ")
    };
  }

  function deriveEnhancedRiskLevel(compositeScore, aiResult, llmResult, domainResult, jailbreakHits, independentSignals) {
    const score = compositeScore.total;
    
    // Critical conditions that immediately trigger high risk (more conservative)
    const criticalConditions = [
      domainResult?.riskScore >= 85,  // Increased from 80
      domainResult?.advancedAnalysis?.typosquatting?.isTyposquat && domainResult.advancedAnalysis.typosquatting.confidence > 0.9,  // Increased from 0.8
      jailbreakHits >= 5,  // Increased from 3
      (aiResult.urgencyScore > 0.85 && llmResult.score > 0.75),  // Both increased
      llmResult.riskFactors?.filter(rf => rf.severity === "critical").length >= 2,  // Require multiple critical factors
      aiResult.manipulationTechniques?.filter(mt => mt.severity === "high").length >= 2 && aiResult.urgencyScore > 0.7
    ];

    if (criticalConditions.some(condition => condition)) {
      return "high";
    }

    // Score-based thresholds - more conservative
    if (score >= 80) {  // Increased from 75
      return "high";
    } else if (score >= 50) {  // Increased from 45
      return "medium";
    } else if (score >= 30) {  // Increased from 25
      return "low";
    }

    return "low";
  }

  // Initial page analysis
  console.log("[AntiLLM] Initialized and monitoring...");
  await analyzePage().catch((error) => {
    console.error("[AntiLLM] Initial analysis failed:", error);
  });

  // Set up observers for dynamic content - more selective
  const mutationObserver = new MutationObserver((mutations) => {
    // Only trigger if significant changes occurred
    let significantChange = false;
    let addedTextLength = 0;

    for (const mutation of mutations) {
      if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
        // Check if added nodes contain substantial content
        for (const node of mutation.addedNodes) {
          if (node.nodeType === Node.ELEMENT_NODE) {
            const text = node.textContent || '';
            if (text.length > 100) {  // Only trigger for substantial content additions
              addedTextLength += text.length;
              significantChange = true;
            }
          } else if (node.nodeType === Node.TEXT_NODE) {
            const text = node.textContent || '';
            if (text.trim().length > 50) {
              addedTextLength += text.length;
              significantChange = true;
            }
          }
        }
      }
    }

    // Only schedule scan if we added substantial content (>200 chars)
    if (significantChange && addedTextLength > 200) {
      scheduleScan();
    }
  });

  mutationObserver.observe(document.documentElement, {
    subtree: true,
    childList: true,
    characterData: false  // Don't watch character changes to reduce noise
  });

  // Listen for navigation events (SPAs)
  window.addEventListener("focus", () => scheduleScan());
  window.addEventListener("hashchange", () => scheduleScan());
  
  // Listen for history changes (for SPAs using pushState)
  const originalPushState = history.pushState;
  history.pushState = function(...args) {
    history.pushState.apply(this, args);
    scheduleScan();
  };

  console.log("[AntiLLM] Active and monitoring page changes");
})();
