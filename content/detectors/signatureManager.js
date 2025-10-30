(function attachSignatureManager(global) {
  if (global.SignatureManager) {
    return;
  }

  class SignatureManager {
    constructor() {
      this.signatures = null;
      this.lastUpdate = 0;
      this.updateInterval = 24 * 60 * 60 * 1000; // 24 hours
      this.signatureUrl = "https://raw.githubusercontent.com/yourusername/antillm/main/signatures/threat-signatures.json";
      this.fallbackSignatures = this.getDefaultSignatures();
    }

    async initialize() {
      // Try to load cached signatures first
      const cached = await this.loadCachedSignatures();
      if (cached) {
        this.signatures = cached;
        this.lastUpdate = Date.now();
      } else {
        this.signatures = this.fallbackSignatures;
      }

      // Check for updates in background
      this.checkForUpdates();
    }

    async loadCachedSignatures() {
      try {
        if (typeof chrome !== 'undefined' && chrome.storage) {
          const result = await chrome.storage.local.get(['signatures', 'signaturesTimestamp']);
          if (result.signatures && result.signaturesTimestamp) {
            const age = Date.now() - result.signaturesTimestamp;
            if (age < this.updateInterval) {
              console.log("[AntiLLM] Loaded cached signatures, age:", Math.round(age / 3600000), "hours");
              return result.signatures;
            }
          }
        }
      } catch (error) {
        console.error("[AntiLLM] Failed to load cached signatures:", error);
      }
      return null;
    }

    async checkForUpdates() {
      try {
        console.log("[AntiLLM] Checking for signature updates...");
        const response = await fetch(this.signatureUrl, {
          cache: 'no-cache',
          headers: {
            'Accept': 'application/json'
          }
        });

        if (!response.ok) {
          console.warn("[AntiLLM] Signature update failed:", response.status);
          return;
        }

        const newSignatures = await response.json();
        
        // Validate signature format
        if (this.validateSignatures(newSignatures)) {
          this.signatures = newSignatures;
          this.lastUpdate = Date.now();
          
          // Cache the new signatures
          if (typeof chrome !== 'undefined' && chrome.storage) {
            await chrome.storage.local.set({
              signatures: newSignatures,
              signaturesTimestamp: Date.now()
            });
          }
          
          console.log("[AntiLLM] Signatures updated to version:", newSignatures.version);
        } else {
          console.error("[AntiLLM] Invalid signature format received");
        }
      } catch (error) {
        console.warn("[AntiLLM] Signature update error:", error.message);
        // Gracefully fallback to existing/default signatures
      }
    }

    validateSignatures(sigs) {
      return sigs && 
             sigs.version && 
             sigs.signatures && 
             sigs.signatures.jailbreak && 
             sigs.signatures.llm &&
             sigs.thresholds;
    }

    getSignatures() {
      return this.signatures || this.fallbackSignatures;
    }

    getThresholds() {
      const sigs = this.getSignatures();
      return sigs.thresholds || this.fallbackSignatures.thresholds;
    }

    getWeights() {
      const sigs = this.getSignatures();
      return sigs.weights || this.fallbackSignatures.weights;
    }

    isWhitelisted(domain) {
      const sigs = this.getSignatures();
      if (!sigs.whitelist) return false;

      // Check exact domain match
      if (sigs.whitelist.domains && sigs.whitelist.domains.includes(domain)) {
        return true;
      }

      // Check pattern match
      if (sigs.whitelist.patterns) {
        for (const pattern of sigs.whitelist.patterns) {
          try {
            const regex = new RegExp(pattern);
            if (regex.test(domain)) {
              return true;
            }
          } catch (e) {
            console.warn("[AntiLLM] Invalid whitelist pattern:", pattern);
          }
        }
      }

      return false;
    }

    getDefaultSignatures() {
      // Embedded fallback signatures (same as threat-signatures.json but embedded)
      return {
        "version": "1.0.0-embedded",
        "updated": "2025-10-29T00:00:00Z",
        "signatures": {
          "jailbreak": [
            { "pattern": "ignore.*previous.*instructions?", "severity": "critical", "confidence": 0.95 },
            { "pattern": "disregard.*(?:above|prior).*(?:rules?|instructions?)", "severity": "critical", "confidence": 0.90 }
          ],
          "llm": {
            "gpt": {
              "markers": ["as an ai language model", "i don't have personal", "it's important to note"],
              "confidence_threshold": 0.7
            },
            "generic": {
              "markers": ["kindly", "please note", "rest assured"],
              "confidence_threshold": 0.6
            }
          },
          "phishing": {
            "urgency": ["urgent.*action.*required", "account.*suspended", "expires?.*soon"],
            "impersonation": ["dear.*(?:customer|user)", "security.*team"]
          },
          "domains": {
            "typosquat_targets": ["google", "microsoft", "apple", "amazon", "paypal", "netflix"],
            "suspicious_tlds": [".tk", ".ml", ".ga", ".xyz"]
          }
        },
        "thresholds": {
          "compositeRisk": { "high": 80, "medium": 50, "low": 30 },
          "jailbreakHits": { "critical": 2, "warning": 5 },
          "domainRisk": { "critical": 85, "high": 70, "medium": 50 }
        },
        "weights": {
          "aiProbability": 20,
          "urgencyScore": 12,
          "persuasionScore": 10,
          "llmScore": 15,
          "domainRisk": 25,
          "jailbreakBase": 12,
          "manipulation": 8,
          "credibility": -12
        },
        "whitelist": {
          "domains": ["google.com", "microsoft.com", "apple.com"],
          "patterns": [".*\\.google\\.com$", ".*\\.microsoft\\.com$"]
        }
      };
    }

    // Method to submit feedback (for future community intelligence)
    async submitFeedback(feedback) {
      // Placeholder for future implementation
      console.log("[AntiLLM] Feedback received (local only):", feedback);
      
      // Store locally for future analysis
      try {
        if (typeof chrome !== 'undefined' && chrome.storage) {
          const { feedbackQueue = [] } = await chrome.storage.local.get('feedbackQueue');
          feedbackQueue.push({
            ...feedback,
            timestamp: Date.now(),
            userAgent: navigator.userAgent
          });
          
          // Keep only last 100 feedback items
          const trimmed = feedbackQueue.slice(-100);
          await chrome.storage.local.set({ feedbackQueue: trimmed });
        }
      } catch (error) {
        console.error("[AntiLLM] Failed to store feedback:", error);
      }
    }
  }

  // Create global instance
  global.SignatureManager = SignatureManager;
  global.signatureManager = new SignatureManager();
  
  // Initialize on load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      global.signatureManager.initialize();
    });
  } else {
    global.signatureManager.initialize();
  }
})(window);
