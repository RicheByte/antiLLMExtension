(function attachDomainReputation(global) {
  if (global.DomainReputation) {
    return;
  }

  class DomainReputation {
    constructor() {
      // Extended list of commonly impersonated domains
      this.commonDomains = [
        // Tech companies
        "google", "facebook", "microsoft", "apple", "amazon", "netflix", "twitter",
        "instagram", "linkedin", "youtube", "zoom", "slack", "dropbox", "adobe",
        // Financial institutions
        "paypal", "chase", "bankofamerica", "wellsfargo", "citibank", "usbank",
        "capitalone", "americanexpress", "discover", "visa", "mastercard",
        // E-commerce
        "ebay", "walmart", "target", "bestbuy", "costco", "etsy",
        // Email/Communication
        "outlook", "gmail", "yahoo", "protonmail", "icloud",
        // Crypto/Finance
        "coinbase", "binance", "kraken", "blockchain", "crypto",
        // Government (common phishing targets)
        "irs", "usps", "fedex", "ups", "dhl"
      ];

      // Suspicious TLDs often used in phishing
      this.suspiciousTLDs = [
        ".tk", ".ml", ".ga", ".cf", ".gq",  // Free domains
        ".xyz", ".top", ".work", ".click", ".link",
        ".loan", ".download", ".racing", ".accountant", ".science",
        ".faith", ".win", ".bid", ".cricket", ".party"
      ];

      // Legitimate TLDs (reduces false positives)
      this.legitimateTLDs = [
        ".com", ".org", ".net", ".edu", ".gov", ".mil",
        ".co.uk", ".ac.uk", ".gov.uk", ".ca", ".de", ".fr"
      ];

      this.domainCache = new Map();
      this.cacheExpiry = 1000 * 60 * 30; // 30 minutes
    }

    async checkDomain(domain) {
      if (!domain || domain === "localhost" || /^\d+\.\d+\.\d+\.\d+$/.test(domain)) {
        return this.createLocalHostResult(domain);
      }

      // Check cache first
      const cached = this.getCachedResult(domain);
      if (cached) {
        return cached;
      }

      try {
        const response = await chrome.runtime.sendMessage({
          type: "REQUEST_DOMAIN_REPUTATION",
          domain
        });

        if (response?.computedRisk !== undefined) {
          const enrichedResult = {
            domain,
            riskScore: response.computedRisk,
            localSignals: response.localSignals,
            remoteSignals: response.remoteSignals,
            advancedAnalysis: this.performAdvancedAnalysis(domain, response),
            recommendations: this.generateEnhancedActionItems(response, domain),
            breakdown: this.createRiskBreakdown(response, domain)
          };

          this.cacheResult(domain, enrichedResult);
          return enrichedResult;
        }
      } catch (error) {
        const fallbackResult = {
          riskScore: this.fallbackRisk(domain),
          domain,
          localSignals: { error: error.message },
          remoteSignals: null,
          advancedAnalysis: this.performAdvancedAnalysis(domain, null),
          recommendations: this.generateFallbackRecommendations(domain),
          breakdown: { error: true, message: error.message }
        };

        this.cacheResult(domain, fallbackResult);
        return fallbackResult;
      }

      return this.createFallbackResult(domain);
    }

    getCachedResult(domain) {
      if (this.domainCache.has(domain)) {
        const cached = this.domainCache.get(domain);
        if (Date.now() - cached.timestamp < this.cacheExpiry) {
          return cached.result;
        } else {
          this.domainCache.delete(domain);
        }
      }
      return null;
    }

    cacheResult(domain, result) {
      this.domainCache.set(domain, {
        result,
        timestamp: Date.now()
      });
    }

    performAdvancedAnalysis(domain, response) {
      const analysis = {
        domainAge: this.estimateDomainAge(domain),
        typosquatting: this.advancedTyposquatAnalysis(domain),
        suspiciousTLD: this.analyzeTLD(domain),
        subdomainAnalysis: this.analyzeSubdomains(domain),
        homoglyphAttack: this.detectHomoglyphs(domain),
        brandImpersonation: this.detectBrandImpersonation(domain),
        entropyAnalysis: this.analyzeEntropy(domain),
        patternMatching: this.detectSuspiciousPatterns(domain)
      };

      return analysis;
    }

    advancedTyposquatAnalysis(domain) {
      const baseDomain = domain.split(".")[0];
      const results = {
        isTyposquat: false,
        likelyTarget: null,
        distance: Infinity,
        technique: null,
        confidence: 0
      };

      for (const target of this.commonDomains) {
        // Levenshtein distance
        const distance = VigilUtils.levenshteinDistance(baseDomain, target);
        
        if (distance <= 2 && distance < results.distance) {
          results.isTyposquat = true;
          results.likelyTarget = target;
          results.distance = distance;
          results.confidence = 1 - (distance / Math.max(baseDomain.length, target.length));
          
          // Identify technique
          if (distance === 1) {
            results.technique = this.identifyTyposquatTechnique(baseDomain, target);
          }
        }

        // Check for common substitutions (l->1, o->0, etc.)
        if (this.checkCharacterSubstitution(baseDomain, target)) {
          results.isTyposquat = true;
          results.likelyTarget = target;
          results.technique = "character_substitution";
          results.confidence = 0.9;
        }

        // Check for added/removed characters
        if (baseDomain.includes(target) && baseDomain !== target) {
          results.isTyposquat = true;
          results.likelyTarget = target;
          results.technique = "combosquatting";
          results.confidence = 0.85;
        }
      }

      return results;
    }

    identifyTyposquatTechnique(squat, target) {
      // Common typosquatting techniques
      if (squat.length === target.length + 1) return "insertion";
      if (squat.length === target.length - 1) return "omission";
      if (squat.length === target.length) {
        // Check for transposition
        for (let i = 0; i < target.length - 1; i++) {
          if (squat[i] === target[i + 1] && squat[i + 1] === target[i]) {
            return "transposition";
          }
        }
        return "substitution";
      }
      return "unknown";
    }

    checkCharacterSubstitution(squat, target) {
      const substitutions = {
        'l': ['1', 'i'],
        'i': ['l', '1'],
        'o': ['0'],
        '0': ['o'],
        's': ['5', '$'],
        'a': ['@'],
        'e': ['3'],
        'g': ['9'],
        'b': ['8']
      };

      for (const [original, replacements] of Object.entries(substitutions)) {
        for (const replacement of replacements) {
          if (squat === target.replace(new RegExp(original, 'g'), replacement)) {
            return true;
          }
        }
      }

      return false;
    }

    analyzeTLD(domain) {
      const parts = domain.split(".");
      if (parts.length < 2) {
        return { suspicious: false, tld: null };
      }

      const tld = "." + parts.slice(-1)[0];
      const secondLevel = parts.length > 2 ? "." + parts.slice(-2).join(".") : tld;

      const analysis = {
        tld: secondLevel,
        suspicious: false,
        risk: "low",
        reason: null
      };

      // Check for suspicious TLDs
      if (this.suspiciousTLDs.includes(secondLevel.toLowerCase()) || 
          this.suspiciousTLDs.includes(tld.toLowerCase())) {
        analysis.suspicious = true;
        analysis.risk = "high";
        analysis.reason = "TLD commonly used in phishing/spam";
      }

      // Check for unusual country code TLDs with suspicious content
      if (/\.(tk|ml|ga|cf|gq)$/i.test(domain)) {
        analysis.suspicious = true;
        analysis.risk = "high";
        analysis.reason = "Free domain service often abused";
      }

      return analysis;
    }

    analyzeSubdomains(domain) {
      const parts = domain.split(".");
      const analysis = {
        count: Math.max(0, parts.length - 2),
        suspicious: false,
        flags: []
      };

      // Too many subdomains is suspicious
      if (analysis.count > 3) {
        analysis.suspicious = true;
        analysis.flags.push("Excessive subdomains");
      }

      // Check for brand names in subdomains (common phishing tactic)
      for (const brand of this.commonDomains) {
        for (let i = 0; i < parts.length - 2; i++) {
          if (parts[i].toLowerCase().includes(brand)) {
            analysis.suspicious = true;
            analysis.flags.push(`Brand name "${brand}" in subdomain`);
          }
        }
      }

      // Check for suspicious subdomain patterns
      const suspiciousSubdomains = ["secure", "login", "account", "verify", "update", "auth"];
      for (const suspicious of suspiciousSubdomains) {
        if (parts.slice(0, -2).some(part => part.toLowerCase().includes(suspicious))) {
          analysis.suspicious = true;
          analysis.flags.push(`Suspicious subdomain keyword: "${suspicious}"`);
        }
      }

      return analysis;
    }

    detectHomoglyphs(domain) {
      // Detect Unicode homoglyph attacks (visually similar characters)
      const hasNonAscii = /[^\x00-\x7F]/.test(domain);
      const hasPunycode = domain.startsWith("xn--");

      const analysis = {
        detected: hasNonAscii || hasPunycode,
        type: null,
        risk: "low"
      };

      if (hasPunycode) {
        analysis.type = "punycode";
        analysis.risk = "high";
        analysis.decoded = this.decodePunycode(domain);
      } else if (hasNonAscii) {
        analysis.type = "unicode";
        analysis.risk = "medium";
      }

      return analysis;
    }

    decodePunycode(domain) {
      try {
        // Simple punycode detection (full decode requires library)
        return { original: domain, note: "Contains international characters" };
      } catch {
        return { original: domain, error: "Could not decode" };
      }
    }

    detectBrandImpersonation(domain) {
      const baseDomain = domain.split(".")[0].toLowerCase();
      const impersonation = {
        detected: false,
        brands: [],
        confidence: 0
      };

      for (const brand of this.commonDomains) {
        // Exact match in domain
        if (baseDomain.includes(brand) && baseDomain !== brand) {
          impersonation.detected = true;
          impersonation.brands.push({
            name: brand,
            position: "base_domain",
            confidence: 0.8
          });
        }

        // Check for hyphenated versions
        if (baseDomain.includes(brand + "-") || baseDomain.includes("-" + brand)) {
          impersonation.detected = true;
          impersonation.brands.push({
            name: brand,
            position: "hyphenated",
            confidence: 0.9
          });
        }
      }

      if (impersonation.brands.length > 0) {
        impersonation.confidence = Math.max(...impersonation.brands.map(b => b.confidence));
      }

      return impersonation;
    }

    analyzeEntropy(domain) {
      const baseDomain = domain.split(".")[0];
      const entropy = this.calculateEntropy(baseDomain);

      return {
        value: Number(entropy.toFixed(3)),
        assessment: entropy > 4.5 ? "high" : entropy > 3.5 ? "medium" : "low",
        note: entropy > 4.5 ? "Unusually random (may be generated)" : "Normal"
      };
    }

    calculateEntropy(str) {
      const freq = {};
      for (const char of str) {
        freq[char] = (freq[char] || 0) + 1;
      }

      let entropy = 0;
      const len = str.length;
      for (const count of Object.values(freq)) {
        const p = count / len;
        entropy -= p * Math.log2(p);
      }

      return entropy;
    }

    detectSuspiciousPatterns(domain) {
      const patterns = {
        hasNumbers: /\d/.test(domain),
        hasHyphens: /-/.test(domain),
        excessiveHyphens: (domain.match(/-/g) || []).length > 2,
        allNumbers: /^\d+$/.test(domain.split(".")[0]),
        randomLooking: this.looksRandom(domain.split(".")[0]),
        shortDomain: domain.split(".")[0].length < 4
      };

      patterns.suspicionScore = (
        (patterns.excessiveHyphens ? 0.3 : 0) +
        (patterns.allNumbers ? 0.4 : 0) +
        (patterns.randomLooking ? 0.2 : 0) +
        (patterns.shortDomain && patterns.hasNumbers ? 0.1 : 0)
      );

      return patterns;
    }

    looksRandom(str) {
      // Heuristic: check for lack of vowels or consonant clusters
      const vowels = (str.match(/[aeiou]/gi) || []).length;
      const consonants = str.length - vowels;
      const vowelRatio = vowels / str.length;

      // Normal words have 30-50% vowels
      return vowelRatio < 0.2 || vowelRatio > 0.6;
    }

    estimateDomainAge(domain) {
      // This is a heuristic - real age requires WHOIS
      // Check if it's a well-known domain
      const baseDomain = domain.split(".")[0];
      
      if (this.commonDomains.includes(baseDomain)) {
        return { estimate: "old", confidence: "high", note: "Well-known brand" };
      }

      // Heuristic based on TLD
      const tld = domain.split(".").slice(-1)[0];
      if (["com", "org", "net"].includes(tld)) {
        return { estimate: "unknown", confidence: "low", note: "Common TLD" };
      }

      return { estimate: "unknown", confidence: "very-low", note: "Requires WHOIS lookup" };
    }

    generateEnhancedActionItems(response, domain) {
      const items = [];
      const localSignals = response.localSignals || {};
      const remoteSignals = response.remoteSignals || {};
      const advanced = this.performAdvancedAnalysis(domain, response);

      // Typosquatting warnings
      if (advanced.typosquatting.isTyposquat) {
        items.push({
          severity: "critical",
          message: `⚠️ CRITICAL: Domain appears to impersonate "${advanced.typosquatting.likelyTarget}". Verify URL carefully!`,
          action: "Do not enter credentials or sensitive information."
        });
      }

      // Homoglyph attacks
      if (advanced.homoglyphAttack.detected) {
        items.push({
          severity: "high",
          message: `⚠️ Domain contains non-standard characters (${advanced.homoglyphAttack.type}). May be spoofing another site.`,
          action: "Verify the actual domain name character-by-character."
        });
      }

      // Suspicious TLD
      if (advanced.suspiciousTLD.suspicious) {
        items.push({
          severity: "medium",
          message: `Domain uses suspicious TLD: ${advanced.suspiciousTLD.reason}`,
          action: "Exercise extra caution with financial or personal information."
        });
      }

      // Subdomain manipulation
      if (advanced.subdomainAnalysis.suspicious) {
        items.push({
          severity: "medium",
          message: `Suspicious subdomain pattern: ${advanced.subdomainAnalysis.flags.join(", ")}`,
          action: "Verify this is the official URL for the service."
        });
      }

      // Threat intelligence findings
      if (remoteSignals?.vtResult?.malicious > 0) {
        items.push({
          severity: "critical",
          message: `🚨 ${remoteSignals.vtResult.malicious} security vendors flagged this domain as malicious!`,
          action: "Leave this site immediately."
        });
      }

      if (remoteSignals?.gsbResult?.matches?.length > 0) {
        items.push({
          severity: "critical",
          message: `🚨 Google Safe Browsing reports this site as dangerous.`,
          action: "Do not proceed. Report to your security team."
        });
      }

      // Entropy warning
      if (advanced.entropyAnalysis.assessment === "high") {
        items.push({
          severity: "low",
          message: "Domain name appears randomly generated.",
          action: "Verify legitimacy before trusting this site."
        });
      }

      // Default safe message
      if (items.length === 0 && response.computedRisk < 30) {
        items.push({
          severity: "info",
          message: "✓ No major threats detected for this domain.",
          action: "Continue monitoring for unusual behavior."
        });
      }

      return items;
    }

    generateFallbackRecommendations(domain) {
      const advanced = this.performAdvancedAnalysis(domain, null);
      const items = [];

      if (advanced.typosquatting.isTyposquat) {
        items.push({
          severity: "critical",
          message: `Possible impersonation of "${advanced.typosquatting.likelyTarget}"`,
          action: "Verify URL immediately."
        });
      }

      items.push({
        severity: "warning",
        message: "Unable to verify domain reputation. Threat intelligence unavailable.",
        action: "Proceed with caution. Avoid entering sensitive information."
      });

      return items;
    }

    createRiskBreakdown(response, domain) {
      const breakdown = {
        localFactors: [],
        remoteFactors: [],
        totalScore: response.computedRisk
      };

      const localSignals = response.localSignals || {};
      const remoteSignals = response.remoteSignals || {};

      if (localSignals.typosquatLikelihood > 0.6) {
        breakdown.localFactors.push({ factor: "Typosquatting", contribution: 35, evidence: "High similarity to known brand" });
      }

      if (localSignals.entropy > 4) {
        breakdown.localFactors.push({ factor: "High Entropy", contribution: 15, evidence: `Entropy: ${localSignals.entropy}` });
      }

      if (localSignals.isPunycode) {
        breakdown.localFactors.push({ factor: "Punycode", contribution: 25, evidence: "Non-ASCII characters" });
      }

      if (remoteSignals?.vtResult?.malicious > 0) {
        breakdown.remoteFactors.push({ 
          factor: "VirusTotal", 
          contribution: 30, 
          evidence: `${remoteSignals.vtResult.malicious} vendors flagged as malicious` 
        });
      }

      if (remoteSignals?.gsbResult?.matches?.length) {
        breakdown.remoteFactors.push({ 
          factor: "Google Safe Browsing", 
          contribution: 30, 
          evidence: "Flagged as dangerous" 
        });
      }

      return breakdown;
    }

    createLocalHostResult(domain) {
      return {
        domain,
        riskScore: 0,
        localSignals: { localhost: true },
        remoteSignals: null,
        advancedAnalysis: {},
        recommendations: [
          {
            severity: "info",
            message: "Local development environment detected.",
            action: "Standard local security practices apply."
          }
        ],
        breakdown: { localhost: true }
      };
    }

    createFallbackResult(domain) {
      return {
        domain,
        riskScore: this.fallbackRisk(domain),
        localSignals: {},
        remoteSignals: null,
        advancedAnalysis: this.performAdvancedAnalysis(domain, null),
        recommendations: this.generateFallbackRecommendations(domain),
        breakdown: { fallback: true }
      };
    }

    fallbackRisk(domain) {
      let base = 20;
      
      if (this.analyzeTyposquatting(domain)) base += 40;
      if (domain.includes("-")) base += 10;
      if (this.analyzeTLD(domain).suspicious) base += 30;
      
      return Math.min(base, 100);
    }

    analyzeTyposquatting(domain) {
      const base = domain.split(".")[0];
      return this.commonDomains.some((common) => {
        const distance = VigilUtils.levenshteinDistance(base, common);
        return distance > 0 && distance <= 2;
      });
    }

    async getScore(domain) {
      const result = await this.checkDomain(domain);
      return result?.riskScore ?? 0;
    }
  }

  global.DomainReputation = DomainReputation;
})(window);
