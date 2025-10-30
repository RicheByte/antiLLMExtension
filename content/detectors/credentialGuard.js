(function attachCredentialGuard(global) {
  if (global.CredentialGuard) {
    return;
  }

  class CredentialGuard {
    constructor(domainReputation, notifier, options = {}) {
      this.domainReputation = domainReputation;
      this.notifier = notifier;
      this.threshold = options.threshold ?? 70;  // Increased from 55 to reduce false positives
      this.boundHandler = null;
      this.boundFocusHandler = null;
      
      // Track form interactions for behavioral analysis
      this.formInteractions = new Map();
      this.passwordFieldActivity = new Map();
      
      // Patterns indicating credential-related fields
      this.credentialPatterns = {
        password: /pass(word|phrase|wd|code)?/i,
        username: /user(name)?|email|login|account/i,
        otp: /otp|token|code|2fa|mfa|verification/i,
        security: /security|secret|pin|ssn|social/i
      };

      // Suspicious form behaviors
      this.suspiciousBehaviors = new Set();
      
      // Cooldown for form evaluations
      this.lastWarningTime = 0;
      this.warningCooldown = 10000; // 10 seconds between warnings
    }

    init() {
      if (this.boundHandler) {
        return;
      }

      this.boundHandler = this.handleInput.bind(this);
      this.boundFocusHandler = this.handleFocus.bind(this);
      this.boundBlurHandler = this.handleBlur.bind(this);

      global.document.addEventListener("input", this.boundHandler, true);
      global.document.addEventListener("focus", this.boundFocusHandler, true);
      global.document.addEventListener("blur", this.boundBlurHandler, true);

      // Monitor for dynamically added forms
      this.observeDynamicForms();
    }

    observeDynamicForms() {
      const observer = new MutationObserver((mutations) => {
        for (const mutation of mutations) {
          if (mutation.type === "childList") {
            mutation.addedNodes.forEach(node => {
              if (node.nodeType === Node.ELEMENT_NODE) {
                // Check if the added node contains password fields
                if (node.tagName === "FORM" || node.querySelector) {
                  const passwordFields = node.querySelectorAll 
                    ? node.querySelectorAll('input[type="password"]') 
                    : [];
                  
                  if (passwordFields.length > 0) {
                    this.analyzeDynamicForm(node, passwordFields);
                  }
                }
              }
            });
          }
        }
      });

      observer.observe(global.document.body, {
        childList: true,
        subtree: true
      });
    }

    analyzeDynamicForm(container, passwordFields) {
      // Dynamically injected forms are suspicious - but don't always notify
      this.suspiciousBehaviors.add("dynamic_form_injection");
      
      // Only warn if there are multiple concerning factors
      passwordFields.forEach(field => {
        const form = field.closest("form");
        if (form) {
          this.evaluateFormSafety(form, true);
        }
      });
    }

    async handleFocus(event) {
      const target = event.target;
      if (!this.isCredentialField(target)) return;

      const fieldId = this.getFieldIdentifier(target);
      const timestamp = Date.now();

      // Track when user focuses on credential fields
      if (!this.passwordFieldActivity.has(fieldId)) {
        this.passwordFieldActivity.set(fieldId, {
          firstFocus: timestamp,
          focusCount: 0,
          inputCount: 0
        });
      }

      const activity = this.passwordFieldActivity.get(fieldId);
      activity.focusCount++;
      activity.lastFocus = timestamp;
    }

    async handleBlur(event) {
      const target = event.target;
      if (!this.isCredentialField(target)) return;

      const fieldId = this.getFieldIdentifier(target);
      if (this.passwordFieldActivity.has(fieldId)) {
        const activity = this.passwordFieldActivity.get(fieldId);
        activity.lastBlur = Date.now();
        activity.focusDuration = activity.lastBlur - activity.lastFocus;
        
        // Very quick focus/blur might indicate automation
        if (activity.focusDuration < 100) {
          this.suspiciousBehaviors.add("rapid_field_interaction");
        }
      }
    }

    async handleInput(event) {
      const target = event.target;
      if (!this.isCredentialField(target)) return;

      const fieldId = this.getFieldIdentifier(target);
      
      // Track input activity
      if (this.passwordFieldActivity.has(fieldId)) {
        const activity = this.passwordFieldActivity.get(fieldId);
        activity.inputCount++;
        activity.lastInput = Date.now();
      }

      // Perform comprehensive safety check
      const form = target.form || target.closest("form");
      if (form) {
        await this.evaluateFormSafety(form, false);
      } else {
        // Credential field without a form is suspicious
        this.suspiciousBehaviors.add("formless_credential_field");
        await this.evaluateStandaloneField(target);
      }
    }

    isCredentialField(element) {
      if (!element || !(element instanceof HTMLInputElement)) {
        return false;
      }

      const type = (element.type || "").toLowerCase();
      const name = (element.name || "").toLowerCase();
      const id = (element.id || "").toLowerCase();
      const placeholder = (element.placeholder || "").toLowerCase();
      const autocomplete = (element.autocomplete || "").toLowerCase();

      // Check type
      if (type === "password") return true;

      // Check for credential-related patterns
      const allText = `${name} ${id} ${placeholder} ${autocomplete}`;
      for (const [category, pattern] of Object.entries(this.credentialPatterns)) {
        if (pattern.test(allText)) {
          return true;
        }
      }

      return false;
    }

    getFieldIdentifier(field) {
      return field.id || field.name || `${field.type}_${Math.random().toString(36).substr(2, 9)}`;
    }

    async evaluateFormSafety(form, isDynamic = false) {
      const formId = this.getFormIdentifier(form);
      const now = Date.now();

      // Prevent duplicate rapid evaluations
      if (this.formInteractions.has(formId)) {
        const lastEval = this.formInteractions.get(formId).lastEvaluation;
        if (now - lastEval < 5000) { // 5 second cooldown increased from 2
          return;
        }
      }

      // Global warning cooldown to prevent spam
      if (now - this.lastWarningTime < this.warningCooldown) {
        return;
      }

      try {
        const hostname = global.window.location.hostname;
        const analysis = await this.analyzeFormStructure(form);
        const reputation = await this.domainReputation.checkDomain(hostname);
        const riskScore = reputation?.riskScore ?? 0;

        // Store interaction data
        this.formInteractions.set(formId, {
          lastEvaluation: now,
          riskScore,
          analysis,
          isDynamic
        });

        // Calculate composite risk
        const compositeRisk = this.calculateCompositeRisk(riskScore, analysis, isDynamic);

        // Issue warnings based on risk level - more conservative
        if (compositeRisk >= 85 || riskScore >= 80) {  // Increased thresholds
          this.notifier?.warn(
            `🚨 CRITICAL: High phishing risk detected (${compositeRisk}/100). Do NOT enter credentials!`
          );
          this.highlightForm(form, "critical");
          this.lastWarningTime = now;
        } else if (compositeRisk >= 75 || riskScore >= 70) {  // Increased thresholds
          this.notifier?.warn(
            `⚠️ WARNING: Potential phishing risk (${compositeRisk}/100). Verify site authenticity before proceeding.`
          );
          this.highlightForm(form, "warning");
          this.lastWarningTime = now;
        }
        // Removed the low-level info notifications to reduce noise

        // Mark form with risk data
        form.setAttribute("data-vigil-risk", String(compositeRisk));
        form.setAttribute("data-vigil-analysis", JSON.stringify({
          riskScore: compositeRisk,
          domainRisk: riskScore,
          flags: analysis.suspiciousFlags
        }));

      } catch (error) {
        // Silent fail to prevent noise
        console.error("[AntiLLM] Form analysis error:", error);
      }
    }

    async evaluateStandaloneField(field) {
      try {
        const hostname = global.window.location.hostname;
        const reputation = await this.domainReputation.checkDomain(hostname);
        const riskScore = reputation?.riskScore ?? 0;

        // Only warn if domain risk is very high
        if (riskScore >= 80) {
          this.notifier?.warn(
            `⚠️ Credential field detected on high-risk site (${riskScore}/100). Avoid entering passwords.`
          );
        }
      } catch (error) {
        console.error("[AntiLLM] Standalone field analysis error:", error);
      }
    }

    async analyzeFormStructure(form) {
      const analysis = {
        suspiciousFlags: [],
        riskFactors: [],
        hasHTTPS: global.window.location.protocol === "https:",
        actionURL: null,
        crossDomain: false,
        hasHiddenFields: false,
        fieldCount: 0,
        credentialFields: 0
      };

      // Check form action
      const action = form.getAttribute("action");
      if (action) {
        try {
          const actionURL = new URL(action, global.window.location.href);
          analysis.actionURL = actionURL.href;
          analysis.crossDomain = actionURL.hostname !== global.window.location.hostname;

          if (analysis.crossDomain) {
            analysis.suspiciousFlags.push("cross_domain_submission");
            analysis.riskFactors.push({
              type: "Cross-domain submission",
              severity: "high",
              details: `Form submits to ${actionURL.hostname}`
            });
          }

          // Check for HTTP submission (insecure)
          if (actionURL.protocol === "http:") {
            analysis.suspiciousFlags.push("insecure_submission");
            analysis.riskFactors.push({
              type: "Insecure HTTP",
              severity: "critical",
              details: "Form submits over unencrypted HTTP"
            });
          }
        } catch (error) {
          analysis.suspiciousFlags.push("invalid_action_url");
        }
      } else {
        // No action means submits to current page
        analysis.actionURL = global.window.location.href;
      }

      // Analyze form fields
      const inputs = form.querySelectorAll("input, select, textarea");
      analysis.fieldCount = inputs.length;

      inputs.forEach(input => {
        // Count credential fields
        if (this.isCredentialField(input)) {
          analysis.credentialFields++;
        }

        // Check for hidden fields with suspicious content
        if (input.type === "hidden") {
          analysis.hasHiddenFields = true;
          const value = input.value || "";
          
          // Check for encoded data (might be exfiltrating)
          if (value.length > 100 || /^[A-Za-z0-9+/=]{20,}$/.test(value)) {
            analysis.suspiciousFlags.push("suspicious_hidden_field");
            analysis.riskFactors.push({
              type: "Suspicious hidden field",
              severity: "medium",
              details: "Hidden field contains encoded/large data"
            });
          }
        }
      });

      // Check form field ratio
      if (analysis.credentialFields > 0 && analysis.fieldCount === analysis.credentialFields) {
        // Form with ONLY password fields is unusual
        analysis.suspiciousFlags.push("credential_only_form");
        analysis.riskFactors.push({
          type: "Unusual form structure",
          severity: "medium",
          details: "Form contains only credential fields"
        });
      }

      // Check for autocomplete disabled (can be legitimate but also suspicious)
      if (form.getAttribute("autocomplete") === "off") {
        analysis.autocompleteDisabled = true;
      }

      // Check for suspicious form styling (might be overlaid/hidden)
      const computedStyle = global.getComputedStyle(form);
      if (computedStyle.opacity < 0.1 || computedStyle.display === "none") {
        analysis.suspiciousFlags.push("hidden_form");
        analysis.riskFactors.push({
          type: "Hidden form",
          severity: "high",
          details: "Form is not visible to user"
        });
      }

      return analysis;
    }

    calculateCompositeRisk(domainRisk, formAnalysis, isDynamic) {
      let risk = domainRisk * 0.6; // Domain contributes 60%

      // Form-specific risk factors
      if (formAnalysis.suspiciousFlags.includes("insecure_submission")) {
        risk += 25;
      }

      if (formAnalysis.suspiciousFlags.includes("cross_domain_submission")) {
        risk += 15;
      }

      if (formAnalysis.suspiciousFlags.includes("hidden_form")) {
        risk += 20;
      }

      if (formAnalysis.suspiciousFlags.includes("credential_only_form")) {
        risk += 10;
      }

      if (formAnalysis.suspiciousFlags.includes("suspicious_hidden_field")) {
        risk += 10;
      }

      if (isDynamic) {
        risk += 15;
      }

      if (this.suspiciousBehaviors.has("formless_credential_field")) {
        risk += 12;
      }

      if (this.suspiciousBehaviors.has("rapid_field_interaction")) {
        risk += 8;
      }

      return Math.min(Math.round(risk), 100);
    }

    getFormIdentifier(form) {
      return form.id || form.name || `form_${Math.random().toString(36).substr(2, 9)}`;
    }

    highlightForm(form, level) {
      // Add visual indicator without disrupting page layout
      const existingOverlay = form.querySelector(".vigil-risk-overlay");
      if (existingOverlay) {
        existingOverlay.remove();
      }

      const overlay = global.document.createElement("div");
      overlay.className = "vigil-risk-overlay";
      overlay.style.cssText = `
        position: absolute;
        top: -2px;
        left: -2px;
        right: -2px;
        bottom: -2px;
        pointer-events: none;
        border: 3px solid ${level === "critical" ? "#d32f2f" : "#f57c00"};
        border-radius: 4px;
        z-index: 10000;
        animation: vigil-pulse 2s infinite;
      `;

      // Make form container relative if it isn't
      const formPosition = global.getComputedStyle(form).position;
      if (formPosition === "static") {
        form.style.position = "relative";
      }

      form.appendChild(overlay);

      // Add animation
      if (!global.document.getElementById("antillm-form-styles")) {
        const style = global.document.createElement("style");
        style.id = "antillm-form-styles";
        style.textContent = `
          @keyframes vigil-pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
          }
        `;
        global.document.head.appendChild(style);
      }
    }
  }

  global.CredentialGuard = CredentialGuard;
})(window);
