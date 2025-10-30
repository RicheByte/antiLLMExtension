(function attachJailbreak(global) {
  if (global.JailbreakDetector) {
    return;
  }

  class JailbreakDetector {
    constructor(notifier) {
      this.notifier = notifier;
      
      // Advanced jailbreak/prompt injection patterns
      this.patterns = {
        // Direct instruction override
        instructionOverride: {
          patterns: [
            /ignore\s+(?:all\s+)?(?:previous|prior|above|system)\s+(?:instructions|prompts|commands|rules)/gi,
            /disregard\s+(?:previous|prior|all)\s+(?:instructions|prompts)/gi,
            /forget\s+(?:everything|all|previous|instructions)/gi,
            /override\s+(?:system|default|previous)\s+(?:settings|instructions|prompts)/gi
          ],
          severity: "critical",
          weight: 0.3
        },
        // Role-play jailbreaks
        rolePlay: {
          patterns: [
            /(?:you are now|act as|pretend to be|role[\-\s]?play as)\s+(?:a |an )?(?:jailbroken|unrestricted|unfiltered)/gi,
            /(?:DAN|developer mode|god mode|sudo mode|admin mode)/gi,
            /in this (?:hypothetical|fictional) scenario/gi,
            /(?:enable|activate|switch to)\s+(?:developer|debug|admin|god|sudo)\s+mode/gi
          ],
          severity: "critical",
          weight: 0.25
        },
        // System prompt extraction
        promptExtraction: {
          patterns: [
            /(?:show|reveal|display|output|print)\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions|rules)/gi,
            /what\s+(?:are|were)\s+your\s+(?:initial|original|system)\s+(?:instructions|prompts)/gi,
            /repeat\s+your\s+(?:instructions|system prompt|rules)/gi
          ],
          severity: "critical",
          weight: 0.25
        },
        // Delimiter/token injection
        delimiterInjection: {
          patterns: [
            /\[SYSTEM\]|\[INST\]|\[\/INST\]|<\|endoftext\|>|<\|im_start\|>|<\|im_end\|>/gi,
            /```system|```assistant|```user/gi,
            /<system>|<\/system>|<assistant>|<\/assistant>/gi
          ],
          severity: "critical",
          weight: 0.30
        },
        // Hypothetical scenarios (common jailbreak)
        hypotheticalScenarios: {
          patterns: [
            /imagine\s+(?:a scenario|you are|we are in a world)/gi,
            /in\s+a\s+(?:hypothetical|fictional|alternate)\s+(?:world|universe|scenario|reality)/gi,
            /let's\s+(?:pretend|assume|say)\s+(?:that|for|you)/gi
          ],
          severity: "medium",
          weight: 0.15
        },
        // Encoding/obfuscation attempts
        encodingAttempts: {
          patterns: [
            /base64|rot13|hex|unicode|url[\-\s]?encode/gi,
            /\\x[0-9a-f]{2}|\\u[0-9a-f]{4}/gi,  // Hex/Unicode escapes
            /%[0-9a-f]{2}/gi  // URL encoding
          ],
          severity: "high",
          weight: 0.20
        },
        // Reverse psychology jailbreaks
        reversePsychology: {
          patterns: [
            /(?:don't|do not)\s+(?:tell|say|mention|think about)/gi,
            /i\s+(?:bet|guarantee)\s+you\s+(?:can't|cannot|won't)/gi,
            /you're\s+(?:not\s+allowed|forbidden|prohibited)\s+to/gi
          ],
          severity: "low",
          weight: 0.10
        },
        // Token/context manipulation
        contextManipulation: {
          patterns: [
            /reset\s+(?:context|conversation|memory)/gi,
            /clear\s+(?:history|context|memory)/gi,
            /start\s+(?:over|fresh|new)/gi,
            /new\s+(?:session|conversation|context)/gi
          ],
          severity: "medium",
          weight: 0.15
        }
      };

      // Suspicious script behaviors
      this.scriptBehaviors = {
        // Event handlers with suspicious content
        eventHandlers: ['onerror', 'onload', 'onclick', 'onmouseover', 'onfocus'],
        // Attributes that shouldn't contain instruction-like text
        suspiciousAttributes: ['data-instructions', 'data-prompt', 'data-system'],
      };

      this.detectionHistory = new Map(); // Track detection patterns over time
    }

    scanPage() {
      const results = {
        totalHits: 0,
        criticalHits: 0,
        detections: [],
        suspiciousScripts: [],
        riskScore: 0
      };

      // Scan script elements
      const scripts = global.document.querySelectorAll('script');
      scripts.forEach(script => {
        const analysis = this.analyzeNode(script, 'script');
        if (analysis.hits > 0) {
          results.detections.push(analysis);
          results.totalHits += analysis.hits;
          if (analysis.maxSeverity === 'critical') {
            results.criticalHits++;
          }
        }
      });

      // Scan event handlers
      this.scriptBehaviors.eventHandlers.forEach(handler => {
        const elements = global.document.querySelectorAll(`[${handler}]`);
        elements.forEach(element => {
          const analysis = this.analyzeNode(element, handler);
          if (analysis.hits > 0) {
            results.detections.push(analysis);
            results.totalHits += analysis.hits;
            if (analysis.maxSeverity === 'critical') {
              results.criticalHits++;
            }
          }
        });
      });

      // Scan suspicious data attributes
      this.scriptBehaviors.suspiciousAttributes.forEach(attr => {
        const elements = global.document.querySelectorAll(`[${attr}]`);
        elements.forEach(element => {
          const analysis = this.analyzeNode(element, attr);
          if (analysis.hits > 0) {
            results.detections.push(analysis);
            results.totalHits += analysis.hits;
            results.criticalHits++; // Suspicious attributes are always critical
          }
        });
      });

      // Calculate overall risk score
      results.riskScore = this.calculateRiskScore(results);

      // Notify if critical patterns found - more conservative
      if (results.criticalHits >= 2) {
        this.notifier?.warn(
          `Critical: ${results.criticalHits} potential prompt-injection payload(s) detected on this page.`
        );
      } else if (results.totalHits >= 5) {
        this.notifier?.warn(
          `Warning: ${results.totalHits} suspicious script pattern(s) detected.`
        );
      }

      // Store in history for trend analysis
      this.updateDetectionHistory(results);

      return results.totalHits;
    }

    analyzeNode(node, source) {
      const result = {
        source,
        hits: 0,
        matches: [],
        maxSeverity: 'low',
        patterns: {}
      };

      let text = '';
      
      // Extract text based on node type
      if (node.tagName === 'SCRIPT') {
        text = node.textContent || node.innerHTML || '';
      } else {
        // For event handlers and attributes
        const attrValue = node.getAttribute(source);
        text = attrValue || '';
      }

      if (!text || text.length === 0) {
        return result;
      }

      // Check against all pattern categories
      for (const [category, config] of Object.entries(this.patterns)) {
        const categoryMatches = [];
        
        for (const pattern of config.patterns) {
          const matches = text.match(pattern);
          if (matches && matches.length > 0) {
            categoryMatches.push(...matches);
            result.hits += matches.length;
            
            // Update max severity
            if (this.compareSeverity(config.severity, result.maxSeverity) > 0) {
              result.maxSeverity = config.severity;
            }
          }
        }

        if (categoryMatches.length > 0) {
          result.patterns[category] = {
            matches: [...new Set(categoryMatches)], // Remove duplicates
            severity: config.severity,
            weight: config.weight
          };
        }
      }

      // Additional heuristic checks
      const heuristics = this.performHeuristicAnalysis(text);
      if (heuristics.suspicious) {
        result.hits += heuristics.suspicionScore;
        result.patterns.heuristics = heuristics;
      }

      if (result.hits > 0) {
        result.matches = this.extractMatchContext(text, result.patterns);
      }

      return result;
    }

    performHeuristicAnalysis(text) {
      const heuristics = {
        suspicious: false,
        suspicionScore: 0,
        flags: []
      };

      // Check for base64-encoded content (common in obfuscation)
      const base64Pattern = /[A-Za-z0-9+/]{20,}={0,2}/g;
      const base64Matches = text.match(base64Pattern) || [];
      if (base64Matches.length > 2) {
        heuristics.suspicious = true;
        heuristics.suspicionScore += 0.5;
        heuristics.flags.push('Multiple base64-like strings');
      }

      // Check for excessive escape sequences
      const escapePattern = /\\[xun][0-9a-f]{2,4}/gi;
      const escapeMatches = text.match(escapePattern) || [];
      if (escapeMatches.length > 5) {
        heuristics.suspicious = true;
        heuristics.suspicionScore += 0.3;
        heuristics.flags.push('Excessive escape sequences');
      }

      // Check for instruction-like imperatives
      const imperatives = /\b(execute|run|eval|compile|interpret|process)\s+/gi;
      const imperativeMatches = text.match(imperatives) || [];
      if (imperativeMatches.length > 2) {
        heuristics.suspicious = true;
        heuristics.suspicionScore += 0.4;
        heuristics.flags.push('Instruction-like commands');
      }

      // Check for prompt-like structures
      if (text.includes('###') || text.includes('User:') || text.includes('Assistant:')) {
        heuristics.suspicious = true;
        heuristics.suspicionScore += 0.6;
        heuristics.flags.push('Prompt-like structure');
      }

      return heuristics;
    }

    extractMatchContext(text, patterns) {
      const contexts = [];
      const maxContextLength = 80;

      for (const [category, data] of Object.entries(patterns)) {
        if (category === 'heuristics') continue;
        
        for (const match of data.matches) {
          const index = text.toLowerCase().indexOf(match.toLowerCase());
          if (index !== -1) {
            const start = Math.max(0, index - 20);
            const end = Math.min(text.length, index + match.length + 20);
            const context = text.substring(start, end).trim();
            
            contexts.push({
              category,
              match,
              context: context.length > maxContextLength 
                ? context.substring(0, maxContextLength) + '...'
                : context,
              severity: data.severity
            });
          }
        }
      }

      return contexts;
    }

    calculateRiskScore(results) {
      let score = 0;

      // Base score from hits
      score += Math.min(results.totalHits * 15, 50);

      // Critical hits have high impact
      score += results.criticalHits * 30;

      // Consider severity distribution
      for (const detection of results.detections) {
        for (const [category, data] of Object.entries(detection.patterns)) {
          if (category === 'heuristics') continue;
          score += data.weight * 20;
        }
      }

      return Math.min(Math.round(score), 100);
    }

    compareSeverity(sev1, sev2) {
      const levels = { low: 1, medium: 2, high: 3, critical: 4 };
      return levels[sev1] - levels[sev2];
    }

    updateDetectionHistory(results) {
      const timestamp = Date.now();
      const key = global.window.location.hostname;
      
      if (!this.detectionHistory.has(key)) {
        this.detectionHistory.set(key, []);
      }

      const history = this.detectionHistory.get(key);
      history.push({ timestamp, ...results });

      // Keep only last 10 detections
      if (history.length > 10) {
        history.shift();
      }

      // Check for escalating pattern
      if (this.detectEscalatingThreat(history)) {
        this.notifier?.warn(
          'Alert: Escalating jailbreak attempts detected over time. This site may be compromised.'
        );
      }
    }

    detectEscalatingThreat(history) {
      if (history.length < 3) return false;

      // Check if threat level is increasing
      const recentScores = history.slice(-3).map(h => h.riskScore);
      return recentScores[0] < recentScores[1] && recentScores[1] < recentScores[2];
    }

    scanNode(node) {
      // Legacy method for backwards compatibility
      const text = node.textContent || "";
      const oldPatterns = [
        /ignore[^\w]{0,4}all[^\w]{0,4}previous/gi,
        /override[^\w]{0,4}system/gi,
        /role[^\w]{0,4}play/gi,
        /hypothetical[^\w]{0,4}scenario/gi,
        /system[^\w]{0,4}prompt/gi,
        /developer[^\w]{0,4}mode/gi,
        /sudo[^\w]{0,4}mode/gi
      ];
      
      const hit = oldPatterns.some((regex) => regex.test(text));
      if (hit) {
        this.notifier?.warn("Potential prompt-injection payload detected.");
      }
      return hit;
    }
  }

  global.JailbreakDetector = JailbreakDetector;
})(window);
