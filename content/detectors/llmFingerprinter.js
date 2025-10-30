(function attachFingerprinter(global) {
  if (global.LLMFingerprinter) {
    return;
  }

  class LLMFingerprinter {
    constructor() {
      // Advanced LLM fingerprinting patterns with model-specific signatures
      this.patterns = {
        // GPT-3/4 specific patterns
        gptSignatures: {
          patterns: [
            /\b(?:as an ai|as a language model|i don't have|i cannot|i'm unable to)\b/gi,
            /\b(?:i apologize, but|i'm sorry, but|unfortunately, i|i must inform you)\b/gi,
            /\b(?:it's important to note|it's worth mentioning|keep in mind that)\b/gi,
            /\b(?:in conclusion|to sum up|to summarize|in summary)\b/gi
          ],
          weight: 0.25,
          modelType: "GPT"
        },
        // Claude-specific patterns
        claudeSignatures: {
          patterns: [
            /\b(?:i aim to|i strive to|i'll be direct|let me be clear)\b/gi,
            /\b(?:i should clarify|to be precise|more specifically)\b/gi
          ],
          weight: 0.20,
          modelType: "Claude"
        },
        // Generic AI politeness (all models)
        unnaturalPoliteness: {
          patterns: [
            /\b(?:kindly|please note|we kindly ask|we sincerely apologize)\b/gi,
            /\b(?:we appreciate your|thank you for your prompt|rest assured)\b/gi,
            /\b(?:please be advised|please be informed|we regret to inform)\b/gi
          ],
          weight: 0.15,
          modelType: "Generic"
        },
        // Phishing-specific generic greetings
        genericGreetings: {
          patterns: [
            /\b(?:valued customer|dear user|dear client|dear customer|dear member)\b/gi,
            /\b(?:hello user|greetings customer|attention account holder)\b/gi
          ],
          weight: 0.20,
          modelType: "Phishing"
        },
        // Urgency combined with AI politeness
        urgencyMarkers: {
          patterns: [
            /\b(?:immediate action|verify now|act immediately|urgent response)\b/gi,
            /\b(?:account suspension|security alert|suspicious activity)\b/gi,
            /\b(?:final warning|last chance|expires soon|time-sensitive)\b/gi
          ],
          weight: 0.25,
          modelType: "Phishing"
        },
        // Corporate/official impersonation
        signaturePatterns: {
          patterns: [
            /\b(?:customer service team|support department|security team|compliance unit)\b/gi,
            /\b(?:fraud prevention|account verification|identity verification)\b/gi,
            /\b(?:technical support|help desk|service desk)\b/gi
          ],
          weight: 0.18,
          modelType: "Impersonation"
        },
        // Structured response patterns
        structuredPatterns: {
          patterns: [
            /(?:first|firstly|1\.|step 1)[,:]/gi,
            /(?:second|secondly|2\.|step 2)[,:]/gi,
            /(?:finally|lastly|in conclusion)[,:]/gi,
            /(?:here's what|here are|below are|following are)/gi
          ],
          weight: 0.12,
          modelType: "Generic"
        },
        // Over-explanation patterns (AI tendency)
        overExplanation: {
          patterns: [
            /\b(?:in other words|that is to say|to put it another way)\b/gi,
            /\b(?:specifically|more precisely|to be more specific)\b/gi,
            /\b(?:essentially|basically|fundamentally)\b/gi
          ],
          weight: 0.10,
          modelType: "Generic"
        }
      };

      // Contextual risk multipliers
      this.contextMultipliers = {
        financialContext: {
          keywords: ["bank", "account", "payment", "credit card", "transaction", "money", "funds", "wire transfer"],
          multiplier: 1.5
        },
        credentialContext: {
          keywords: ["password", "login", "verify", "authenticate", "credentials", "access", "sign in"],
          multiplier: 1.4
        },
        urgentContext: {
          keywords: ["urgent", "immediately", "now", "asap", "expire", "deadline", "suspend"],
          multiplier: 1.3
        }
      };
    }

    detectAIPhishing(content) {
      if (!content || content.length < 30) {
        return this.createEmptyResult();
      }

      const text = content.toLowerCase();
      const matches = {};
      const modelSignatures = {};
      let totalScore = 0;
      let totalHits = 0;

      // Pattern matching with weighted scoring
      for (const [category, config] of Object.entries(this.patterns)) {
        const categoryMatches = [];
        let categoryHits = 0;

        for (const pattern of config.patterns) {
          const found = content.match(pattern) || [];
          if (found.length > 0) {
            categoryMatches.push(...found);
            categoryHits += found.length;
          }
        }

        if (categoryMatches.length > 0) {
          matches[category] = [...new Set(categoryMatches)]; // Remove duplicates
          totalHits += categoryHits;
          
          // Weight the score
          const categoryScore = Math.min((categoryHits * 0.1) * config.weight, config.weight);
          totalScore += categoryScore;

          // Track model signatures
          if (!modelSignatures[config.modelType]) {
            modelSignatures[config.modelType] = 0;
          }
          modelSignatures[config.modelType] += categoryScore;
        }
      }

      // Apply contextual multipliers
      const contextMultiplier = this.calculateContextMultiplier(text);
      totalScore *= contextMultiplier;

      // Additional heuristics
      const heuristics = this.analyzeHeuristics(content, text);
      totalScore += heuristics.score;

      // Determine likely AI model
      const likelyModel = this.identifyLikelyModel(modelSignatures, heuristics);

      return {
        score: Number(Math.min(totalScore, 1).toFixed(3)),
        matches,
        totalHits,
        modelSignatures,
        likelyModel,
        contextMultiplier: Number(contextMultiplier.toFixed(2)),
        heuristics,
        riskFactors: this.identifyRiskFactors(matches, heuristics, contextMultiplier)
      };
    }

    createEmptyResult() {
      return {
        score: 0,
        matches: {},
        totalHits: 0,
        modelSignatures: {},
        likelyModel: null,
        contextMultiplier: 1.0,
        heuristics: {},
        riskFactors: []
      };
    }

    calculateContextMultiplier(text) {
      let maxMultiplier = 1.0;

      for (const [contextType, config] of Object.entries(this.contextMultipliers)) {
        const hasContext = config.keywords.some(keyword => text.includes(keyword));
        if (hasContext) {
          maxMultiplier = Math.max(maxMultiplier, config.multiplier);
        }
      }

      return maxMultiplier;
    }

    analyzeHeuristics(content, text) {
      let score = 0;
      const details = {};

      // Check for excessive formality (AI characteristic)
      const formalWords = text.match(/\b(?:utilize|facilitate|endeavor|commence|thereafter|hereby)\b/gi) || [];
      if (formalWords.length > 2) {
        score += 0.1;
        details.excessiveFormality = formalWords.length;
      }

      // Check for perfect grammar with urgency (suspicious combination)
      const hasUrgency = /\b(?:urgent|immediate|now|asap)\b/gi.test(text);
      const hasPerfectGrammar = this.assessGrammarQuality(content);
      if (hasUrgency && hasPerfectGrammar) {
        score += 0.15;
        details.suspiciousGrammar = true;
      }

      // Check for unnatural sentence rhythm
      const sentences = content.split(/[.!?]+/).filter(s => s.trim().length > 10);
      if (sentences.length >= 3) {
        const lengths = sentences.map(s => s.trim().split(/\s+/).length);
        const variance = this.calculateVariance(lengths);
        if (variance < 15) { // Very consistent = AI
          score += 0.1;
          details.unnaturalRhythm = { variance: Number(variance.toFixed(2)) };
        }
      }

      // Check for AI's tendency to over-structure
      const hasBullets = /(?:•|\*|\-)\s+/g.test(content);
      const hasNumbers = /\d+\.\s+/g.test(content);
      const hasHeaders = /^(?:#+|\*\*).+$/gm.test(content);
      const structureCount = [hasBullets, hasNumbers, hasHeaders].filter(Boolean).length;
      if (structureCount >= 2) {
        score += 0.08;
        details.overStructured = structureCount;
      }

      // Check for repetitive phrasing patterns
      const commonPhrases = this.findRepetitivePhrases(content);
      if (commonPhrases.length > 2) {
        score += 0.1;
        details.repetitivePhrases = commonPhrases;
      }

      return { score: Math.min(score, 0.4), details };
    }

    assessGrammarQuality(text) {
      // Simple heuristic: check for common grammar errors
      // Perfect grammar + phishing context = suspicious
      const commonErrors = [
        /\byour\s+are\b/gi,  // your are
        /\bits\s+is\b/gi,    // its is
        /\btheir\s+is\b/gi,  // their is
        /\bwanna\b/gi,       // wanna
        /\bgonna\b/gi        // gonna
      ];

      return !commonErrors.some(pattern => pattern.test(text));
    }

    findRepetitivePhrases(content) {
      const sentences = content.split(/[.!?]+/).filter(s => s.trim().length > 10);
      const starts = sentences.map(s => {
        const words = s.trim().split(/\s+/);
        return words.slice(0, 3).join(' ').toLowerCase();
      });

      const frequency = {};
      for (const start of starts) {
        frequency[start] = (frequency[start] || 0) + 1;
      }

      return Object.entries(frequency)
        .filter(([phrase, count]) => count > 1)
        .map(([phrase]) => phrase);
    }

    calculateVariance(numbers) {
      if (numbers.length === 0) return 0;
      const mean = numbers.reduce((a, b) => a + b, 0) / numbers.length;
      return numbers.reduce((sum, num) => sum + Math.pow(num - mean, 2), 0) / numbers.length;
    }

    identifyLikelyModel(signatures, heuristics) {
      if (Object.keys(signatures).length === 0) {
        return null;
      }

      // Find the model type with highest signature score
      const sorted = Object.entries(signatures)
        .sort(([, a], [, b]) => b - a);

      const [topModel, topScore] = sorted[0];

      // Only return if confidence is high enough
      if (topScore > 0.15) {
        return {
          type: topModel,
          confidence: Number(Math.min(topScore * 2, 1).toFixed(3)),
          allSignatures: Object.fromEntries(
            sorted.map(([model, score]) => [model, Number(score.toFixed(3))])
          )
        };
      }

      return null;
    }

    identifyRiskFactors(matches, heuristics, contextMultiplier) {
      const factors = [];

      // High urgency with AI patterns
      if (matches.urgencyMarkers && matches.urgencyMarkers.length > 0) {
        factors.push({
          type: "high_urgency_ai_combo",
          severity: "high",
          description: "AI-generated urgency tactics detected",
          count: matches.urgencyMarkers.length
        });
      }

      // Generic greetings (impersonal)
      if (matches.genericGreetings && matches.genericGreetings.length > 0) {
        factors.push({
          type: "impersonal_greeting",
          severity: "medium",
          description: "Generic, non-personalized greeting",
          examples: matches.genericGreetings.slice(0, 2)
        });
      }

      // Impersonation attempts
      if (matches.signaturePatterns && matches.signaturePatterns.length > 0) {
        factors.push({
          type: "authority_impersonation",
          severity: "high",
          description: "Impersonating official departments/teams",
          examples: matches.signaturePatterns.slice(0, 2)
        });
      }

      // Context-based risk
      if (contextMultiplier > 1.3) {
        factors.push({
          type: "high_risk_context",
          severity: "high",
          description: "Financial or credential-related context",
          multiplier: contextMultiplier
        });
      }

      // Suspicious grammar
      if (heuristics.details?.suspiciousGrammar) {
        factors.push({
          type: "suspicious_grammar",
          severity: "medium",
          description: "Perfect grammar with urgency (unusual for legit urgent messages)"
        });
      }

      return factors;
    }
  }

  global.LLMFingerprinter = LLMFingerprinter;
})(window);
