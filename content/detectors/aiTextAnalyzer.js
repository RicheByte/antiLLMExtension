(function attachAnalyzer(global) {
  if (global.AITextAnalyzer) {
    return;
  }

  class AITextAnalyzer {
    constructor() {
      // Advanced detection patterns with weighted scoring
      this.aiSignatures = {
        // GPT-3/4 common patterns
        politenessMarkers: {
          patterns: [
            /\b(?:kindly|please note|thank you for your prompt|we appreciate|we sincerely|we kindly ask)\b/gi,
            /\b(?:i understand that|i apologize for|i'd be happy to|i'm here to help)\b/gi,
            /\b(?:rest assured|please be assured|you can be confident)\b/gi
          ],
          weight: 0.15
        },
        // Structured AI writing patterns
        structureMarkers: {
          patterns: [
            /\b(?:in conclusion|as a reminder|furthermore|in addition|moreover|additionally)\b/gi,
            /\b(?:to summarize|in summary|first and foremost|it's important to note)\b/gi,
            /\b(?:moving forward|going forward|with that being said|having said that)\b/gi,
            /\b(?:alternatively|conversely|on the other hand|in contrast)\b/gi
          ],
          weight: 0.12
        },
        // Overly formal/corporate speak
        formalityMarkers: {
          patterns: [
            /\b(?:utilize|facilitate|endeavor|ascertain|aforementioned)\b/gi,
            /\b(?:pursuant to|in accordance with|notwithstanding|henceforth)\b/gi,
            /\b(?:at your earliest convenience|please do not hesitate|should you require)\b/gi
          ],
          weight: 0.10
        },
        // ChatGPT specific hedging
        hedgingMarkers: {
          patterns: [
            /\b(?:it's worth noting|it appears that|it seems that|potentially|possibly)\b/gi,
            /\b(?:you might want to|you may wish to|you could consider|it may be helpful)\b/gi,
            /\b(?:generally speaking|in most cases|typically)\b/gi
          ],
          weight: 0.08
        },
        // List/enumeration patterns
        enumerationMarkers: {
          patterns: [
            /(?:first|second|third|finally|lastly)[,:]?\s+/gi,
            /(?:\d+\.|[a-z]\))\s+[A-Z]/g,
            /(?:•|\*|\-)\s+[A-Z]/g
          ],
          weight: 0.05
        }
      };

      // Advanced statistical thresholds
      this.thresholds = {
        sentenceLength: { min: 15, max: 30, optimal: 20 },
        paragraphLength: { min: 3, max: 8, optimal: 5 },
        vocabularyDiversity: { min: 0.4, max: 0.8 },
        transitionDensity: { max: 0.15 }
      };
    }

    analyzeText(content) {
      const text = (content || "").toLowerCase();
      const originalText = content || "";
      
      if (!text || text.length < 100) {  // Increased from 50 to reduce noise
        return this.createEmptyResult();
      }

      // Multi-dimensional analysis
      const linguisticScore = this.calculateLinguisticAIScore(text, originalText);
      const statisticalScore = this.calculateStatisticalAIScore(text);
      const semanticScore = this.calculateSemanticAIScore(text);
      const structuralScore = this.calculateStructuralAIScore(originalText);
      
      // Composite AI probability with confidence interval
      const aiScore = this.calculateCompositeAIScore({
        linguistic: linguisticScore,
        statistical: statisticalScore,
        semantic: semanticScore,
        structural: structuralScore
      });

      const persuasion = this.detectPersuasionPatterns(text, originalText);
      const urgency = this.measureUrgencyTactics(text, originalText);
      const manipulation = this.detectManipulationTechniques(text, originalText);
      const credibility = this.assessCredibilitySignals(text, originalText);

      return {
        aiProbability: Number(aiScore.probability.toFixed(3)),
        confidence: Number(aiScore.confidence.toFixed(3)),
        breakdown: aiScore.breakdown,
        persuasionFlags: persuasion.flags,
        persuasionScore: Number(persuasion.score.toFixed(3)),
        urgencyScore: Number(urgency.score.toFixed(3)),
        urgencyIndicators: urgency.indicators,
        manipulationTechniques: manipulation,
        credibilityScore: Number(credibility.score.toFixed(3)),
        credibilityFactors: credibility.factors,
        recommendation: this.generateWarningLevel(aiScore.probability, urgency.score, persuasion.flags, manipulation),
        textStats: this.getTextStatistics(text, originalText)
      };
    }

    createEmptyResult() {
      return {
        aiProbability: 0,
        confidence: 0,
        breakdown: {},
        persuasionFlags: [],
        persuasionScore: 0,
        urgencyScore: 0,
        urgencyIndicators: [],
        manipulationTechniques: [],
        credibilityScore: 1,
        credibilityFactors: [],
        recommendation: "low",
        textStats: {}
      };
    }

    calculateLinguisticAIScore(text, originalText) {
      let score = 0;
      const details = {};

      for (const [category, config] of Object.entries(this.aiSignatures)) {
        let categoryHits = 0;
        for (const pattern of config.patterns) {
          const matches = text.match(pattern) || [];
          categoryHits += matches.length;
        }
        const categoryScore = Math.min((categoryHits / 10) * config.weight, config.weight);
        score += categoryScore;
        details[category] = {
          hits: categoryHits,
          score: Number(categoryScore.toFixed(3))
        };
      }

      return { score: Math.min(score, 1), details };
    }

    calculateStatisticalAIScore(text) {
      const sentences = text.split(/[.!?]+/).filter(s => s.trim().length > 5);
      
      if (sentences.length < 3) {
        return { score: 0, details: {} };
      }

      // Sentence length analysis
      const sentenceLengths = sentences.map(s => s.trim().split(/\s+/).length);
      const avgLength = sentenceLengths.reduce((a, b) => a + b, 0) / sentenceLengths.length;
      const variance = this.calculateVariance(sentenceLengths);
      const stdDev = Math.sqrt(variance);
      
      // AI tends to have consistent sentence length (low variance)
      const consistencyScore = variance < 20 ? 0.2 : 0;
      
      // AI tends to avoid very short or very long sentences
      const lengthScore = (avgLength >= 15 && avgLength <= 25) ? 0.15 : 0;
      
      // Coefficient of variation (measures relative variability)
      const cv = stdDev / avgLength;
      const variabilityScore = (cv < 0.4) ? 0.15 : 0; // Low CV indicates AI
      
      // Word diversity (Type-Token Ratio)
      const words = text.split(/\s+/).filter(w => w.length > 2);
      const uniqueWords = new Set(words.map(w => w.toLowerCase()));
      const ttr = uniqueWords.size / words.length;
      const diversityScore = (ttr >= 0.4 && ttr <= 0.6) ? 0.1 : 0; // AI has moderate diversity

      return {
        score: consistencyScore + lengthScore + variabilityScore + diversityScore,
        details: {
          avgSentenceLength: Number(avgLength.toFixed(2)),
          variance: Number(variance.toFixed(2)),
          stdDev: Number(stdDev.toFixed(2)),
          coefficientOfVariation: Number(cv.toFixed(3)),
          typeTokenRatio: Number(ttr.toFixed(3)),
          sentenceCount: sentences.length
        }
      };
    }

    calculateSemanticAIScore(text) {
      // Detect repetitive semantic patterns common in AI
      const semanticPatterns = {
        // Repetitive phrase structures
        repetitiveStarts: /\b(it is|it's|there is|there are|this is|these are)\b/gi,
        // Weak verb usage
        weakVerbs: /\b(is|are|was|were|be|being|been|have|has|had)\b/gi,
        // Filler words
        fillers: /\b(very|really|quite|rather|somewhat|fairly|pretty)\b/gi,
        // Passive voice indicators
        passiveVoice: /\b(is|are|was|were|be|being|been)\s+\w+ed\b/gi
      };

      const words = text.split(/\s+/).length;
      let score = 0;

      // Check for overuse of weak patterns
      const repetitiveStartMatches = text.match(semanticPatterns.repetitiveStarts) || [];
      if (repetitiveStartMatches.length / words > 0.05) score += 0.1;

      const weakVerbMatches = text.match(semanticPatterns.weakVerbs) || [];
      if (weakVerbMatches.length / words > 0.15) score += 0.1;

      const passiveMatches = text.match(semanticPatterns.passiveVoice) || [];
      if (passiveMatches.length > 2) score += 0.1;

      return {
        score: Math.min(score, 0.3),
        details: {
          repetitiveStartsRatio: Number((repetitiveStartMatches.length / words).toFixed(3)),
          weakVerbRatio: Number((weakVerbMatches.length / words).toFixed(3)),
          passiveVoiceCount: passiveMatches.length
        }
      };
    }

    calculateStructuralAIScore(originalText) {
      // Analyze structural patterns in formatting
      const paragraphs = originalText.split(/\n\n+/).filter(p => p.trim().length > 0);
      const hasBulletPoints = /(?:•|\*|\-|\d+\.)\s+/g.test(originalText);
      const hasNumberedLists = /\d+\.\s+[A-Z]/g.test(originalText);
      const hasHeaders = /^#{1,6}\s+/gm.test(originalText);
      
      let score = 0;
      
      // AI loves structured lists
      if (hasBulletPoints) score += 0.1;
      if (hasNumberedLists) score += 0.1;
      
      // AI tends to create well-structured paragraphs (3-6 sentences each)
      const avgParaLength = paragraphs.length > 0 
        ? paragraphs.reduce((sum, p) => sum + p.split(/[.!?]+/).length, 0) / paragraphs.length 
        : 0;
      
      if (avgParaLength >= 3 && avgParaLength <= 6) score += 0.1;

      return {
        score: Math.min(score, 0.3),
        details: {
          paragraphCount: paragraphs.length,
          avgParagraphLength: Number(avgParaLength.toFixed(2)),
          hasBulletPoints,
          hasNumberedLists,
          hasHeaders
        }
      };
    }

    calculateCompositeAIScore(components) {
      // Weighted combination with confidence estimation
      const weights = {
        linguistic: 0.35,
        statistical: 0.30,
        semantic: 0.20,
        structural: 0.15
      };

      let totalScore = 0;
      const breakdown = {};

      for (const [component, weight] of Object.entries(weights)) {
        const componentScore = components[component]?.score || 0;
        totalScore += componentScore * weight;
        breakdown[component] = {
          score: Number(componentScore.toFixed(3)),
          weight,
          contribution: Number((componentScore * weight).toFixed(3)),
          details: components[component]?.details || {}
        };
      }

      // Calculate confidence based on signal consistency
      const scores = Object.values(components).map(c => c.score);
      const avgScore = scores.reduce((a, b) => a + b, 0) / scores.length;
      const variance = this.calculateVariance(scores);
      const confidence = Math.max(0, 1 - variance); // Lower variance = higher confidence

      return {
        probability: Math.min(totalScore, 1),
        confidence: Number(confidence.toFixed(3)),
        breakdown
      };
    }

    detectPersuasionPatterns(text, originalText) {
      const persuasionTechniques = {
        urgency: [
          "urgent", "immediately", "right now", "asap", "hurry",
          "limited time", "expires soon", "act now", "don't wait",
          "time-sensitive", "last chance"
        ],
        scarcity: [
          "limited supply", "only a few left", "exclusive offer",
          "while supplies last", "limited availability", "rare opportunity"
        ],
        authority: [
          "official", "verified", "certified", "authorized",
          "government", "legal notice", "compliance required"
        ],
        fear: [
          "account suspended", "security breach", "unauthorized access",
          "fraud detected", "suspicious activity", "locked out",
          "compromised", "at risk", "warning", "alert"
        ],
        reward: [
          "free gift", "bonus", "prize", "winner", "congratulations",
          "reward", "cash back", "discount", "special offer"
        ],
        social: [
          "everyone is", "most people", "join millions",
          "trending", "popular choice", "highly rated"
        ],
        action: [
          "click here", "verify now", "confirm identity", "update immediately",
          "act now", "respond now", "call now", "download now"
        ]
      };

      const flags = [];
      const categoryScores = {};
      let totalScore = 0;

      for (const [category, keywords] of Object.entries(persuasionTechniques)) {
        const matches = keywords.filter(keyword => text.includes(keyword.toLowerCase()));
        if (matches.length > 0) {
          flags.push(...matches);
          categoryScores[category] = matches.length;
          totalScore += matches.length * 0.15; // Each match increases score
        }
      }

      return {
        flags: [...new Set(flags)],
        score: Math.min(totalScore, 1),
        categories: categoryScores
      };
    }

    measureUrgencyTactics(text, originalText) {
      const urgencyIndicators = {
        timeConstraints: [
          /(?:within|in the next)\s+\d+\s+(?:minutes?|hours?|days?)/gi,
          /expires?\s+(?:in|within)/gi,
          /deadline\s*:\s*/gi,
          /(?:by|before)\s+\d{1,2}(?:am|pm)/gi
        ],
        consequenceThreats: [
          /(?:will be|shall be)\s+(?:closed|suspended|terminated|deleted|locked)/gi,
          /failure to\s+(?:respond|comply|act|verify)/gi,
          /if you (?:do not|don't|fail to)/gi,
          /consequences\s+(?:of|for|include)/gi
        ],
        imperativeLanguage: [
          /(?:you must|you need to|you should|you have to)\s+(?:immediately|urgently|now|asap)/gi,
          /(?:immediate|urgent|critical)\s+(?:action|response|attention)\s+required/gi,
          /do\s+(?:this|it)\s+now/gi
        ],
        stressMarkers: [
          /!{2,}/g,  // Multiple exclamation marks
          /\b[A-Z]{4,}\b/g,  // CAPS LOCK words
          /\*{2,}.+?\*{2,}/g  // Bold emphasis
        ]
      };

      const indicators = [];
      let score = 0;

      for (const [category, patterns] of Object.entries(urgencyIndicators)) {
        for (const pattern of patterns) {
          const matches = originalText.match(pattern) || [];
          if (matches.length > 0) {
            indicators.push({
              category,
              count: matches.length,
              examples: matches.slice(0, 2)
            });
            score += matches.length * 0.2;
          }
        }
      }

      // Penalize excessive punctuation
      const exclamationCount = (originalText.match(/!/g) || []).length;
      if (exclamationCount > 3) {
        score += Math.min(exclamationCount * 0.05, 0.3);
      }

      return {
        score: Math.min(score, 1),
        indicators,
        exclamationCount
      };
    }

    detectManipulationTechniques(text, originalText) {
      const techniques = [];

      // Social proof manipulation - require stronger signal
      if (/(?:thousands|millions)\s+(?:of\s+)?(?:people|users|customers)/gi.test(text)) {
        techniques.push({
          type: "social_proof",
          severity: "medium",
          description: "Uses social proof to influence decision"
        });
      }

      // False authority - be more specific
      const authPattern = /(?:official|government|legal)\s+(?:notice|notification|requirement|compliance)/gi;
      if (authPattern.test(text)) {
        techniques.push({
          type: "false_authority",
          severity: "high",
          description: "Claims official/legal authority"
        });
      }

      // Reciprocity manipulation - only flag with urgency
      if (/(?:free\s+gift|exclusive\s+offer)/gi.test(text) && /(?:limited|expire|hurry)/gi.test(text)) {
        techniques.push({
          type: "reciprocity",
          severity: "low",
          description: "Uses reciprocity principle with urgency"
        });
      }

      // Emotional manipulation - require strong language
      if (/(?:immediately\s+(?:worried|concerned)|urgent.*(?:fear|panic))/gi.test(text)) {
        techniques.push({
          type: "emotional_manipulation",
          severity: "high",
          description: "Exploits emotional vulnerabilities"
        });
      }

      return techniques;
    }

    assessCredibilitySignals(text, originalText) {
      let credibilityScore = 1.0; // Start at 100% credible
      const factors = [];

      // Negative signals
      if (/(?:click here|click now)/gi.test(text)) {
        credibilityScore -= 0.15;
        factors.push({ type: "negative", description: "Generic 'click here' links" });
      }

      if (/dear\s+(?:customer|user|member)/gi.test(text)) {
        credibilityScore -= 0.2;
        factors.push({ type: "negative", description: "Generic greeting (not personalized)" });
      }

      if ((originalText.match(/!/g) || []).length > 5) {
        credibilityScore -= 0.1;
        factors.push({ type: "negative", description: "Excessive exclamation marks" });
      }

      // Positive signals
      if (/https:\/\//gi.test(originalText)) {
        credibilityScore += 0.05;
        factors.push({ type: "positive", description: "Uses HTTPS links" });
      }

      return {
        score: Math.max(0, Math.min(credibilityScore, 1)),
        factors
      };
    }

    getTextStatistics(text, originalText) {
      const words = text.split(/\s+/).filter(w => w.length > 0);
      const sentences = text.split(/[.!?]+/).filter(s => s.trim().length > 5);
      const characters = text.length;

      return {
        wordCount: words.length,
        sentenceCount: sentences.length,
        characterCount: characters,
        avgWordLength: Number((characters / words.length).toFixed(2)),
        avgSentenceLength: Number((words.length / sentences.length).toFixed(2)),
        readabilityScore: this.calculateReadability(words.length, sentences.length, this.countSyllables(text))
      };
    }

    calculateVariance(numbers) {
      if (numbers.length === 0) return 0;
      const mean = numbers.reduce((a, b) => a + b, 0) / numbers.length;
      return numbers.reduce((sum, num) => sum + Math.pow(num - mean, 2), 0) / numbers.length;
    }

    countSyllables(text) {
      // Simplified syllable counting
      const words = text.split(/\s+/);
      return words.reduce((count, word) => {
        const syllables = word.toLowerCase()
          .replace(/(?:[^laeiouy]es|ed|[^laeiouy]e)$/, '')
          .replace(/^y/, '')
          .match(/[aeiouy]{1,2}/g);
        return count + (syllables ? syllables.length : 1);
      }, 0);
    }

    calculateReadability(words, sentences, syllables) {
      // Flesch Reading Ease Score
      if (sentences === 0 || words === 0) return 0;
      const score = 206.835 - 1.015 * (words / sentences) - 84.6 * (syllables / words);
      return Number(Math.max(0, Math.min(100, score)).toFixed(2));
    }

    generateWarningLevel(aiScore, urgency, persuasion, manipulation) {
      // Advanced risk assessment
      const highRiskManipulation = manipulation.some(m => m.severity === "high");
      const criticalUrgency = urgency > 0.7;
      const excessivePersuasion = persuasion.length > 4;
      const highAIScore = aiScore > 0.7;

      if ((highRiskManipulation && criticalUrgency) || (highAIScore && excessivePersuasion && urgency > 0.5)) {
        return "high";
      }
      
      if (urgency > 0.5 || persuasion.length > 2 || (aiScore > 0.6 && manipulation.length > 0)) {
        return "medium";
      }
      
      return "low";
    }
  }

  global.AITextAnalyzer = AITextAnalyzer;
})(window);
