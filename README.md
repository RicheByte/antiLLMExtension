# AntiLLM - Advanced AI Phishing Detection Extension
![Demo Video](/assets/video.gif)
##  Overview

AntiLLM is a sophisticated browser extension that provides real-time detection of AI-generated phishing attempts, prompt injection attacks, and social engineering tactics. Using advanced machine learning patterns, behavioral analysis, and threat intelligence, it protects users from the latest generation of automated phishing campaigns.

##  Key Features

### 1. **Multi-Dimensional AI Text Analysis**
- **Linguistic Pattern Detection**: Identifies GPT-3/4, Claude, and generic LLM signatures
- **Statistical Analysis**: Examines sentence structure, variance, and consistency patterns
- **Semantic Analysis**: Detects repetitive patterns and weak verb usage common in AI
- **Structural Analysis**: Identifies over-structured content typical of AI generation
- **Confidence Scoring**: Provides reliability metrics for each detection

### 2. **Advanced LLM Fingerprinting**
- Model-specific signature detection (GPT, Claude, generic patterns)
- Contextual risk multipliers for financial/credential scenarios
- Heuristic analysis including grammar quality assessment
- Identifies specific AI models with confidence scores
- Detects phishing-specific AI patterns

### 3. **Sophisticated Jailbreak Detection**
- **Instruction Override Detection**: Monitors for attempts to bypass system prompts
- **Role-Play Jailbreaks**: Detects "DAN mode" and similar techniques
- **Prompt Extraction Attempts**: Identifies system prompt harvesting
- **Delimiter Injection**: Catches token manipulation attempts
- **Encoding Detection**: Spots obfuscated payloads (base64, hex, URL encoding)
- **Behavioral Tracking**: Historical pattern analysis for escalating threats

### 4. **Enhanced Domain Reputation**
- **Advanced Typosquatting Detection**: Levenshtein distance + character substitution
- **Homoglyph Attack Detection**: Identifies Unicode/Punycode spoofing
- **Suspicious TLD Analysis**: Flags high-risk domain extensions
- **Subdomain Analysis**: Detects brand impersonation in subdomains
- **Entropy Analysis**: Identifies randomly generated domain names
- **Brand Impersonation**: Detects combosquatting and hyphenated brand names

### 5. **Intelligent Credential Guard**
- Real-time form safety evaluation
- Dynamic form injection detection
- Cross-domain submission warnings
- Insecure (HTTP) form detection
- Hidden field analysis
- Behavioral anomaly detection
- Visual risk indicators on forms

### 6. **Comprehensive Form Behavior Monitoring**
- Cross-domain form submission tracking
- Formless credential field detection
- Hidden form detection
- Suspicious field ratio analysis
- Event handler monitoring

##  Detection Metrics

### AI Analysis Breakdown
- **AI Probability**: 0-100% likelihood of AI-generated content
- **Confidence Score**: Reliability of the AI detection
- **Urgency Score**: Level of pressure tactics detected
- **Persuasion Score**: Manipulation keyword density
- **Credibility Score**: Overall authenticity assessment

### Risk Scoring
- **Composite Risk**: Weighted combination of all signals (0-100)
- **Individual Component Scores**: Detailed breakdown per detection category
- **Contextual Multipliers**: Financial/credential context awareness
- **Dynamic Thresholds**: Adaptive risk levels based on combinations

##  Use Cases

### Protection Against:
1. **AI-Generated Phishing Emails**: Detects ChatGPT/Claude-written scams
2. **Typosquatting Attacks**: Identifies domains impersonating major brands
3. **Prompt Injection**: Monitors for jailbreak attempts in web content
4. **Social Engineering**: Recognizes urgency and manipulation tactics
5. **Credential Harvesting**: Guards password fields on suspicious sites
6. **Homoglyph Attacks**: Catches Unicode character substitution
7. **Dynamic Phishing**: Detects forms injected via JavaScript

##  Technical Architecture

### Detection Pipeline
```
Page Load → Text Extraction → Parallel Analysis
    ↓
    ├─→ AI Text Analyzer (Linguistic + Statistical + Semantic)
    ├─→ LLM Fingerprinter (Model Detection + Risk Factors)
    ├─→ Jailbreak Detector (Pattern Matching + Heuristics)
    ├─→ Domain Reputation (Local + Remote Signals)
    └─→ Credential Guard (Form Analysis + Behavioral)
    ↓
Composite Risk Calculation → User Notification
```

### Performance Optimizations
- **Debounced Analysis**: Prevents analysis spam (800ms delay)
- **Signature-based Updates**: Only sends changed assessments
- **Parallel Processing**: Concurrent execution of detectors
- **Cached Results**: Domain reputation caching (30min TTL)
- **Incremental Scanning**: Mutation observer with significance filtering

##  Scoring Algorithm

### Composite Risk Formula
```javascript
totalRisk = 
  (aiProbability × aiConfidence × 25) +
  (urgencyScore × 15) +
  (persuasionScore × 12) +
  (llmScore × llmMultiplier × 20) +
  (domainRisk / 100 × 18) +
  (jailbreakHits × 3 × criticalMultiplier) +
  (manipulationTechniques × 2.5) +
  ((1 - credibilityScore) × 15)
```

### Risk Levels
- **Low**: 0-24 (Minimal threat)
- **Medium**: 25-74 (Potential risk, caution advised)
- **High**: 75-100 (Critical threat, do not proceed)

### Critical Triggers (Immediate High Risk)
- Domain risk ≥ 80
- High-confidence typosquatting
- 3+ jailbreak attempts
- High AI + High urgency combination
- Critical LLM risk factors

##  Advanced Features

### AI Detection Capabilities
- **Politeness Markers**: Excessive formality detection
- **Structure Markers**: Transition word overuse
- **Hedging Patterns**: "It's worth noting" type phrases
- **Enumeration Detection**: Bullet points and numbered lists
- **Readability Analysis**: Flesch Reading Ease scoring
- **Type-Token Ratio**: Vocabulary diversity measurement
- **Coefficient of Variation**: Sentence length consistency

### Domain Analysis
- **Typosquatting Techniques**: Insertion, omission, transposition, substitution
- **Character Substitution**: l→1, o→0, s→5, etc.
- **Combosquatting**: Brand name + extra characters
- **Punycode Decoding**: International domain representation
- **TLD Risk Classification**: Free domains, suspicious extensions
- **Subdomain Pattern Matching**: "secure", "login", "verify" keywords

### Jailbreak Patterns (30+ Detection Rules)
- System prompt override attempts
- Role-play mode activation
- Developer/Debug mode requests
- Delimiter injection (`[SYSTEM]`, `<|endoftext|>`)
- Hypothetical scenario framing
- Reverse psychology techniques
- Context manipulation commands

##  User Interface

### Popup Display
- **Risk Pill**: Color-coded threat level (Green/Yellow/Red)
- **Metric Grid**: 8 detailed signal cards
- **Domain Summary**: Comprehensive analysis with warnings
- **Recommendations**: Actionable security advice
- **API Configuration**: VirusTotal & Safe Browsing keys

### Visual Indicators
- **Form Highlighting**: Red/Orange borders on risky forms
- **Severity Icons**: 🚨 Critical, ⚠️ Warning, ℹ️ Info
- **Animated Warnings**: Pulsing high-risk indicators
- **Gradient Design**: Modern, professional UI

##  External Integrations

### Optional APIs (Enhanced Detection)
1. **VirusTotal**: Domain malware/phishing database
2. **Google Safe Browsing**: Real-time threat feeds

### Local-First Processing
All core detection runs locally without external dependencies. APIs are optional enhancements for additional threat intelligence.

##  Installation

1. Clone or download the repository
2. Open browser extension management:
   - Chrome: `chrome://extensions/`
   - Edge: `edge://extensions/`
   - Firefox: `about:addons`
3. Enable "Developer mode"
4. Click "Load unpacked" and select the extension folder
5. (Optional) Add VirusTotal/Safe Browsing API keys in popup settings

##  Performance Metrics

### Resource Impact
- **Memory**: ~15-25MB per tab
- **CPU**: Minimal (debounced analysis)
- **Page Load Impact**: <100ms additional processing
- **Network**: Only for optional API calls

### Accuracy Targets (MVP)
- **False Positive Rate**: <5% on legitimate sites
- **Detection Accuracy**: >85% on known phishing patterns
- **AI Detection Confidence**: 70%+ on GPT-generated content

##  Privacy & Security

### Data Handling
- **Local Processing**: All analysis happens in-browser
- **No Tracking**: Zero telemetry or analytics
- **No Data Collection**: Content never leaves your device
- **Optional APIs**: User-controlled external queries
- **Secure Storage**: API keys stored in browser local storage

##  Usage Examples

### Detection Scenarios

#### Scenario 1: AI-Generated Phishing Email
```
Input: Email with perfect grammar, urgency tactics, and ChatGPT patterns
Detection:
- AI Probability: 87%
- Urgency Score: 72%
- LLM Model: GPT (Confidence: 81%)
- Risk Level: HIGH
Result: User warned before clicking links
```

#### Scenario 2: Typosquatting Attack
```
Input: User visits "micros0ft-login.com"
Detection:
- Domain Risk: 95/100
- Typosquatting: "microsoft" (Confidence: 95%)
- Technique: Character substitution (o→0)
- Risk Level: CRITICAL
Result: Red border on page, warning popup
```

#### Scenario 3: Prompt Injection on Website
```
Input: Hidden script with "Ignore previous instructions"
Detection:
- Jailbreak Hits: 3 (2 critical)
- Patterns: Instruction override, system prompt extraction
- Risk Score: 88/100
Result: Critical warning notification
```

##  Contributing

Contributions welcome! Focus areas:
- Additional AI model signatures
- New jailbreak patterns
- Performance optimizations
- UI/UX improvements
- Additional threat intelligence sources


##  Acknowledgments

Built with modern browser APIs:
- Manifest V3
- Chrome Extension APIs
- Web Standards (MutationObserver, Shadow DOM)
- Content Security Policy compliant

---

**AntiLLM** - *Protecting users from the next generation of AI-powered threats*
