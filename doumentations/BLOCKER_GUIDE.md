# Blocker System & Read LLM Queue - User Guide

## Overview

The AntiLLM extension now includes an advanced blocker system that allows you to:
1. **Automatically detect** suspicious text/links on web pages
2. **Block interactions** with flagged elements
3. **Queue items** for later analysis ("Read LLM")
4. **Customize detection** thresholds and behavior

## How It Works

### Automatic Detection

The extension scans visible text elements on every page looking for:
- AI-generated content (high probability with confidence)
- LLM phishing patterns
- High urgency tactics
- Manipulation techniques

When suspicious content is found, a **warning overlay** appears above the element.

### Warning Overlay

Each flagged element shows an overlay with:
- **Icon & Reason**: Why the element was flagged (e.g., "AI-generated content", "High urgency tactics")
- **Block Button**: Click to block all interactions with this element
- **+ Read LLM Button**: Add to analysis queue without blocking
- **✕ Dismiss**: Hide the warning (element remains active)

### Blocking Behavior

When you click **Block**:
- The element becomes non-interactive (links/buttons won't work)
- A translucent red overlay covers the blocked area
- All clicks, touches, and keyboard actions are prevented
- The block persists across page refreshes (stored by domain)
- Click **Unblock** in the overlay or popup to restore functionality

### Read LLM Queue

The "Read LLM" queue is a personal collection of suspicious items you want to review or analyze later.

**To add an item:**
- Click **+ Read LLM** on any warning overlay

**To manage the queue:**
- Open the extension popup
- View **Read LLM Queue** section
- Export queue as JSON for external analysis
- Remove individual items or clear entire queue

## Popup Interface

### Blocked Items Section
- Shows all blocked elements on the current domain
- **Unblock**: Remove block from specific item
- **View URL**: Open the page containing the blocked item
- **Clear All Blocks**: Remove all blocks for this domain

### Read LLM Queue Section  
- Shows all queued items across all sites
- **Remove**: Delete item from queue
- **View URL**: Open the page containing the item
- **Export Queue**: Download JSON file with all queue data
- **Clear Queue**: Empty the entire queue

### Settings Section

**Enable Blockers** (toggle)
- Turn the entire blocker system on/off
- Default: ON

**Auto-block High Risk** (toggle)
- Automatically block elements with very high threat scores
- Default: OFF (manual blocking only)

**AI Probability Threshold** (slider: 0.3 - 0.9)
- Minimum AI probability score to trigger a warning
- Lower = more sensitive (more warnings)
- Default: 0.75 (75%)

**LLM Score Threshold** (slider: 0.3 - 0.9)
- Minimum LLM phishing score to trigger a warning
- Lower = more sensitive
- Default: 0.65 (65%)

## Detection Thresholds

An element is flagged if it meets **AT LEAST 2** of the following conditions:

1. **AI Probability** >= 0.75 (75%) AND **Confidence** >= 0.65
2. **LLM Phishing Score** >= 0.65 (65%)
3. **Urgency Score** >= 0.7 (70%)
4. Contains **high-severity manipulation techniques**

**Exception:** Elements with extremely high risk (AI >= 0.85 AND urgency >= 0.8) are flagged with just one signal.

You can adjust thresholds in Settings to reduce false positives or increase sensitivity.

## Privacy & Data Storage

- **All data stored locally** in browser storage (no cloud sync by default)
- Blocked items contain: domain, URL, excerpt (300 chars), scores, timestamp
- Read LLM queue contains same metadata
- Maximum storage: 200 blocked items, 100 queued items (oldest removed first)
- To export data: Use "Export Queue" button in popup

## Performance

- Element scanning runs every **5 seconds** (debounced)
- Maximum **20 elements analyzed per scan** to avoid lag
- Only elements with **150+ characters** are analyzed
- Already-analyzed elements are skipped
- Requires multiple independent signals to flag (reduces false positives)
- Minimal performance impact on most pages

## Troubleshooting

### Too many false positives
1. Thresholds are already conservative (0.75 AI, 0.65 LLM)
2. Requires 2+ independent signals before flagging
3. Increase thresholds even more in Settings (0.8-0.85 for maximum strictness)
4. Dismiss warnings on known-good sites

### Not detecting threats
1. Lower thresholds in Settings (0.5-0.6 for higher sensitivity)
2. Note: System requires multiple signals, so very subtle threats may be missed
3. Ensure "Enable Blockers" is ON
4. Check browser console for errors (`F12` > Console)

### Blocked element won't unblock
1. Click "Unblock" in the overlay
2. Or use popup > Blocked Items > Unblock
3. If persists, clear all blocks for the domain

### Overlay positioning issues
- Overlays use absolute positioning relative to parent
- Some complex CSS layouts may cause misalignment
- Dismiss and use popup to manage blocks instead

## Advanced Usage

### Exporting Read LLM Queue

The exported JSON contains:
```json
[
  {
    "id": "abc123",
    "url": "https://example.com/page",
    "domain": "example.com",
    "excerpt": "Suspicious text content...",
    "aiScore": 0.75,
    "llmScore": 0.62,
    "urgencyScore": 0.8,
    "reason": "High urgency tactics",
    "timestamp": 1701648000000,
    "status": "queued"
  }
]
```

Use this data for:
- Feeding into LLM analysis tools
- Training custom models
- Reporting threats to security teams
- Personal threat intelligence database

### Whitelisting Domains

Currently via storage (future UI planned):
```javascript
// In browser console on extension popup:
chrome.storage.local.get('settings', (result) => {
  const settings = result.settings || {};
  settings.whitelistedDomains = ['trusted-site.com', 'example.org'];
  chrome.storage.local.set({ settings });
});
```

## Keyboard Shortcuts

(Future enhancement - not yet implemented)

## Feedback

Help improve detection by using the **Feedback** section in the popup:
- **False Positive**: This is legitimate content, not a threat
- **Confirm Threat**: This is definitely malicious
- **Mark as Safe**: Add to whitelist (future feature)

## Related Features

- **Domain Reputation**: Shown in popup, influences composite risk score
- **Jailbreak Detection**: Monitors for prompt injection attempts
- **Credential Guard**: Protects password entry on suspicious sites
- **Form Behavior Monitor**: Tracks unusual form submission patterns

All these systems work together to provide comprehensive protection.

## Version History

- **v0.3.0** (Dec 2025): Initial blocker system and Read LLM queue
- Future: Auto-block, advanced filtering, export formats, whitelist UI
