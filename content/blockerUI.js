(function attachBlockerUI(global) {
  if (global.BlockerUI) {
    return;
  }

  class BlockerUI {
    constructor(notifier) {
      this.notifier = notifier;
      this.blockedElements = new WeakMap(); // Store block state per element
      this.blockHandlers = new WeakMap(); // Store event handlers for cleanup
      this.overlays = new WeakMap(); // Store overlay references
    }

    /**
     * Create and inject a blocker overlay for a flagged element
     */
    createOverlay(element, analysisData) {
      // Don't create duplicate overlays
      if (this.overlays.has(element)) {
        return this.overlays.get(element);
      }

      // Create shadow host
      const shadowHost = global.document.createElement('div');
      shadowHost.className = 'antillm-blocker-host';
      shadowHost.style.cssText = `
        position: absolute;
        z-index: 999999;
        pointer-events: none;
      `;

      // Attach shadow DOM for style isolation
      const shadow = shadowHost.attachShadow({ mode: 'open' });

      // Add styles
      const style = global.document.createElement('style');
      style.textContent = `
        .overlay-container {
          position: relative;
          display: inline-flex;
          align-items: center;
          gap: 6px;
          padding: 6px 10px;
          background: rgba(255, 152, 0, 0.95);
          border: 2px solid rgba(245, 124, 0, 0.8);
          border-radius: 6px;
          font-family: system-ui, -apple-system, sans-serif;
          font-size: 12px;
          color: #fff;
          box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
          pointer-events: auto;
          white-space: nowrap;
          backdrop-filter: blur(4px);
        }
        .overlay-container.blocked {
          background: rgba(198, 40, 40, 0.95);
          border-color: rgba(183, 28, 28, 0.8);
        }
        .icon {
          width: 16px;
          height: 16px;
          flex-shrink: 0;
        }
        .message {
          font-weight: 500;
          margin: 0 4px;
        }
        .button-group {
          display: flex;
          gap: 4px;
          margin-left: 8px;
        }
        button {
          padding: 3px 8px;
          border: 1px solid rgba(255, 255, 255, 0.3);
          border-radius: 4px;
          background: rgba(255, 255, 255, 0.15);
          color: #fff;
          font-size: 11px;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.2s;
          white-space: nowrap;
        }
        button:hover {
          background: rgba(255, 255, 255, 0.25);
          border-color: rgba(255, 255, 255, 0.5);
        }
        button:active {
          transform: scale(0.95);
        }
        button.block-btn {
          background: rgba(198, 40, 40, 0.8);
        }
        button.block-btn:hover {
          background: rgba(198, 40, 40, 1);
        }
        button.unblock-btn {
          background: rgba(76, 175, 80, 0.8);
        }
        button.unblock-btn:hover {
          background: rgba(76, 175, 80, 1);
        }
        .blocked-cover {
          position: absolute;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          background: rgba(198, 40, 40, 0.15);
          border: 2px solid rgba(198, 40, 40, 0.5);
          border-radius: 4px;
          pointer-events: auto;
          cursor: not-allowed;
          z-index: 999998;
        }
      `;
      shadow.appendChild(style);

      // Create overlay content
      const container = global.document.createElement('div');
      container.className = 'overlay-container';

      const icon = global.document.createElement('span');
      icon.className = 'icon';
      icon.innerHTML = '⚠️';

      const message = global.document.createElement('span');
      message.className = 'message';
      const reason = this.getReasonText(analysisData);
      message.textContent = reason;

      const buttonGroup = global.document.createElement('div');
      buttonGroup.className = 'button-group';

      const blockBtn = global.document.createElement('button');
      blockBtn.className = 'block-btn';
      blockBtn.textContent = 'Block';
      blockBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        this.toggleBlock(element, analysisData);
      });

      const readLlmBtn = global.document.createElement('button');
      readLlmBtn.textContent = '+ Read LLM';
      readLlmBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        this.addToReadLLM(element, analysisData);
      });

      const dismissBtn = global.document.createElement('button');
      dismissBtn.textContent = '✕';
      dismissBtn.title = 'Dismiss warning';
      dismissBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        this.removeOverlay(element);
      });

      buttonGroup.appendChild(blockBtn);
      buttonGroup.appendChild(readLlmBtn);
      buttonGroup.appendChild(dismissBtn);

      container.appendChild(icon);
      container.appendChild(message);
      container.appendChild(buttonGroup);
      shadow.appendChild(container);

      // Store references
      const overlayData = {
        host: shadowHost,
        shadow,
        container,
        blockBtn,
        analysisData
      };
      this.overlays.set(element, overlayData);

      // Position and insert overlay
      this.positionOverlay(element, shadowHost);
      element.parentElement?.insertBefore(shadowHost, element);

      return overlayData;
    }

    getReasonText(analysisData) {
      const { aiScore, llmScore, urgencyScore, manipulationTechniques } = analysisData;
      
      if (manipulationTechniques > 0) {
        return 'Manipulation detected';
      }
      if (urgencyScore >= 0.7) {
        return 'High urgency tactics';
      }
      if (aiScore >= 0.7) {
        return 'AI-generated content';
      }
      if (llmScore >= 0.6) {
        return 'Phishing pattern';
      }
      return 'Suspicious content';
    }

    positionOverlay(element, overlayHost) {
      const rect = element.getBoundingClientRect();
      const scrollX = global.pageXOffset || global.document.documentElement.scrollLeft;
      const scrollY = global.pageYOffset || global.document.documentElement.scrollTop;

      // Position above the element
      overlayHost.style.left = `${rect.left + scrollX}px`;
      overlayHost.style.top = `${rect.top + scrollY - 35}px`;
    }

    /**
     * Toggle block state for an element
     */
    toggleBlock(element, analysisData) {
      if (this.blockedElements.has(element)) {
        this.unblockElement(element);
      } else {
        this.blockElement(element, analysisData);
      }
    }

    /**
     * Block an element - prevent all interactions
     */
    blockElement(element, analysisData) {
      if (this.blockedElements.has(element)) {
        return; // Already blocked
      }

      // Mark as blocked
      element.setAttribute('data-antillm-blocked', 'true');
      this.blockedElements.set(element, analysisData);

      // Create blocked cover
      const cover = global.document.createElement('div');
      cover.className = 'antillm-blocked-cover';
      cover.style.cssText = `
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(198, 40, 40, 0.15);
        border: 2px solid rgba(198, 40, 40, 0.5);
        border-radius: 4px;
        pointer-events: auto;
        cursor: not-allowed;
        z-index: 999998;
      `;

      // Position cover
      if (global.getComputedStyle(element).position === 'static') {
        element.style.position = 'relative';
      }
      element.appendChild(cover);

      // Block all interactive elements inside
      const interactiveElements = element.querySelectorAll('a, button, input, textarea, select, [onclick]');
      const handlers = [];

      const blockHandler = (e) => {
        e.preventDefault();
        e.stopPropagation();
        e.stopImmediatePropagation();
        
        // Show visual feedback
        if (this.notifier) {
          this.notifier.warn('This element is blocked. Unblock to interact.');
        }
        return false;
      };

      // Save original hrefs and onclick handlers
      interactiveElements.forEach((el) => {
        if (el.tagName === 'A' && el.href) {
          el.setAttribute('data-original-href', el.href);
          el.removeAttribute('href');
        }
        if (el.onclick) {
          el.setAttribute('data-original-onclick', el.onclick.toString());
          el.onclick = null;
        }

        // Add blocking event listeners
        const events = ['click', 'auxclick', 'mousedown', 'keydown', 'touchstart'];
        events.forEach(eventType => {
          el.addEventListener(eventType, blockHandler, { capture: true });
          handlers.push({ el, eventType, handler: blockHandler });
        });
      });

      // Also block the element itself
      const events = ['click', 'auxclick', 'mousedown', 'keydown', 'touchstart'];
      events.forEach(eventType => {
        element.addEventListener(eventType, blockHandler, { capture: true });
        handlers.push({ el: element, eventType, handler: blockHandler });
      });

      this.blockHandlers.set(element, { handlers, cover });

      // Update overlay UI
      const overlayData = this.overlays.get(element);
      if (overlayData) {
        overlayData.container.classList.add('blocked');
        overlayData.blockBtn.textContent = 'Unblock';
        overlayData.blockBtn.className = 'unblock-btn';
      }

      // Notify background to persist
      chrome.runtime.sendMessage({
        type: 'BLOCK_ITEM',
        item: this.createBlockPayload(element, analysisData)
      });

      if (this.notifier) {
        this.notifier.info('Element blocked. Click "Unblock" to restore.');
      }
    }

    /**
     * Unblock an element - restore interactions
     */
    unblockElement(element) {
      if (!this.blockedElements.has(element)) {
        return; // Not blocked
      }

      element.removeAttribute('data-antillm-blocked');
      this.blockedElements.delete(element);

      // Remove cover
      const handlerData = this.blockHandlers.get(element);
      if (handlerData) {
        if (handlerData.cover && handlerData.cover.parentNode) {
          handlerData.cover.remove();
        }

        // Remove all event handlers
        handlerData.handlers.forEach(({ el, eventType, handler }) => {
          el.removeEventListener(eventType, handler, { capture: true });
        });

        this.blockHandlers.delete(element);
      }

      // Restore original hrefs and onclick
      const interactiveElements = element.querySelectorAll('[data-original-href], [data-original-onclick]');
      interactiveElements.forEach((el) => {
        const originalHref = el.getAttribute('data-original-href');
        if (originalHref) {
          el.href = originalHref;
          el.removeAttribute('data-original-href');
        }

        const originalOnclick = el.getAttribute('data-original-onclick');
        if (originalOnclick) {
          try {
            el.onclick = new Function(originalOnclick);
          } catch (e) {
            console.warn('[BlockerUI] Could not restore onclick:', e);
          }
          el.removeAttribute('data-original-onclick');
        }
      });

      // Update overlay UI
      const overlayData = this.overlays.get(element);
      if (overlayData) {
        overlayData.container.classList.remove('blocked');
        overlayData.blockBtn.textContent = 'Block';
        overlayData.blockBtn.className = 'block-btn';
      }

      // Notify background to remove from persistence
      chrome.runtime.sendMessage({
        type: 'UNBLOCK_ITEM',
        itemId: this.generateElementId(element)
      });

      if (this.notifier) {
        this.notifier.info('Element unblocked.');
      }
    }

    /**
     * Add element to Read LLM queue
     */
    addToReadLLM(element, analysisData) {
      const payload = this.createBlockPayload(element, analysisData);
      
      chrome.runtime.sendMessage({
        type: 'ADD_TO_READ_LLM',
        item: payload
      }, (response) => {
        if (response && response.success) {
          if (this.notifier) {
            this.notifier.info('Added to Read LLM queue');
          }
        } else {
          if (this.notifier) {
            this.notifier.warn('Failed to add to queue');
          }
        }
      });
    }

    /**
     * Remove overlay from element
     */
    removeOverlay(element) {
      const overlayData = this.overlays.get(element);
      if (overlayData && overlayData.host && overlayData.host.parentNode) {
        overlayData.host.remove();
      }
      this.overlays.delete(element);
    }

    /**
     * Create block payload for storage
     */
    createBlockPayload(element, analysisData) {
      const excerpt = element.textContent?.trim().slice(0, 300) || '';
      const selector = this.generateSelector(element);
      
      return {
        id: this.generateElementId(element),
        url: global.location.href,
        domain: global.location.hostname,
        excerpt,
        selector,
        outerHTML: element.outerHTML.slice(0, 500), // Truncate for storage
        aiScore: analysisData.aiScore || 0,
        llmScore: analysisData.llmScore || 0,
        urgencyScore: analysisData.urgencyScore || 0,
        manipulationTechniques: analysisData.manipulationTechniques || 0,
        reason: this.getReasonText(analysisData),
        timestamp: Date.now()
      };
    }

    /**
     * Generate unique ID for element
     */
    generateElementId(element) {
      const text = element.textContent?.trim().slice(0, 100) || '';
      const url = global.location.href;
      return this.simpleHash(`${url}:${text}`);
    }

    /**
     * Simple hash function
     */
    simpleHash(str) {
      let hash = 0;
      for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash; // Convert to 32bit integer
      }
      return Math.abs(hash).toString(36);
    }

    /**
     * Generate CSS selector for element
     */
    generateSelector(element) {
      if (element.id) {
        return `#${element.id}`;
      }
      
      const path = [];
      let current = element;
      
      while (current && current.nodeType === Node.ELEMENT_NODE && path.length < 5) {
        let selector = current.nodeName.toLowerCase();
        
        if (current.className && typeof current.className === 'string') {
          const classes = current.className.trim().split(/\s+/).slice(0, 2);
          if (classes.length > 0 && classes[0]) {
            selector += '.' + classes.join('.');
          }
        }
        
        path.unshift(selector);
        current = current.parentElement;
      }
      
      return path.join(' > ');
    }

    /**
     * Restore blocks from storage on page load
     */
    restoreBlocks(blockedItems) {
      if (!blockedItems || blockedItems.length === 0) {
        return;
      }

      blockedItems.forEach(item => {
        if (item.domain !== global.location.hostname) {
          return; // Skip items from other domains
        }

        // Try to find element by selector first
        let element = null;
        if (item.selector) {
          try {
            element = global.document.querySelector(item.selector);
          } catch (e) {
            console.warn('[BlockerUI] Invalid selector:', item.selector);
          }
        }

        // Fallback: try to match by excerpt
        if (!element && item.excerpt) {
          const allElements = global.document.querySelectorAll('p, div, li, span, article, a, section');
          for (const el of allElements) {
            if (el.textContent?.includes(item.excerpt.slice(0, 50))) {
              element = el;
              break;
            }
          }
        }

        if (element) {
          const analysisData = {
            aiScore: item.aiScore,
            llmScore: item.llmScore,
            urgencyScore: item.urgencyScore,
            manipulationTechniques: item.manipulationTechniques
          };
          
          this.createOverlay(element, analysisData);
          this.blockElement(element, analysisData);
        }
      });
    }
  }

  global.BlockerUI = BlockerUI;
})(window);
