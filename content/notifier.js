(function attachNotifier(global) {
  if (global.ThreatNotifier) {
    return;
  }

  class ThreatNotifier {
    constructor() {
      this.recentMessages = new Map(); // Track recent messages to prevent duplicates
      this.messageDebounceTime = 5000; // 5 seconds cooldown per unique message
      this.maxActiveToasts = 2; // Maximum simultaneous notifications
    }

    ensureContainer() {
      if (this.root) {
        return;
      }
      const host = global.document.createElement("div");
      host.id = "antillm-root";
      host.style.position = "fixed";
      host.style.top = "16px";
      host.style.right = "16px";
      host.style.zIndex = "2147483647";
      host.style.pointerEvents = "none";
      global.document.documentElement.appendChild(host);
      this.root = host.attachShadow({ mode: "open" });
      const style = global.document.createElement("style");
      style.textContent = `
        .toast {
          min-width: 240px;
          max-width: 360px;
          margin-bottom: 8px;
          padding: 12px 16px;
          border-radius: 6px;
          background: rgba(33, 150, 243, 0.95);
          color: #fff;
          font-family: system-ui, sans-serif;
          font-size: 13px;
          line-height: 1.4;
          box-shadow: 0 8px 20px rgba(0, 0, 0, 0.25);
          pointer-events: auto;
          display: flex;
          gap: 8px;
          align-items: center;
          animation: slideIn 0.3s ease-out;
        }
        @keyframes slideIn {
          from {
            transform: translateX(400px);
            opacity: 0;
          }
          to {
            transform: translateX(0);
            opacity: 1;
          }
        }
        .toast.warn {
          background: rgba(198, 40, 40, 0.95);
        }
        .toast::before {
          content: "";
          width: 8px;
          height: 8px;
          border-radius: 50%;
          background: rgba(255, 255, 255, 0.85);
          flex-shrink: 0;
          margin-top: 2px;
        }
        button.dismiss {
          margin-left: auto;
          background: transparent;
          border: none;
          color: #fff;
          font-size: 18px;
          cursor: pointer;
          opacity: 0.8;
          flex-shrink: 0;
          padding: 0 4px;
        }
        button.dismiss:hover {
          opacity: 1;
        }
      `;
      this.root.appendChild(style);
      this.container = global.document.createElement("div");
      this.root.appendChild(this.container);
    }

    isDuplicate(message) {
      // Check if we've shown this exact message recently
      const messageKey = message.toLowerCase().trim();
      const now = Date.now();
      
      if (this.recentMessages.has(messageKey)) {
        const lastShown = this.recentMessages.get(messageKey);
        if (now - lastShown < this.messageDebounceTime) {
          return true; // Duplicate within cooldown period
        }
      }
      
      return false;
    }

    cleanupOldMessages() {
      // Remove expired message timestamps
      const now = Date.now();
      for (const [key, timestamp] of this.recentMessages.entries()) {
        if (now - timestamp > this.messageDebounceTime) {
          this.recentMessages.delete(key);
        }
      }
    }

    getActiveToastCount() {
      this.ensureContainer();
      return this.container.querySelectorAll('.toast').length;
    }

    show(message, intent = "info", timeout = 6000) {
      if (!message) {
        return;
      }

      // Prevent duplicate notifications
      if (this.isDuplicate(message)) {
        return;
      }

      // Limit active notifications
      if (this.getActiveToastCount() >= this.maxActiveToasts) {
        return;
      }

      this.ensureContainer();
      
      // Record this message
      const messageKey = message.toLowerCase().trim();
      this.recentMessages.set(messageKey, Date.now());
      this.cleanupOldMessages();

      const toast = global.document.createElement("div");
      toast.className = `toast ${intent === "warn" ? "warn" : ""}`;
      toast.textContent = message;
      
      const dismiss = global.document.createElement("button");
      dismiss.className = "dismiss";
      dismiss.textContent = "×";
      dismiss.addEventListener("click", () => {
        toast.remove();
      });
      
      toast.appendChild(dismiss);
      this.container.appendChild(toast);
      
      if (timeout) {
        setTimeout(() => {
          if (toast.parentNode) {
            toast.remove();
          }
        }, timeout);
      }
    }

    warn(message) {
      this.show(message, "warn", 8000);
    }

    info(message) {
      this.show(message, "info", 5000);
    }
  }

  global.ThreatNotifier = ThreatNotifier;
})(window);
