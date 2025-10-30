(function attachFormMonitor(global) {
  if (global.FormBehaviorMonitor) {
    return;
  }

  class FormBehaviorMonitor {
    constructor(notifier, domainReputation) {
      this.notifier = notifier;
      this.domainReputation = domainReputation;
      this.installed = false;
    }

    interceptFormSubmissions() {
      if (this.installed) {
        return;
      }
      this.installed = true;
      const originalSubmit = HTMLFormElement.prototype.submit;
      if (!HTMLFormElement.prototype.vigilSubmit) {
        HTMLFormElement.prototype.vigilSubmit = originalSubmit;
        HTMLFormElement.prototype.submit = function patchedSubmit() {
          FormBehaviorMonitor.analyzeSubmission(this);
          return HTMLFormElement.prototype.vigilSubmit.apply(this, arguments);
        };
      }
      global.document.addEventListener("submit", (event) => {
        FormBehaviorMonitor.analyzeSubmission(event.target);
      }, true);
    }

    static analyzeSubmission(form) {
      if (!form || !(form instanceof HTMLFormElement)) {
        return;
      }
      const monitor = FormBehaviorMonitor.instance;
      if (!monitor) {
        return;
      }
      monitor.inspectForm(form);
    }

    async inspectForm(form) {
      try {
        const action = form.getAttribute("action") || "";
        if (!action) {
          this.notifier?.warn("Form submission missing explicit action. Confirm the destination before proceeding.");
          return;
        }
        const actionDomain = new URL(action, global.window.location.href).hostname;
        const currentDomain = global.window.location.hostname;
        if (actionDomain !== currentDomain) {
          this.flagCrossDomainSubmission(form, actionDomain);
          const reputation = await this.domainReputation.checkDomain(actionDomain);
          if (reputation?.riskScore >= 60) {
            this.notifier?.warn(`High-risk form destination detected: ${actionDomain}`);
          }
        }
        if (action.startsWith("http://")) {
          this.notifier?.warn("Form is submitting over insecure HTTP.");
        }
      } catch (error) {
        this.notifier?.warn("Unable to verify form destination.");
      }
    }

    flagCrossDomainSubmission(form, actionDomain) {
      form.setAttribute("data-vigil-cross-domain", actionDomain);
      this.notifier?.warn(`Form submits to ${actionDomain}. Confirm legitimacy before continuing.`);
    }
  }

  FormBehaviorMonitor.instance = null;

  FormBehaviorMonitor.registerInstance = function registerInstance(instance) {
    FormBehaviorMonitor.instance = instance;
  };

  global.FormBehaviorMonitor = FormBehaviorMonitor;
})(window);
