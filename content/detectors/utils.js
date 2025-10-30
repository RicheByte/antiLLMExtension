(function attachUtils(global) {
  if (global.VigilUtils) {
    return;
  }

  function debounce(fn, delay) {
    let timer;
    return (...args) => {
      clearTimeout(timer);
      timer = setTimeout(() => fn(...args), delay);
    };
  }

  function trunc(text, limit) {
    if (!text || text.length <= limit) {
      return text;
    }
    return text.slice(0, limit);
  }

  function levenshteinDistance(a = "", b = "") {
    const matrix = Array.from({ length: a.length + 1 }, () => new Array(b.length + 1).fill(0));
    for (let i = 0; i <= a.length; i += 1) {
      matrix[i][0] = i;
    }
    for (let j = 0; j <= b.length; j += 1) {
      matrix[0][j] = j;
    }
    for (let i = 1; i <= a.length; i += 1) {
      for (let j = 1; j <= b.length; j += 1) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        matrix[i][j] = Math.min(
          matrix[i - 1][j] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j - 1] + cost
        );
      }
    }
    return matrix[a.length][b.length];
  }

  function computeAverageSentenceLength(text) {
    if (!text) {
      return 0;
    }
    const sentences = text.split(/[.!?]+/).filter(Boolean);
    if (!sentences.length) {
      return text.length;
    }
    const total = sentences.reduce((sum, sentence) => sum + sentence.trim().split(/\s+/).length, 0);
    return total / sentences.length;
  }

  function computeSentenceVariance(text) {
    const sentences = text.split(/[.!?]+/).map((s) => s.trim()).filter(Boolean);
    if (sentences.length < 2) {
      return 0;
    }
    const lengths = sentences.map((s) => s.split(/\s+/).length);
    const mean = lengths.reduce((sum, len) => sum + len, 0) / lengths.length;
    const variance = lengths.reduce((sum, len) => sum + (len - mean) ** 2, 0) / lengths.length;
    return Number(variance.toFixed(2));
  }

  function collectVisibleText(root) {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode(node) {
        if (!node.parentElement) {
          return NodeFilter.FILTER_REJECT;
        }
        const style = global.getComputedStyle(node.parentElement);
        if (style && (style.visibility === "hidden" || style.display === "none")) {
          return NodeFilter.FILTER_REJECT;
        }
        const value = node.nodeValue.trim();
        if (!value) {
          return NodeFilter.FILTER_REJECT;
        }
        return NodeFilter.FILTER_ACCEPT;
      }
    });
    const parts = [];
    let current;
    while ((current = walker.nextNode())) {
      parts.push(current.nodeValue.trim());
      if (parts.join(" ").length > 20000) {
        break;
      }
    }
    return parts.join(" ");
  }

  function normalizeScore(score, min, max) {
    if (max === min) {
      return 0;
    }
    return Math.min(Math.max((score - min) / (max - min), 0), 1);
  }

  global.VigilUtils = {
    debounce,
    trunc,
    levenshteinDistance,
    computeAverageSentenceLength,
    computeSentenceVariance,
    collectVisibleText,
    normalizeScore
  };
})(window);
