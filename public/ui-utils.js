// ═══════════════════════════════════════════════════════════════════════════════
// QuantumGuard — Global UI Utilities (Kinetic Shield v2.0)
// ═══════════════════════════════════════════════════════════════════════════════
// Shared interactive behaviors loaded across all pages:
//   - Toast notifications
//   - Mobile menu drawer
//   - Scroll-to-top button
//   - Intersection observer animations
//   - Animated number counters
// ═══════════════════════════════════════════════════════════════════════════════

const QGUtils = {};

// ═══════════════════════════════════════════════════
// TOAST NOTIFICATION SYSTEM
// ═══════════════════════════════════════════════════
QGUtils.toast = (function() {
  let container = null;

  function ensureContainer() {
    container = document.getElementById('toastContainer');
    if (!container) {
      container = document.createElement('div');
      container.id = 'toastContainer';
      container.className = 'toast-container';
      document.body.appendChild(container);
    }
    return container;
  }

  /**
   * Show a toast notification.
   * @param {string} message - The message to display
   * @param {string} type - 'success' | 'error' | 'warning' | 'info'
   * @param {number} duration - Auto-dismiss in milliseconds (default: 4000)
   */
  function show(message, type, duration) {
    type = type || 'info';
    duration = duration || 4000;
    const c = ensureContainer();

    const icons = {
      success: 'check_circle',
      error:   'error',
      warning: 'warning',
      info:    'info'
    };

    const toast = document.createElement('div');
    toast.className = 'toast toast-' + type;
    toast.innerHTML =
      '<span class="material-symbols-outlined" style="font-size:18px">' + (icons[type] || 'info') + '</span>' +
      '<span>' + message + '</span>';

    c.appendChild(toast);

    // Auto-dismiss
    setTimeout(function() {
      toast.classList.add('toast-exit');
      setTimeout(function() { toast.remove(); }, 300);
    }, duration);

    return toast;
  }

  return {
    show: show,
    success: function(msg, dur) { return show(msg, 'success', dur); },
    error:   function(msg, dur) { return show(msg, 'error', dur); },
    warning: function(msg, dur) { return show(msg, 'warning', dur); },
    info:    function(msg, dur) { return show(msg, 'info', dur); }
  };
})();


// ═══════════════════════════════════════════════════
// MOBILE MENU SYSTEM
// ═══════════════════════════════════════════════════
QGUtils.mobileMenu = (function() {
  function init() {
    // Check if mobile menu elements already exist (e.g., on index.html)
    if (document.getElementById('mobileOverlay')) return;

    // Auto-detect current page for active state
    const currentPage = window.location.pathname.split('/').pop() || 'index.html';

    const links = [
      { href: 'index.html',          icon: 'home',        label: 'Home' },
      { href: 'quick-assessment.html',icon: 'quiz',        label: 'Assessment' },
      { href: 'results.html',        icon: 'assessment',  label: 'Results' },
      { href: 'compliance.html',     icon: 'verified',    label: 'Compliance' },
      { href: 'tools.html',          icon: 'build',       label: 'Tools' },
      { href: 'leaderboard.html',    icon: 'leaderboard', label: 'Leaderboard' },
      { href: 'docs.html',           icon: 'description', label: 'Docs' },
      { href: 'about.html',          icon: 'info',        label: 'About' },
    ];

    // Create overlay
    const overlay = document.createElement('div');
    overlay.id = 'mobileOverlay';
    overlay.className = 'mobile-menu-overlay';

    // Create drawer
    const drawer = document.createElement('div');
    drawer.id = 'mobileDrawer';
    drawer.className = 'mobile-menu-drawer';

    const header = document.createElement('div');
    header.className = 'flex justify-between items-center mb-8';
    header.innerHTML =
      '<span class="text-lg font-bold gradient-text">QuantumGuard</span>' +
      '<button id="mobileCloseBtn" class="p-2 hover:bg-[#27354C]/50 rounded-lg"><span class="material-symbols-outlined">close</span></button>';
    drawer.appendChild(header);

    links.forEach(function(link) {
      var a = document.createElement('a');
      a.href = link.href;
      if (currentPage === link.href) a.className = 'active';
      a.innerHTML = '<span class="material-symbols-outlined">' + link.icon + '</span> ' + link.label;
      drawer.appendChild(a);
    });

    document.body.appendChild(overlay);
    document.body.appendChild(drawer);

    // Add hamburger button to nav if missing
    var nav = document.querySelector('nav');
    if (nav) {
      var existing = document.getElementById('mobileMenuBtn');
      if (!existing) {
        var btnContainer = nav.querySelector('.flex.items-center.gap-4') || nav.querySelector('.flex.items-center');
        if (btnContainer) {
          var btn = document.createElement('button');
          btn.id = 'mobileMenuBtn';
          btn.className = 'md:hidden p-2 hover:bg-[#27354C]/50 rounded-lg transition-all';
          btn.setAttribute('aria-label', 'Open menu');
          btn.innerHTML = '<span class="material-symbols-outlined text-[#D6E3FF]">menu</span>';
          btnContainer.appendChild(btn);
        }
      }
    }

    // Event handlers
    function openMenu() { overlay.classList.add('active'); drawer.classList.add('active'); }
    function closeMenu() { overlay.classList.remove('active'); drawer.classList.remove('active'); }

    document.addEventListener('click', function(e) {
      if (e.target.closest('#mobileMenuBtn')) openMenu();
      if (e.target.closest('#mobileCloseBtn') || e.target === overlay) closeMenu();
    });

    // Close on Escape
    document.addEventListener('keydown', function(e) {
      if (e.key === 'Escape') closeMenu();
    });
  }

  return { init: init };
})();


// ═══════════════════════════════════════════════════
// SCROLL-TO-TOP BUTTON
// ═══════════════════════════════════════════════════
QGUtils.scrollTop = (function() {
  function init() {
    if (document.getElementById('scrollTopBtn')) return;

    var btn = document.createElement('button');
    btn.id = 'scrollTopBtn';
    btn.className = 'scroll-top-btn';
    btn.setAttribute('aria-label', 'Scroll to top');
    btn.innerHTML = '<span class="material-symbols-outlined">arrow_upward</span>';
    document.body.appendChild(btn);

    window.addEventListener('scroll', function() {
      btn.classList.toggle('visible', window.scrollY > 400);
    }, { passive: true });

    btn.addEventListener('click', function() {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });
  }

  return { init: init };
})();


// ═══════════════════════════════════════════════════
// INTERSECTION OBSERVER ANIMATIONS
// ═══════════════════════════════════════════════════
QGUtils.scrollAnimate = (function() {
  function init() {
    var observer = new IntersectionObserver(function(entries) {
      entries.forEach(function(entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add('is-visible');
        }
      });
    }, { threshold: 0.1 });

    document.querySelectorAll('.observe-animate').forEach(function(el) {
      observer.observe(el);
    });
  }

  return { init: init };
})();


// ═══════════════════════════════════════════════════
// ANIMATED NUMBER COUNTERS
// ═══════════════════════════════════════════════════
QGUtils.counterAnimation = (function() {
  function init() {
    var counters = document.querySelectorAll('[data-count]');
    if (counters.length === 0) return;

    var observer = new IntersectionObserver(function(entries) {
      entries.forEach(function(entry) {
        if (entry.isIntersecting && !entry.target.dataset.counted) {
          entry.target.dataset.counted = 'true';
          var target = parseInt(entry.target.dataset.count);
          var current = 0;
          var step = Math.max(1, Math.floor(target / 40));
          var timer = setInterval(function() {
            current += step;
            if (current >= target) { current = target; clearInterval(timer); }
            entry.target.textContent = current;
          }, 30);
        }
      });
    }, { threshold: 0.5 });

    counters.forEach(function(c) { observer.observe(c); });
  }

  return { init: init };
})();


// ═══════════════════════════════════════════════════
// AUTO-SAVE INDICATOR
// ═══════════════════════════════════════════════════
QGUtils.autosave = (function() {
  var indicator = null;

  function show(parentEl) {
    if (indicator) indicator.remove();
    indicator = document.createElement('div');
    indicator.className = 'autosave-indicator';
    indicator.innerHTML = '<span class="autosave-dot"></span> Auto-saved';
    if (parentEl) { parentEl.appendChild(indicator); }
    else { document.body.appendChild(indicator); }

    setTimeout(function() {
      if (indicator) { indicator.style.opacity = '0'; setTimeout(function() { indicator.remove(); indicator = null; }, 300); }
    }, 2500);
  }

  return { show: show };
})();


// ═══════════════════════════════════════════════════
// PDF EXPORT (via browser print)
// ═══════════════════════════════════════════════════
QGUtils.exportPDF = function(title) {
  var originalTitle = document.title;
  document.title = title || 'QuantumGuard Assessment Report';
  window.print();
  document.title = originalTitle;
};

// ═══════════════════════════════════════════════════
// JSON EXPORT
// ═══════════════════════════════════════════════════
QGUtils.exportJSON = function(data, filename) {
  var blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url;
  a.download = filename || 'quantumguard-report.json';
  a.click();
  URL.revokeObjectURL(url);
  QGUtils.toast.success('Report exported as JSON');
};


// ═══════════════════════════════════════════════════
// RADAR CHART (SVG-based, no dependencies)
// ═══════════════════════════════════════════════════
QGUtils.radarChart = (function() {
  /**
   * Render a radar/spider chart into a container element.
   * @param {HTMLElement} container - DOM element to render into
   * @param {Object} data - { labels: string[], values: number[], maxValue: number }
   * @param {Object} opts - { size, color, bgColor, showLabels, benchmark }
   */
  function render(container, data, opts) {
    opts = opts || {};
    var size = opts.size || 280;
    var cx = size / 2;
    var cy = size / 2;
    var maxR = size / 2 - 40;
    var color = opts.color || '#00D4FF';
    var bgColor = opts.bgColor || 'rgba(0,212,255,0.08)';
    var maxVal = data.maxValue || 4;
    var n = data.labels.length;
    var angleStep = (2 * Math.PI) / n;

    var svg = '<svg viewBox="0 0 ' + size + ' ' + size + '" xmlns="http://www.w3.org/2000/svg" class="w-full h-full">';

    // Grid rings (4 levels)
    for (var ring = 1; ring <= 4; ring++) {
      var r = (ring / 4) * maxR;
      var pts = [];
      for (var i = 0; i < n; i++) {
        var angle = (i * angleStep) - Math.PI / 2;
        pts.push((cx + r * Math.cos(angle)).toFixed(1) + ',' + (cy + r * Math.sin(angle)).toFixed(1));
      }
      svg += '<polygon points="' + pts.join(' ') + '" fill="none" stroke="rgba(133,147,152,0.15)" stroke-width="1"/>';
    }

    // Axes
    for (var i = 0; i < n; i++) {
      var angle = (i * angleStep) - Math.PI / 2;
      var ex = cx + maxR * Math.cos(angle);
      var ey = cy + maxR * Math.sin(angle);
      svg += '<line x1="' + cx + '" y1="' + cy + '" x2="' + ex.toFixed(1) + '" y2="' + ey.toFixed(1) + '" stroke="rgba(133,147,152,0.1)" stroke-width="1"/>';
    }

    // Benchmark overlay (if provided)
    if (opts.benchmark && opts.benchmark.length === n) {
      var bPts = [];
      for (var i = 0; i < n; i++) {
        var angle = (i * angleStep) - Math.PI / 2;
        var val = Math.min(opts.benchmark[i], maxVal);
        var r = (val / maxVal) * maxR;
        bPts.push((cx + r * Math.cos(angle)).toFixed(1) + ',' + (cy + r * Math.sin(angle)).toFixed(1));
      }
      svg += '<polygon points="' + bPts.join(' ') + '" fill="rgba(210,187,255,0.08)" stroke="rgba(210,187,255,0.4)" stroke-width="1.5" stroke-dasharray="4 3"/>';
    }

    // Data polygon
    var dPts = [];
    for (var i = 0; i < n; i++) {
      var angle = (i * angleStep) - Math.PI / 2;
      var val = Math.min(data.values[i], maxVal);
      var r = (val / maxVal) * maxR;
      dPts.push((cx + r * Math.cos(angle)).toFixed(1) + ',' + (cy + r * Math.sin(angle)).toFixed(1));
    }
    svg += '<polygon points="' + dPts.join(' ') + '" fill="' + bgColor + '" stroke="' + color + '" stroke-width="2"/>';

    // Data points
    for (var i = 0; i < n; i++) {
      var angle = (i * angleStep) - Math.PI / 2;
      var val = Math.min(data.values[i], maxVal);
      var r = (val / maxVal) * maxR;
      var px = cx + r * Math.cos(angle);
      var py = cy + r * Math.sin(angle);
      svg += '<circle cx="' + px.toFixed(1) + '" cy="' + py.toFixed(1) + '" r="4" fill="' + color + '" stroke="#041329" stroke-width="2"/>';
    }

    // Labels
    if (opts.showLabels !== false) {
      for (var i = 0; i < n; i++) {
        var angle = (i * angleStep) - Math.PI / 2;
        var lr = maxR + 24;
        var lx = cx + lr * Math.cos(angle);
        var ly = cy + lr * Math.sin(angle);
        var anchor = Math.abs(Math.cos(angle)) < 0.01 ? 'middle' : (Math.cos(angle) > 0 ? 'start' : 'end');
        svg += '<text x="' + lx.toFixed(1) + '" y="' + (ly + 4).toFixed(1) + '" text-anchor="' + anchor + '" fill="#bbc9cf" font-size="10" font-family="Space Grotesk, sans-serif" font-weight="600">' + data.labels[i] + '</text>';
        // Score value
        var sv = data.values[i];
        svg += '<text x="' + lx.toFixed(1) + '" y="' + (ly + 16).toFixed(1) + '" text-anchor="' + anchor + '" fill="' + color + '" font-size="11" font-family="JetBrains Mono, monospace" font-weight="700">' + sv.toFixed(1) + '</text>';
      }
    }

    svg += '</svg>';
    container.innerHTML = svg;
  }

  return { render: render };
})();


// ═══════════════════════════════════════════════════
// SCORE UTILITIES — Boundary enforcement
// ═══════════════════════════════════════════════════

/**
 * Clamp a score to [0, 100] range. Handles NaN, undefined, negative values.
 * @param {number} score — raw score value
 * @returns {number} score clamped to [0, 100]
 */
QGUtils.clampScore = function(score) {
  if (score == null || isNaN(score)) return 0;
  return Math.max(0, Math.min(100, Math.round(Number(score))));
};

/**
 * Format a score for display. Handles decimals, ensures [0, 100] bounds.
 * @param {number} score — raw score value
 * @param {number} decimals — decimal places (default: 0)
 * @returns {string} formatted score string
 */
QGUtils.formatScore = function(score, decimals) {
  decimals = decimals || 0;
  const clamped = QGUtils.clampScore(score);
  return clamped.toFixed(decimals);
};

/**
 * Explanatory text constants for UI tooltips and descriptions.
 */
QGUtils.EXPLANATIONS = {
  assetCriticalityMultiplier:
    'The Asset Criticality Multiplier adjusts vulnerability scores based on the strategic importance of the scanned asset. ' +
    'Higher-criticality assets (e.g., payment systems, authentication infrastructure) receive amplified risk scores ' +
    'to reflect greater potential business impact of quantum-vulnerable cryptography.',
  pqcVulnerabilityTypes: {
    shor: "Shor's Algorithm Threat: Provides exponential speedup for breaking RSA, ECDSA, ECDH, and DH. " +
          'These algorithms will be completely broken by a sufficiently large quantum computer.',
    grover: "Grover's Algorithm Threat: Provides quadratic speedup against symmetric ciphers. " +
            'AES-128 effective security drops to 64 bits; AES-256 drops to 128 bits (still safe).',
    harvest: 'Harvest Now, Decrypt Later (HNDL): Adversaries record encrypted traffic today, ' +
             'planning to decrypt it once quantum computers become available.'
  }
};


// ═══════════════════════════════════════════════════
// BOOTSTRAP — Auto-initialize on DOM ready
// ═══════════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', function() {
  QGUtils.mobileMenu.init();
  QGUtils.scrollTop.init();
  QGUtils.scrollAnimate.init();
  QGUtils.counterAnimation.init();
});

// Make globally available
if (typeof window !== 'undefined') window.QGUtils = QGUtils;

