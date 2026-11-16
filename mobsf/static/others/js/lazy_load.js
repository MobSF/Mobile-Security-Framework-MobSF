// Deferred loading and layout helpers for large report pages.
(function () {
  var loaded = Object.create(null);

  // Load scripts in order; each URL is fetched at most once per page.
  window.mobsfLoadScripts = function (urls) {
    return urls.reduce(function (prev, url) {
      return prev.then(function () {
        if (!loaded[url]) {
          loaded[url] = new Promise(function (resolve, reject) {
            var script = document.createElement('script');
            script.src = url;
            script.onload = resolve;
            script.onerror = function () {
              delete loaded[url];
              reject(new Error('Failed to load ' + url));
            };
            document.head.appendChild(script);
          });
        }
        return loaded[url];
      });
    }, Promise.resolve());
  };

  // Run callback once, when the element first approaches the viewport.
  window.mobsfWhenVisible = function (element, callback, rootMargin) {
    if (!element) {
      return;
    }
    if (!('IntersectionObserver' in window)) {
      callback(element);
      return;
    }
    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          observer.unobserve(entry.target);
          callback(entry.target);
        }
      });
    }, { rootMargin: rootMargin || '300px 0px' });
    observer.observe(element);
  };

  // Row count as rendered by the server, before DataTables pages rows out.
  function rowCount(table) {
    if (!table.dataset.rows) {
      var body = table.tBodies[0];
      table.dataset.rows = body ? body.rows.length : 0;
    }
    return Number(table.dataset.rows);
  }
  window.mobsfRowCount = rowCount;

  function isReportTable(table) {
    return !table.parentElement.closest('table') && !table.closest('.modal');
  }

  // Collapsed lists ship their rows inside <template> so they are not
  // rendered until the user expands them.
  function expandTemplate(container) {
    var template = container.querySelector(':scope > template');
    if (template) {
      container.appendChild(template.content.cloneNode(true));
      template.remove();
    }
  }
  window.mobsfExpandTemplate = expandTemplate;

  // Clamp long text to a few lines with a "Show more" toggle.
  function checkClamp(el) {
    if (el.dataset.clampChecked || !el.isConnected || !el.offsetParent) {
      return;
    }
    el.dataset.clampChecked = '1';
    if (el.scrollHeight <= el.clientHeight + 1) {
      return;
    }
    el.classList.add('clamped');
    var toggle = document.createElement('button');
    toggle.type = 'button';
    toggle.className = 'btn btn-link btn-sm clamp-toggle';
    toggle.textContent = 'Show more';
    toggle.addEventListener('click', function () {
      var expanded = el.classList.toggle('expanded');
      toggle.textContent = expanded ? 'Show less' : 'Show more';
    });
    el.insertAdjacentElement('afterend', toggle);
  }

  function setupClamp(el) {
    if (el.dataset.clampLines) {
      el.style.setProperty('--clamp-lines', el.dataset.clampLines);
    }
    window.mobsfWhenVisible(el, checkClamp);
  }

  var CLAMP_CHARS = 160;
  var CLAMP_SKIP = 'table, template, .collapse, details, pre, button, .btn';
  var CLAMP_TABLES = ['table_urls', 'table_emails'];

  // Wrap long URL and email cells so they can be clamped; overflow is
  // measured per page on the DataTables draw event.
  window.mobsfPrepareTable = function (table) {
    if (CLAMP_TABLES.indexOf(table.id) === -1 || rowCount(table) > 2000) {
      return;
    }
    Array.prototype.forEach.call(table.tBodies[0] ? table.tBodies[0].rows : [], function (row) {
      Array.prototype.forEach.call(row.cells, function (cell) {
        if (cell.textContent.trim().length < CLAMP_CHARS || cell.querySelector(CLAMP_SKIP)) {
          return;
        }
        var wrap = document.createElement('div');
        wrap.className = 'clamp';
        wrap.style.setProperty('--clamp-lines', '5');
        while (cell.firstChild) {
          wrap.appendChild(cell.firstChild);
        }
        cell.appendChild(wrap);
      });
    });
  };

  // Replace empty tables with a one-line note.
  function markEmpty(table) {
    table.dataset.empty = '1';
    table.hidden = true;
    var prev = table.previousSibling;
    while (prev && (prev.nodeType === Node.COMMENT_NODE
        || (prev.nodeType === Node.TEXT_NODE && !prev.textContent.trim()))) {
      prev = prev.previousSibling;
    }
    if (prev && (prev.nodeType === Node.TEXT_NODE || prev.matches('p, strong, div:not(.dataTables_wrapper)'))) {
      return;
    }
    var note = document.createElement('p');
    note.className = 'text-muted mb-0 empty-note';
    note.textContent = 'None found.';
    table.insertAdjacentElement('afterend', note);
  }

  function sectionFor(link) {
    var id = decodeURIComponent(link.getAttribute('href').slice(1));
    var anchor = id && document.getElementById(id);
    if (!anchor) {
      return null;
    }
    var next = anchor.nextElementSibling;
    return next && next.matches('section') ? next : null;
  }

  // Sidebar: row counts per section and highlight the section in view.
  function setupSidebar() {
    var links = document.querySelectorAll('.nav-sidebar a.nav-link[href^="#"]');
    var bySection = new Map();
    links.forEach(function (link) {
      var section = sectionFor(link);
      if (!section) {
        return;
      }
      bySection.set(section, link);
      var tables = Array.prototype.filter.call(section.querySelectorAll('table'), isReportTable);
      if (!tables.length) {
        return;
      }
      var total = tables.reduce(function (sum, t) { return sum + rowCount(t); }, 0);
      var label = link.querySelector('p') || link;
      var badge = document.createElement('span');
      badge.className = 'badge right nav-count';
      badge.textContent = String(total);
      label.appendChild(badge);
      if (total === 0) {
        link.classList.add('nav-empty');
        section.classList.add('section-empty');
      }
    });
    if (!('IntersectionObserver' in window) || !bySection.size) {
      return;
    }
    var inBand = new Set();
    var spy = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          inBand.add(entry.target);
        } else {
          inBand.delete(entry.target);
        }
      });
      var top = null;
      inBand.forEach(function (section) {
        if (!top || section.compareDocumentPosition(top) & Node.DOCUMENT_POSITION_FOLLOWING) {
          top = section;
        }
      });
      if (!top) {
        return;
      }
      var link = bySection.get(top);
      var tree = link.closest('.nav-treeview');
      var parent = tree && tree.parentElement.querySelector(':scope > .nav-link');
      document.querySelectorAll('.nav-sidebar .nav-link.active').forEach(function (l) {
        l.classList.remove('active');
      });
      link.classList.add('active');
      if (parent) {
        parent.classList.add('active');
      }
    }, { rootMargin: '-64px 0px -70% 0px' });
    bySection.forEach(function (link, section) { spy.observe(section); });
  }

  // Sections render (and tables initialize) only near the viewport, so
  // content above an in-page jump target can change height after the jump.
  // Hold the target in place briefly, until the user scrolls.
  function pinTarget(id) {
    var el = id && document.getElementById(id);
    if (!el) {
      return;
    }
    requestAnimationFrame(function () {
      var offset = el.getBoundingClientRect().top;
      var until = Date.now() + 1500;
      var cancelled = false;
      var cancel = function () { cancelled = true; };
      ['wheel', 'touchstart', 'keydown', 'mousedown'].forEach(function (name) {
        window.addEventListener(name, cancel, { once: true, passive: true });
      });
      (function hold() {
        if (cancelled || Date.now() > until) {
          return;
        }
        var drift = el.getBoundingClientRect().top - offset;
        if (Math.abs(drift) > 2) {
          window.scrollBy(0, drift);
        }
        requestAnimationFrame(hold);
      })();
    });
  }

  document.addEventListener('click', function (event) {
    var link = event.target.closest && event.target.closest('a[href^="#"]:not([data-toggle])');
    if (link && link.getAttribute('href').length > 1) {
      pinTarget(decodeURIComponent(link.getAttribute('href').slice(1)));
    }
  });

  window.addEventListener('load', function () {
    if (location.hash.length > 1) {
      pinTarget(decodeURIComponent(location.hash.slice(1)));
    }
  });

  document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('table').forEach(function (table) {
      if (!isReportTable(table)) {
        return;
      }
      if (rowCount(table) === 0) {
        markEmpty(table);
      }
    });
    document.querySelectorAll('.clamp').forEach(setupClamp);
    setupSidebar();
  });

  if (window.jQuery) {
    jQuery(document).on('show.bs.collapse', '.collapse', function (event) {
      if (event.target === this) {
        expandTemplate(this);
      }
    });
    // Rows drawn by DataTables (paging, search) get their clamps checked.
    jQuery(document).on('draw.dt', function (event) {
      event.target.querySelectorAll('.clamp:not([data-clamp-checked])').forEach(checkClamp);
    });
    // Binary check cells: reveal the explanation on click or Enter.
    jQuery(document).on('click keydown', '.check-cell[tabindex]', function (event) {
      if (event.type === 'keydown' && event.key !== 'Enter') {
        return;
      }
      this.classList.toggle('expanded');
    });
  }
})();
