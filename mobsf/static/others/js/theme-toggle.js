/**
 * Dark/Light theme toggle.
 *
 * The actual theme is applied by a tiny inline script in <head> (before any
 * stylesheet loads, to avoid a flash of the wrong theme) that reads
 * localStorage and sets document.documentElement[data-theme]. This file only
 * wires up the toggle button's click handler and keeps its icon/label in
 * sync, once the DOM is ready.
 */
(function () {
  var STORAGE_KEY = 'mobsf-theme';

  function currentTheme() {
    return document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
  }

  function applyTheme(theme) {
    if (theme === 'light') {
      document.documentElement.setAttribute('data-theme', 'light');
    } else {
      document.documentElement.removeAttribute('data-theme');
    }
    try {
      localStorage.setItem(STORAGE_KEY, theme);
    } catch (e) { /* localStorage unavailable (private mode, etc.) - theme just won't persist */ }
    updateToggleButtons(theme);
  }

  function updateToggleButtons(theme) {
    var buttons = document.querySelectorAll('.theme-toggle-btn');
    for (var i = 0; i < buttons.length; i++) {
      var btn = buttons[i];
      var icon = btn.querySelector('i');
      if (icon) {
        icon.className = theme === 'light' ? 'fas fa-moon' : 'fas fa-sun';
      }
      btn.setAttribute('aria-label', theme === 'light' ? 'Switch to dark theme' : 'Switch to light theme');
      btn.setAttribute('title', theme === 'light' ? 'Switch to dark theme' : 'Switch to light theme');
    }
  }

  function toggleTheme() {
    applyTheme(currentTheme() === 'light' ? 'dark' : 'light');
  }

  document.addEventListener('DOMContentLoaded', function () {
    updateToggleButtons(currentTheme());
    var buttons = document.querySelectorAll('.theme-toggle-btn');
    for (var i = 0; i < buttons.length; i++) {
      buttons[i].addEventListener('click', toggleTheme);
    }
  });
})();
