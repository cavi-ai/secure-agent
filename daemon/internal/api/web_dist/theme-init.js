// Theme before first paint: explicit choice (localStorage) wins,
// otherwise follow the system.
(function () {
  var t = null;
  try { t = localStorage.getItem('sa-theme'); } catch (e) {}
  if (t === 'light' || t === 'dark') {
    document.documentElement.dataset.theme = t;
  } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
    document.documentElement.dataset.theme = 'light';
  } else {
    document.documentElement.dataset.theme = 'dark';
  }
})();
