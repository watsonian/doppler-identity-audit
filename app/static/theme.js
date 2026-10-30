"use strict";

// Runs before first paint so the page never flashes the wrong theme: a saved choice
// wins, otherwise follow the system and keep following it.
(function () {
  let saved = null;
  try { saved = localStorage.getItem("identity-audit:theme"); } catch { /* storage unavailable */ }
  const system = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  const theme = saved === "dark" || saved === "light" ? saved : system;
  document.documentElement.classList.add(`theme-${theme}`);
  document.documentElement.dataset.systemTheme = saved ? "false" : "true";
})();
