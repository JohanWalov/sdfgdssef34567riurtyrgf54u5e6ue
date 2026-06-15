/* ------------------------------------------------------------------ *
 * Soft password gate for the portfolio.
 * - Note: this is a client-side gate, not real security. Files still
 *   download to the browser. It keeps the site out of casual view only.
 * - Skips itself when loaded inside an iframe (so card-cover animations
 *   and embedded demos are never gated).
 * - Remembers the unlock for the rest of the browser session.
 * ------------------------------------------------------------------ */
(function () {
  'use strict';

  // SHA-256 of the password (the literal password is not stored here).
  var PASS_HASH = '9b820b355d93381ea0e34f4bc6e4d7ee6b2d55ec2c9e6dea764ec244deacaf28';
  var STORAGE_KEY = 'pf_unlocked';
  var CONTACT_URL = 'https://www.techmagic.co/';

  // Don't gate when embedded in an iframe (card covers / inline demos).
  try { if (window.self !== window.top) return; } catch (e) { return; }

  function isUnlocked() {
    try { return sessionStorage.getItem(STORAGE_KEY) === '1'; } catch (e) { return false; }
  }

  if (isUnlocked()) return;

  // Hide page content immediately to avoid a flash before the gate appears.
  // (This script is loaded synchronously in <head>, before <body> parses.)
  document.documentElement.classList.add('pf-locked');
  var preStyle = document.createElement('style');
  preStyle.id = 'pf-gate-prestyle';
  preStyle.textContent =
    'html.pf-locked body{visibility:hidden!important}' +
    'html.pf-locked,html.pf-locked body{overflow:hidden!important}' +
    'html.pf-locked,html.pf-locked *{cursor:auto!important}' +
    '#pf-gate{visibility:visible}';
  (document.head || document.documentElement).appendChild(preStyle);

  /* --- compact, dependency-free SHA-256 (returns lowercase hex) ------ */
  function sha256(ascii) {
    function rightRotate(value, amount) { return (value >>> amount) | (value << (32 - amount)); }
    var mathPow = Math.pow, maxWord = mathPow(2, 32), result = '', words = [];
    var asciiBitLength = ascii.length * 8;
    var hash = sha256.h = sha256.h || [];
    var k = sha256.k = sha256.k || [];
    var primeCounter = k.length, isComposite = {};
    for (var candidate = 2; primeCounter < 64; candidate++) {
      if (!isComposite[candidate]) {
        for (var i = 0; i < 313; i += candidate) { isComposite[i] = candidate; }
        hash[primeCounter] = (mathPow(candidate, 0.5) * maxWord) | 0;
        k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
      }
    }
    ascii += '\x80';
    while (ascii.length % 64 - 56) ascii += '\x00';
    for (i = 0; i < ascii.length; i++) {
      var j = ascii.charCodeAt(i);
      if (j >> 8) return; // ASCII only (password is ASCII)
      words[i >> 2] |= j << ((3 - i) % 4) * 8;
    }
    words[words.length] = (asciiBitLength / maxWord) | 0;
    words[words.length] = asciiBitLength;
    for (j = 0; j < words.length;) {
      var w = words.slice(j, j += 16), oldHash = hash;
      hash = hash.slice(0, 8);
      for (i = 0; i < 64; i++) {
        var w15 = w[i - 15], w2 = w[i - 2];
        var a = hash[0], e = hash[4];
        var temp1 = hash[7] +
          (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)) +
          ((e & hash[5]) ^ (~e & hash[6])) + k[i] +
          (w[i] = i < 16 ? w[i] : (
            w[i - 16] +
            (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3)) +
            w[i - 7] +
            (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10))
          ) | 0);
        var temp2 = (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)) +
          ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]));
        hash = [(temp1 + temp2) | 0].concat(hash);
        hash[4] = (hash[4] + temp1) | 0;
      }
      for (i = 0; i < 8; i++) { hash[i] = (hash[i] + oldHash[i]) | 0; }
    }
    for (i = 0; i < 8; i++) {
      for (j = 3; j + 1; j--) {
        var b = (hash[i] >> (j * 8)) & 255;
        result += ((b < 16) ? 0 : '') + b.toString(16);
      }
    }
    return result;
  }

  /* --- build the gate overlay --------------------------------------- */
  function buildGate() {
    if (document.getElementById('pf-gate')) return;

    var style = document.createElement('style');
    style.textContent = [
      '#pf-gate{position:fixed;inset:0;z-index:2147483647;display:flex;align-items:center;',
      'justify-content:center;padding:24px;background:#1F1F1E;color:#f1efe9;',
      'font-family:"Hanken Grotesk",system-ui,-apple-system,sans-serif;',
      '-webkit-font-smoothing:antialiased}',
      '#pf-gate *{box-sizing:border-box}',
      /* restore a visible cursor over the gate (pages hide it with cursor:none) */
      '#pf-gate,#pf-gate *{cursor:auto!important}',
      '#pf-gate input{cursor:text!important}',
      '#pf-gate button,#pf-gate a{cursor:pointer!important}',
      '#pf-gate .pf-card{width:100%;max-width:420px;text-align:center}',
      '#pf-gate h1{font-family:"Yrsa",Georgia,serif;font-weight:600;font-size:34px;',
      'line-height:1.1;letter-spacing:-.01em;margin:0 0 24px}',
      '#pf-gate form{display:flex;flex-direction:column;gap:0}',
      '#pf-gate input{width:100%;height:48px;padding:0 16px;border-radius:10px;',
      'border:1px solid #34342f;background:#161618;color:#f1efe9;font-size:15px;',
      'font-family:inherit;outline:none;transition:border-color .18s}',
      '#pf-gate input::placeholder{color:#6f6f68}',
      '#pf-gate input:focus{border-color:#5b78ff}',
      '#pf-gate.pf-error input{border-color:#e5534b}',
      '#pf-gate button{width:100%;height:48px;margin-top:12px;border:0;border-radius:10px;cursor:pointer;',
      'background:#5b78ff;color:#fff;font-size:15px;font-weight:600;font-family:inherit;',
      'transition:filter .18s}',
      '#pf-gate button:hover{filter:brightness(1.08)}',
      '#pf-gate .pf-err{font-size:13px;color:#ff8a82;text-align:left;margin:0;height:0;overflow:hidden;',
      'opacity:0;transition:opacity .18s}',
      '#pf-gate.pf-error .pf-err{height:auto;margin:8px 2px 0;opacity:1}',
      '#pf-gate .pf-sign{margin:22px 0 0;font-size:13px;color:#9a9a92}',
      '#pf-gate .pf-sign a{color:#f1efe9;text-decoration:underline;text-underline-offset:2px;transition:color .18s}',
      '#pf-gate .pf-sign a:hover{color:#5b78ff}'
    ].join('');
    document.head.appendChild(style);

    var gate = document.createElement('div');
    gate.id = 'pf-gate';
    gate.setAttribute('role', 'dialog');
    gate.setAttribute('aria-modal', 'true');
    gate.setAttribute('aria-label', 'Password required');
    gate.innerHTML =
      '<div class="pf-card">' +
        '<h1>This portfolio is private</h1>' +
        '<form id="pf-form" autocomplete="off" novalidate>' +
          '<input id="pf-input" type="password" placeholder="Password" ' +
            'aria-label="Password" autocomplete="off" autocapitalize="off" ' +
            'autocorrect="off" spellcheck="false">' +
          '<div class="pf-err" id="pf-err" role="alert">Incorrect password. Please try again.</div>' +
          '<button type="button" id="pf-unlock">Unlock</button>' +
        '</form>' +
        '<p class="pf-sign">' +
          '<a href="https://www.linkedin.com/in/sviatoslav-nytka/" target="_blank" rel="noopener noreferrer">Sviatoslav Nytka</a>' +
          ' from ' +
          '<a href="' + CONTACT_URL + '" target="_blank" rel="noopener noreferrer">TechMagic</a>' +
        '</p>' +
      '</div>';
    document.body.appendChild(gate);

    var form = gate.querySelector('#pf-form');
    var input = gate.querySelector('#pf-input');
    var errText = gate.querySelector('#pf-err');
    input.focus();

    function fail() {
      gate.classList.add('pf-error');
      input.value = '';
      input.focus();
    }
    function succeed() {
      try { sessionStorage.setItem(STORAGE_KEY, '1'); } catch (e) {}
      document.documentElement.classList.remove('pf-locked');
      var pre = document.getElementById('pf-gate-prestyle');
      if (pre) pre.parentNode.removeChild(pre);
      gate.parentNode.removeChild(gate);
    }

    var unlockBtn = gate.querySelector('#pf-unlock');

    function validate() {
      if (sha256(input.value) === PASS_HASH) { succeed(); } else { fail(); }
    }

    // Validation runs ONLY when the Unlock button is clicked.
    unlockBtn.addEventListener('click', validate);
    // Pressing Enter must not validate or submit the form.
    form.addEventListener('submit', function (ev) { ev.preventDefault(); });
    // clear the error state as soon as the user edits the field again
    input.addEventListener('input', function () {
      if (gate.classList.contains('pf-error')) gate.classList.remove('pf-error');
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', buildGate);
  } else {
    buildGate();
  }
})();
