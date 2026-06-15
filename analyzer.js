/**
 * SecuriFeed · analyzer.js
 * Phishing URL detection engine — 15+ signals, risk scoring 0-100
 * All analysis runs locally — zero server calls
 */

const SUSPICIOUS_TLDS = ['.tk','.ml','.gq','.cf','.xyz','.top','.click','.download','.review','.country','.kim','.science','.work','.party','.bid'];
const TRUSTED_BRANDS  = ['paypal','google','facebook','microsoft','amazon','apple','netflix','instagram','twitter','linkedin','github','dropbox','chase','wellsfargo','bankofamerica','citibank'];
const PHISH_KEYWORDS  = ['verify','update','secure','login','account','banking','suspend','confirm','unlock','validate','reset','alert','notice','invoice','urgent','free','winner','claim'];
const SAFE_DOMAINS    = ['google.com','facebook.com','microsoft.com','amazon.com','apple.com','github.com','linkedin.com','twitter.com','instagram.com','netflix.com','youtube.com','wikipedia.org'];

let threatCount = parseInt(sessionStorage.getItem('sf_count') || '0');

function updateThreatCount() {
  const el = document.getElementById('navThreatCount');
  if (el) el.textContent = `${threatCount} URL${threatCount !== 1 ? 's' : ''} analyzed`;
}
updateThreatCount();

/* ── CORE ANALYSIS ENGINE ────────────────────── */
function analyzeUrl(rawUrl) {
  let url = rawUrl.trim();
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'http://' + url;
  }

  let parsed;
  try { parsed = new URL(url); }
  catch { return null; }

  const hostname  = parsed.hostname.toLowerCase();
  const pathname  = parsed.pathname.toLowerCase();
  const fullUrl   = url.toLowerCase();
  const signals   = [];
  let riskScore   = 0;

  // ── 1. Protocol check
  const isHttps = parsed.protocol === 'https:';
  signals.push({
    label: 'SSL / HTTPS',
    icon: isHttps ? '🔒' : '🔓',
    val: isHttps ? 'HTTPS' : 'HTTP only',
    status: isHttps ? 'pass' : 'fail',
    weight: isHttps ? 0 : 15,
  });
  if (!isHttps) riskScore += 15;

  // ── 2. IP address in hostname
  const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
  signals.push({
    label: 'IP Address URL',
    icon: isIp ? '🚨' : '✅',
    val: isIp ? 'YES — Red flag' : 'Domain name',
    status: isIp ? 'fail' : 'pass',
    weight: isIp ? 25 : 0,
  });
  if (isIp) riskScore += 25;

  // ── 3. Trusted brand in URL but wrong domain (typosquatting)
  const brandFound = TRUSTED_BRANDS.find(b => fullUrl.includes(b));
  const isTrustedDomain = SAFE_DOMAINS.some(d => hostname === d || hostname.endsWith('.' + d));
  const isBrandSpoof = brandFound && !isTrustedDomain;
  signals.push({
    label: 'Brand Spoofing',
    icon: isBrandSpoof ? '🎭' : '✅',
    val: isBrandSpoof ? `"${brandFound}" in fake domain` : 'None detected',
    status: isBrandSpoof ? 'fail' : 'pass',
    weight: isBrandSpoof ? 30 : 0,
  });
  if (isBrandSpoof) riskScore += 30;

  // ── 4. Suspicious TLD
  const suspTld = SUSPICIOUS_TLDS.find(t => hostname.endsWith(t));
  signals.push({
    label: 'Suspicious TLD',
    icon: suspTld ? '⚠️' : '✅',
    val: suspTld ? suspTld : 'Normal TLD',
    status: suspTld ? 'warn' : 'pass',
    weight: suspTld ? 12 : 0,
  });
  if (suspTld) riskScore += 12;

  // ── 5. URL length
  const urlLen = rawUrl.length;
  const isLong = urlLen > 75;
  signals.push({
    label: 'URL Length',
    icon: isLong ? '⚠️' : '✅',
    val: `${urlLen} chars${isLong ? ' — suspicious' : ''}`,
    status: isLong ? 'warn' : 'pass',
    weight: isLong ? 8 : 0,
  });
  if (isLong) riskScore += 8;

  // ── 6. Hyphen count in domain
  const hyphenCount = (hostname.match(/-/g) || []).length;
  const tooManyHyphens = hyphenCount >= 3;
  signals.push({
    label: 'Hyphens in Domain',
    icon: tooManyHyphens ? '⚠️' : '✅',
    val: `${hyphenCount} hyphen${hyphenCount !== 1 ? 's' : ''}`,
    status: tooManyHyphens ? 'warn' : 'pass',
    weight: tooManyHyphens ? 10 : 0,
  });
  if (tooManyHyphens) riskScore += 10;

  // ── 7. Phishing keywords in URL
  const foundKeywords = PHISH_KEYWORDS.filter(k => fullUrl.includes(k));
  const hasKeywords = foundKeywords.length >= 2;
  signals.push({
    label: 'Phishing Keywords',
    icon: hasKeywords ? '🚨' : '✅',
    val: hasKeywords ? foundKeywords.slice(0,3).join(', ') : 'None',
    status: hasKeywords ? 'fail' : 'pass',
    weight: hasKeywords ? 18 : 0,
  });
  if (hasKeywords) riskScore += 18;

  // ── 8. Subdomain depth
  const subdomainParts = hostname.split('.').length - 2;
  const deepSubdomain = subdomainParts >= 3;
  signals.push({
    label: 'Subdomain Depth',
    icon: deepSubdomain ? '⚠️' : '✅',
    val: `${Math.max(0, subdomainParts)} level${subdomainParts !== 1 ? 's' : ''}`,
    status: deepSubdomain ? 'warn' : 'pass',
    weight: deepSubdomain ? 10 : 0,
  });
  if (deepSubdomain) riskScore += 10;

  // ── 9. Number substitution (0→o, 1→l, 3→e etc.)
  const hasNumSub = /[0-9]/.test(hostname) && TRUSTED_BRANDS.some(b => {
    const numVersion = b.replace(/o/g,'0').replace(/l/g,'1').replace(/e/g,'3').replace(/a/g,'4');
    return hostname.includes(numVersion) || (hostname.includes(b.slice(0,-1)) && /[0-9]/.test(hostname));
  });
  signals.push({
    label: 'Number Substitution',
    icon: hasNumSub ? '🚨' : '✅',
    val: hasNumSub ? 'Detected (e.g. 0→o)' : 'None',
    status: hasNumSub ? 'fail' : 'pass',
    weight: hasNumSub ? 20 : 0,
  });
  if (hasNumSub) riskScore += 20;

  // ── 10. @ symbol in URL
  const hasAt = rawUrl.includes('@');
  signals.push({
    label: '@ Symbol in URL',
    icon: hasAt ? '🚨' : '✅',
    val: hasAt ? 'Redirect trick' : 'Clean',
    status: hasAt ? 'fail' : 'pass',
    weight: hasAt ? 20 : 0,
  });
  if (hasAt) riskScore += 20;

  // ── 11. Port in URL
  const hasPort = !!parsed.port;
  signals.push({
    label: 'Non-standard Port',
    icon: hasPort ? '⚠️' : '✅',
    val: hasPort ? `:${parsed.port}` : 'Standard',
    status: hasPort ? 'warn' : 'pass',
    weight: hasPort ? 8 : 0,
  });
  if (hasPort) riskScore += 8;

  // ── 12. Safe known domain
  const isKnownSafe = SAFE_DOMAINS.some(d => hostname === d || hostname.endsWith('.' + d));
  if (isKnownSafe) riskScore = Math.max(0, riskScore - 30);

  // Cap at 100
  riskScore = Math.min(100, Math.max(0, riskScore));

  // ── Verdict
  let verdict, verdictClass, summary, recClass, recommendation;
  if (riskScore <= 15) {
    verdict = '✅ SAFE'; verdictClass = 'safe-badge';
    summary = 'This URL shows no significant phishing indicators. Appears legitimate.';
    recClass = 'rec--safe';
    recommendation = '✅ This URL appears safe. Still, stay alert and never enter sensitive data on unexpected pages.';
  } else if (riskScore <= 35) {
    verdict = '⚠️ LOW RISK'; verdictClass = 'warn-badge';
    summary = 'A few minor signals detected. Proceed with caution.';
    recClass = 'rec--warn';
    recommendation = '⚠️ Low risk but suspicious. Verify you meant to visit this site before entering any credentials.';
  } else if (riskScore <= 60) {
    verdict = '🔴 SUSPICIOUS'; verdictClass = 'danger-badge';
    summary = 'Multiple phishing indicators found. This URL is likely malicious.';
    recClass = 'rec--danger';
    recommendation = '🔴 Do NOT proceed. This URL has multiple phishing signals. If you received this link unsolicited, report it and delete it.';
  } else {
    verdict = '🚨 PHISHING'; verdictClass = 'critical-badge';
    summary = 'High confidence phishing URL. Do not visit this site under any circumstances.';
    recClass = 'rec--critical';
    recommendation = '🚨 DANGER — This is almost certainly a phishing site. Do not click, do not enter any information. Report to your IT team or phishing@reportphishing.antiphishing.org.';
  }

  return { url: rawUrl, hostname, riskScore, verdict, verdictClass, summary, signals, isHttps, recClass, recommendation };
}

/* ── RENDER RESULT ───────────────────────────── */
function renderResult(result) {
  if (!result) return;

  const panel = document.getElementById('analyzerResult');
  panel.removeAttribute('hidden');

  // Gauge
  const gaugeScore = document.getElementById('gaugeScore');
  const gaugeFill  = document.getElementById('gaugeFill');
  const gaugeLabel = document.getElementById('gaugeLabel');
  const score      = result.riskScore;

  gaugeScore.textContent = score;
  gaugeLabel.textContent = score <= 15 ? 'SAFE' : score <= 35 ? 'LOW RISK' : score <= 60 ? 'SUSPICIOUS' : 'PHISHING';

  const colors = score <= 15 ? '#48BB78' : score <= 35 ? '#F6AD55' : score <= 60 ? '#FF6B35' : '#E53E3E';
  const dashArr = (score / 100) * 188;
  gaugeFill.style.stroke = colors;
  gaugeFill.style.strokeDasharray = `${dashArr} 188`;

  // Verdict
  document.getElementById('verdictBadge').textContent = result.verdict;
  document.getElementById('verdictBadge').className = `verdict-badge ${result.verdictClass}`;
  document.getElementById('resultUrl').textContent = result.url;
  document.getElementById('resultSummary').textContent = result.summary;

  // Signals
  const grid = document.getElementById('signalsGrid');
  grid.innerHTML = '';
  result.signals.forEach(sig => {
    const div = document.createElement('div');
    div.className = `signal-item signal--${sig.status}`;
    div.innerHTML = `
      <span class="signal-icon">${sig.icon}</span>
      <span class="signal-label">${sig.label}</span>
      <span class="signal-val">${sig.val}</span>
    `;
    grid.appendChild(div);
  });

  // SSL
  const sslInfo = document.getElementById('sslInfo');
  sslInfo.innerHTML = `
    <div class="ssl-badge ${result.isHttps ? 'secure' : 'insecure'}">
      ${result.isHttps ? '🔒 HTTPS — Encrypted connection' : '🔓 HTTP — No encryption'}
    </div>
    <div class="ssl-badge ${result.isHttps ? 'secure' : 'insecure'}">
      ${result.isHttps ? '✅ Certificate present' : '⚠️ No SSL certificate'}
    </div>
  `;

  // Recommendation
  const rec = document.getElementById('recommendation');
  rec.className = `recommendation ${result.recClass}`;
  rec.textContent = result.recommendation;

  // Scroll to result
  panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

/* ── INIT ANALYZER ───────────────────────────── */
(function initAnalyzer() {
  const input      = document.getElementById('analyzerInput');
  const analyzeBtn = document.getElementById('analyzeBtn');
  const clearBtn   = document.getElementById('clearBtn');

  function runAnalysis(url) {
    if (!url?.trim()) { input?.focus(); return; }
    const result = analyzeUrl(url);
    if (!result) {
      alert('Please enter a valid URL.');
      return;
    }
    renderResult(result);
    threatCount++;
    sessionStorage.setItem('sf_count', String(threatCount));
    updateThreatCount();
  }

  analyzeBtn?.addEventListener('click', () => runAnalysis(input.value));
  input?.addEventListener('keydown', e => { if (e.key === 'Enter') runAnalysis(input.value); });
  clearBtn?.addEventListener('click', () => {
    input.value = '';
    document.getElementById('analyzerResult')?.setAttribute('hidden', '');
    input.focus();
  });

  // Hero scan
  document.getElementById('heroScanBtn')?.addEventListener('click', () => {
    const url = document.getElementById('heroUrlInput').value;
    if (url) {
      document.getElementById('analyzerInput').value = url;
      document.getElementById('analyzer').scrollIntoView({ behavior: 'smooth' });
      setTimeout(() => runAnalysis(url), 600);
    }
  });

  document.getElementById('heroUrlInput')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') document.getElementById('heroScanBtn').click();
  });

  // Example pills
  document.querySelectorAll('.example-pill').forEach(btn => {
    btn.addEventListener('click', () => {
      const url = btn.dataset.url;
      document.getElementById('heroUrlInput').value = url;
      document.getElementById('analyzerInput').value = url;
      document.getElementById('analyzer').scrollIntoView({ behavior: 'smooth' });
      setTimeout(() => runAnalysis(url), 400);
    });
  });

  // Test URLs
  loadTestUrls();
})();

/* ── TEST URLS ───────────────────────────────── */
async function loadTestUrls() {
  try {
    const res  = await fetch('data/news-data.json');
    const data = await res.json();
    const grid = document.getElementById('testUrlsGrid');
    if (!grid) return;

    data.testUrls.forEach(item => {
      const div = document.createElement('div');
      div.className = 'test-url-item';
      div.innerHTML = `
        <span class="url-text">${item.url}</span>
        <span class="url-expected ${item.expected}">${item.expected}</span>
        <span class="url-result" id="tr-${btoa(item.url).slice(0,8)}"></span>
      `;
      div.addEventListener('click', () => {
        document.getElementById('analyzerInput').value = item.url;
        document.getElementById('analyzeBtn').click();
      });
      grid.appendChild(div);
    });

    // Run all tests
    document.getElementById('runAllTests')?.addEventListener('click', () => {
      let correct = 0;
      data.testUrls.forEach(item => {
        const result = analyzeUrl(item.url);
        if (!result) return;
        const predicted = result.riskScore > 30 ? 'phishing' : 'safe';
        const isCorrect = predicted === item.expected;
        if (isCorrect) correct++;
        const el = document.getElementById(`tr-${btoa(item.url).slice(0,8)}`);
        if (el) el.textContent = isCorrect ? '✅' : '❌';
      });
      const acc = Math.round((correct / data.testUrls.length) * 100);
      const bar = document.getElementById('accuracyBar');
      const scoreEl = document.getElementById('accuracyScore');
      if (bar && scoreEl) {
        bar.removeAttribute('hidden');
        scoreEl.textContent = `${acc}% (${correct}/${data.testUrls.length})`;
      }
    });
  } catch (e) {
    console.warn('Could not load test URLs:', e);
  }
}
