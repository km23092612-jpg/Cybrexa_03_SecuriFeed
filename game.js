/**
 * SecuriFeed · game.js
 * Phish or Legit? — 10-round quiz game
 */

const QUIZ_URLS = [
  { url: 'http://paypa1.com/login', answer: 'phishing', reason: '⚠️ "paypa1" uses number substitution (1→l). Real PayPal is paypal.com.' },
  { url: 'https://google.com/search?q=security', answer: 'safe', reason: '✅ Legitimate Google URL with HTTPS and correct domain.' },
  { url: 'http://192.168.10.1/bank-login', answer: 'phishing', reason: '🚨 Raw IP addresses in URLs are a major red flag — never login via an IP.' },
  { url: 'https://facebook.com/login', answer: 'safe', reason: '✅ Legitimate Facebook login page with HTTPS.' },
  { url: 'http://amaz0n-account-verify.xyz/update', answer: 'phishing', reason: '🚨 "amaz0n" (0→o), .xyz TLD, and "verify"/"update" keywords — classic phishing.' },
  { url: 'https://github.com/login', answer: 'safe', reason: '✅ Legitimate GitHub. HTTPS, correct domain.' },
  { url: 'http://secure-bankofamerica-login.tk', answer: 'phishing', reason: '🚨 .tk is a free suspicious TLD. Real BofA is bankofamerica.com.' },
  { url: 'https://linkedin.com/in/profile', answer: 'safe', reason: '✅ Legitimate LinkedIn profile URL.' },
  { url: 'http://netflix-account-suspended.click/verify', answer: 'phishing', reason: '🚨 .click TLD, "suspended" and "verify" keywords, HTTP only — textbook phishing.' },
  { url: 'https://microsoft.com/en-us/security', answer: 'safe', reason: '✅ Official Microsoft security page with HTTPS.' },
  { url: 'http://dropbox.com.file-share.tk/document', answer: 'phishing', reason: '🚨 Real domain is dropbox.com — here it\'s a subdomain of file-share.tk.' },
  { url: 'https://apple.com/iphone', answer: 'safe', reason: '✅ Official Apple website.' },
];

(function initGame() {
  let questions = [];
  let currentIndex = 0;
  let score = 0;
  let streak = 0;
  let answered = false;

  const gameUrl      = document.getElementById('gameUrl');
  const btnSafe      = document.getElementById('btnSafe');
  const btnPhish     = document.getElementById('btnPhish');
  const gameFeedback = document.getElementById('gameFeedback');
  const gameResult   = document.getElementById('gameResult');
  const gameScore    = document.getElementById('gameScore');
  const gameRound    = document.getElementById('gameRound');
  const gameStreak   = document.getElementById('gameStreak');
  const finalScore   = document.getElementById('finalScore');
  const resultMsg    = document.getElementById('resultMessage');
  const restartBtn   = document.getElementById('restartGame');

  if (!gameUrl) return;

  function shuffle(arr) {
    const a = [...arr];
    for (let i = a.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [a[i], a[j]] = [a[j], a[i]];
    }
    return a;
  }

  function startGame() {
    questions   = shuffle(QUIZ_URLS).slice(0, 10);
    currentIndex = 0; score = 0; streak = 0; answered = false;

    gameResult.setAttribute('hidden', '');
    gameFeedback.setAttribute('hidden', '');
    gameScore.textContent  = '0';
    gameRound.textContent  = '1';
    gameStreak.textContent = '0';
    btnSafe.disabled  = false;
    btnPhish.disabled = false;

    loadQuestion();
  }

  function loadQuestion() {
    if (currentIndex >= questions.length) { showResult(); return; }
    answered = false;
    gameFeedback.setAttribute('hidden', '');
    btnSafe.disabled  = false;
    btnPhish.disabled = false;
    gameRound.textContent = currentIndex + 1;
    gameUrl.textContent   = questions[currentIndex].url;  // textContent = XSS safe
  }

  function answer(choice) {
    if (answered) return;
    answered = true;
    btnSafe.disabled  = true;
    btnPhish.disabled = true;

    const q = questions[currentIndex];
    const correct = choice === q.answer;

    if (correct) {
      score++; streak++;
      gameScore.textContent  = score;
      gameStreak.textContent = streak;
    } else {
      streak = 0;
      gameStreak.textContent = '0';
    }

    gameFeedback.className   = `game__feedback ${correct ? 'correct' : 'wrong'}`;
    gameFeedback.textContent = q.reason;
    gameFeedback.removeAttribute('hidden');

    setTimeout(() => {
      currentIndex++;
      loadQuestion();
    }, 2200);
  }

  function showResult() {
    gameResult.removeAttribute('hidden');
    finalScore.textContent = `${score}/10`;
    const msgs = [
      [10, '🏆 Perfect score! You\'re a phishing detection expert!'],
      [8,  '🔥 Excellent! Attackers would have a hard time fooling you.'],
      [6,  '👍 Good job! A bit more practice and you\'ll be expert-level.'],
      [4,  '⚠️ Getting there — review the Learn section to sharpen your eye.'],
      [0,  '📚 Don\'t worry! Check the Learn section and try again.'],
    ];
    const msg = msgs.find(([min]) => score >= min);
    resultMsg.textContent = msg ? msg[1] : '';
  }

  btnSafe?.addEventListener('click',  () => answer('safe'));
  btnPhish?.addEventListener('click', () => answer('phishing'));
  restartBtn?.addEventListener('click', startGame);

  startGame();
})();
