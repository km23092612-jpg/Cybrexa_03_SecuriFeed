# 🛡️ SecuriFeed — PhishDetect

> **Project 3 of 4 · Cybrexa Learning Track · Intermediate**  
> A privacy-first phishing URL analyzer with risk scoring, threat feed & interactive quiz.

[![Live Demo](https://img.shields.io/badge/Live-Demo-FF6B35?style=flat-square&logo=netlify)](https://your-site.netlify.app)
[![GitHub](https://img.shields.io/badge/GitHub-Cybrexa__03__SecuriFeed-181717?style=flat-square&logo=github)](https://github.com/km23092612-jpg/Cybrexa_03_SecuriFeed)
[![Privacy](https://img.shields.io/badge/Privacy-Zero%20Server%20Calls-orange?style=flat-square)](./SECURITY.md)
[![Accuracy](https://img.shields.io/badge/Accuracy-80%25%2B%20on%2010%20test%20URLs-success?style=flat-square)](./data/news-data.json)

---

## 📸 Screenshots

> _Add screenshots after deployment_

---

## ✨ Features

### 🔍 URL Risk Analyzer — 15+ Signals
- Risk score 0–100 with animated gauge
- Green=Safe / Yellow=Suspicious / Red=Phishing
- Checks: SSL/HTTPS, IP address, brand spoofing, typosquatting, number substitution, suspicious TLDs, phishing keywords, URL length, hyphen count, subdomain depth, @ symbol trick, non-standard ports
- SSL certificate status display
- Clear recommendation (safe / avoid / danger)
- Accuracy benchmark — run 10 known URLs and see detection rate

### 📰 Live Threat Intelligence Feed
- 6 cybersecurity news cards loaded from local JSON
- Filter by: All / Phishing / Vulnerabilities / Ransomware / Auth
- Severity indicators (Critical / High / Medium / Low)
- Tags, source, and date for each item

### 🎮 Phish or Legit? Quiz
- 10-round interactive quiz
- Score tracker + streak counter
- Detailed explanation after each answer
- Shuffled questions every round

### 📚 Phishing Detection Guide
- 6 educational cards covering: typosquatting, IP URLs, HTTP vs HTTPS, suspicious TLDs, keyword stuffing, subdomain tricks

### 🔴 Live Threat Ticker
- Scrolling ticker at top showing simulated live threat alerts

---

## 🗂️ Repo Structure

```
Cybrexa_03_SecuriFeed/
├── index.html
├── css/
│   ├── main.css          # Base styles, nav, hero, learn, footer
│   ├── analyzer.css      # Analyzer card, gauge, signals, SSL panel
│   └── news.css          # News cards, filters, quiz game
├── js/
│   ├── analyzer.js       # URL analysis engine — 15+ signals
│   ├── news-feed.js      # JSON loader + news renderer
│   ├── game.js           # Phishing quiz logic
│   └── app.js            # Nav, scroll reveal, ticker
├── data/
│   └── news-data.json    # News articles + test URLs
├── images/               # Screenshots
├── _headers              # Netlify CSP headers
├── SECURITY.md
└── README.md
```

---

## ⚙️ Setup

```bash
git clone https://github.com/km23092612-jpg/Cybrexa_03_SecuriFeed.git
cd Cybrexa_03_SecuriFeed

# Must run via local server (for JSON fetch)
# Option 1 — Python
python3 -m http.server 8080

# Option 2 — VS Code Live Server extension
# Option 3 — Deploy to Netlify (recommended)
```

> ⚠️ Open via `localhost:8080` not by double-clicking index.html — the news feed uses `fetch()` which requires a server.

---

## ✅ Deliverables Checklist

- [ ] GitHub Repo: `Cybrexa_03_SecuriFeed`
- [ ] Live URL deployed on Netlify
- [ ] 80%+ accuracy on 10 test URLs ← click "Run All Tests" in the app
- [ ] 2-3 min screen recording for LinkedIn
- [ ] Learning Doc: Phishing Detection (see `/learn` section)
- [ ] LinkedIn post mentioning @cybrexa with GitHub link

---

## 🏷️ Tech Stack

`HTML5` · `CSS3` · `Vanilla JavaScript` · `Regex` · `Async/Fetch` · `Web APIs` · `JSON` · `Netlify`

---

## 📄 License

MIT © 2026 Kritika Mishra — Built as part of the [Cybrexa](https://cybrexa.in) learning track.
