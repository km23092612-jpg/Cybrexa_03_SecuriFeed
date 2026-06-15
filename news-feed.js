/**
 * SecuriFeed · news-feed.js
 * Loads cybersecurity news from local JSON and renders the feed
 */

(async function initNewsFeed() {
  const grid = document.getElementById('newsGrid');
  if (!grid) return;

  let allNews = [];

  try {
    const res = await fetch('news-data.json');
    const data = await res.json();
    allNews = data.news;
    renderNews(allNews);
  } catch (e) {
    grid.innerHTML = '<p style="color:var(--text-muted);font-size:0.88rem;">// Could not load news feed. Open via a local server or deploy to Netlify.</p>';
    return;
  }

  // Filter buttons
  document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const filter = btn.dataset.filter;
      const filtered = filter === 'all' ? allNews : allNews.filter(n => n.category === filter);
      renderNews(filtered);
    });
  });

  function renderNews(items) {
    grid.innerHTML = '';
    if (!items.length) {
      grid.innerHTML = '<p style="color:var(--text-muted);font-size:0.88rem;">No items in this category.</p>';
      return;
    }
    items.forEach(item => {
      const card = document.createElement('div');
      card.className = 'news-card reveal';
      card.innerHTML = `
        <div class="news-card__top">
          <span class="news-card__category cat--${item.category}">${item.category}</span>
          <span class="severity-dot sev--${item.severity}" title="${item.severity}"></span>
        </div>
        <h3>${item.title}</h3>
        <p>${item.summary}</p>
        <div class="news-card__tags">
          ${item.tags.map(t => `<span class="news-tag">#${t}</span>`).join('')}
        </div>
        <div class="news-card__footer">
          <span class="news-card__source">${item.source}</span>
          <span class="news-card__date">${item.date}</span>
        </div>
      `;
      grid.appendChild(card);

      // Trigger reveal
      requestAnimationFrame(() => {
        const observer = new IntersectionObserver(entries => {
          entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('visible'); observer.unobserve(e.target); } });
        }, { threshold: 0.1 });
        observer.observe(card);
      });
    });
  }
})();
