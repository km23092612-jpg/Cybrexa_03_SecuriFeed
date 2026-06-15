/**
 * SecuriFeed · app.js
 * Nav, scroll reveal, ticker, active links
 */

// Nav scroll
(function() {
  const nav = document.getElementById('nav');
  const hamburger = document.getElementById('hamburger');
  const navLinks  = document.querySelector('.nav__links');

  window.addEventListener('scroll', () => {
    nav?.classList.toggle('scrolled', window.scrollY > 60);
  }, { passive: true });

  hamburger?.addEventListener('click', () => {
    const open = navLinks.classList.toggle('open');
    hamburger.setAttribute('aria-expanded', String(open));
  });

  navLinks?.querySelectorAll('a').forEach(link => {
    link.addEventListener('click', () => navLinks.classList.remove('open'));
  });
})();

// Ticker duplication for seamless loop
(function() {
  const inner = document.getElementById('tickerInner');
  if (!inner) return;
  inner.innerHTML += inner.innerHTML;
})();

// Scroll reveal
(function() {
  const selectors = '.learn-card, .section__title, .section__eyebrow, .section__desc, .analyzer__card, .game__card';
  document.querySelectorAll(selectors).forEach((el, i) => {
    el.classList.add('reveal');
    el.style.transitionDelay = `${(i % 4) * 0.07}s`;
  });

  const observer = new IntersectionObserver(entries => {
    entries.forEach(e => {
      if (e.isIntersecting) { e.target.classList.add('visible'); observer.unobserve(e.target); }
    });
  }, { threshold: 0.1, rootMargin: '0px 0px -30px 0px' });

  document.querySelectorAll('.reveal').forEach(el => observer.observe(el));
})();

// Active nav link on scroll
(function() {
  const sections = document.querySelectorAll('section[id]');
  const links    = document.querySelectorAll('.nav__links a');
  const observer = new IntersectionObserver(entries => {
    entries.forEach(e => {
      if (e.isIntersecting) {
        const id = e.target.id;
        links.forEach(l => {
          l.style.color = l.getAttribute('href') === `#${id}` ? 'var(--danger)' : '';
        });
      }
    });
  }, { threshold: 0.4 });
  sections.forEach(s => observer.observe(s));
})();
