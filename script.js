/* ── Navbar scroll effect ──────────────────────────────────── */
const navbar = document.getElementById('navbar');
window.addEventListener('scroll', () => {
  navbar.classList.toggle('scrolled', window.scrollY > 20);
  highlightNavLink();
});

/* ── Mobile nav toggle ─────────────────────────────────────── */
document.getElementById('navToggle').addEventListener('click', () => {
  document.getElementById('navLinks').classList.toggle('open');
});
document.querySelectorAll('.nav-links a').forEach(link => {
  link.addEventListener('click', () => {
    document.getElementById('navLinks').classList.remove('open');
  });
});

/* ── Active nav link on scroll ─────────────────────────────── */
function highlightNavLink() {
  const sections = document.querySelectorAll('section[id]');
  const links    = document.querySelectorAll('.nav-links a');
  let current = '';
  sections.forEach(sec => {
    if (window.scrollY >= sec.offsetTop - 100) current = sec.id;
  });
  links.forEach(link => {
    link.classList.toggle('active', link.getAttribute('href') === '#' + current);
  });
}
highlightNavLink();

/* ── Typewriter effect ─────────────────────────────────────── */
const phrases = [
  'Cyber Security Lead',
  'Email Threat Analyst',
  'ISMS Manager',
  'Information Security Professional',
];
let phraseIdx = 0, charIdx = 0, deleting = false;
const twEl = document.getElementById('typewriter');

function typewrite() {
  if (!twEl) return;
  const phrase = phrases[phraseIdx];
  if (deleting) {
    charIdx--;
    twEl.textContent = phrase.slice(0, charIdx);
    if (charIdx === 0) {
      deleting = false;
      phraseIdx = (phraseIdx + 1) % phrases.length;
      setTimeout(typewrite, 450);
      return;
    }
    setTimeout(typewrite, 38);
  } else {
    charIdx++;
    twEl.textContent = phrase.slice(0, charIdx);
    if (charIdx === phrase.length) {
      deleting = true;
      setTimeout(typewrite, 2200);
      return;
    }
    setTimeout(typewrite, 68);
  }
}
typewrite();

/* ── Scroll-reveal with staggered data-delay ───────────────── */
/**
 * Elements with class  reveal        → fade up
 * Elements with class  reveal-left   → slide in from left
 * Elements with class  reveal-right  → slide in from right
 *
 * Add data-delay="N" (ms) for staggered entrance inside a group.
 */
const revealObserver = new IntersectionObserver(
  (entries) => {
    entries.forEach(entry => {
      if (!entry.isIntersecting) return;
      const el    = entry.target;
      const delay = parseInt(el.dataset.delay || '0', 10);
      setTimeout(() => el.classList.add('visible'), delay);
      revealObserver.unobserve(el);
    });
  },
  { threshold: 0.1, rootMargin: '0px 0px -40px 0px' }
);

/* Attach reveal classes and observe */
function initReveal() {
  /* Section titles & tags */
  document.querySelectorAll('.section-title, .section-tag, .section-header').forEach(el => {
    el.classList.add('reveal');
    revealObserver.observe(el);
  });

  /* About grid — left/right */
  const aboutText     = document.querySelector('.about-text');
  const aboutTerminal = document.querySelector('.about-terminal');
  if (aboutText)     { aboutText.classList.add('reveal-left');  revealObserver.observe(aboutText); }
  if (aboutTerminal) { aboutTerminal.classList.add('reveal-right'); revealObserver.observe(aboutTerminal); }

  /* Skill cards — staggered */
  document.querySelectorAll('.skill-card').forEach(el => {
    el.classList.add('reveal');
    revealObserver.observe(el);
  });

  /* Project cards */
  document.querySelectorAll('.project-card').forEach((el, i) => {
    el.dataset.delay = el.dataset.delay || String(i * 120);
    el.classList.add('reveal');
    revealObserver.observe(el);
  });

  /* Timeline items — alternate left/right on desktop */
  document.querySelectorAll('.timeline-item').forEach((el, i) => {
    el.dataset.delay = el.dataset.delay || String(i * 100);
    el.classList.add('reveal');
    revealObserver.observe(el);
  });

  /* Education cards */
  document.querySelectorAll('.edu-card').forEach((el, i) => {
    el.dataset.delay = el.dataset.delay || String(i * 120);
    el.classList.add('reveal');
    revealObserver.observe(el);
  });

  /* Certification cards — staggered */
  document.querySelectorAll('.cert-card').forEach(el => {
    el.classList.add('reveal');
    revealObserver.observe(el);
  });

  /* Contact grid */
  const contactText     = document.querySelector('.contact-text');
  const contactTerminal = document.querySelector('.contact-terminal');
  if (contactText)     { contactText.classList.add('reveal-left');  revealObserver.observe(contactText); }
  if (contactTerminal) { contactTerminal.classList.add('reveal-right'); revealObserver.observe(contactTerminal); }

  /* About stats */
  document.querySelectorAll('.stat').forEach((el, i) => {
    el.dataset.delay = el.dataset.delay || String(i * 100);
    el.classList.add('reveal');
    revealObserver.observe(el);
  });
}

initReveal();

/* ── Hero badges stagger on load ───────────────────────────── */
window.addEventListener('load', () => {
  document.querySelectorAll('.hero-badges .badge').forEach((b, i) => {
    setTimeout(() => b.classList.add('badge-visible'), 800 + i * 100);
  });
});

/* ── Smooth counter animation for about stats ──────────────── */
function animateCounter(el, target, duration = 1200) {
  const isNum = !isNaN(parseInt(target, 10));
  if (!isNum) return; /* skip non-numeric like "ISO" */
  let start     = 0;
  const numTarget = parseInt(target, 10);
  const step    = numTarget / (duration / 16);
  const timer   = setInterval(() => {
    start += step;
    if (start >= numTarget) {
      el.textContent = target; /* preserve "+" suffix */
      clearInterval(timer);
    } else {
      el.textContent = Math.floor(start) + (target.includes('+') ? '+' : '');
    }
  }, 16);
}

const statObserver = new IntersectionObserver(entries => {
  entries.forEach(e => {
    if (!e.isIntersecting) return;
    const numEl = e.target.querySelector('.stat-num');
    if (numEl && !numEl.dataset.animated) {
      numEl.dataset.animated = '1';
      animateCounter(numEl, numEl.textContent.trim());
    }
    statObserver.unobserve(e.target);
  });
}, { threshold: 0.5 });

document.querySelectorAll('.stat').forEach(el => statObserver.observe(el));

/* ── Matrix rain canvas ────────────────────────────────────── */
(function initMatrix() {
  const canvas = document.getElementById('matrixCanvas');
  if (!canvas) return;
  const ctx   = canvas.getContext('2d');
  const chars = '01アイウエオカキクケコサシスセソタチツテトナニヌネノ'.split('');
  let cols, drops, animId;

  function resize() {
    canvas.width  = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;
    cols  = Math.floor(canvas.width / 18);
    drops = Array(cols).fill(1);
  }

  function draw() {
    ctx.fillStyle = 'rgba(7, 11, 20, 0.05)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = 'rgba(99,179,237,0.55)';
    ctx.font = '13px JetBrains Mono, monospace';
    drops.forEach((y, i) => {
      const char = chars[Math.floor(Math.random() * chars.length)];
      ctx.fillText(char, i * 18, y * 18);
      if (y * 18 > canvas.height && Math.random() > 0.975) drops[i] = 0;
      drops[i]++;
    });
    animId = requestAnimationFrame(draw);
  }

  /* Pause when hero is not visible to save CPU */
  const heroObserver = new IntersectionObserver(entries => {
    entries.forEach(e => {
      if (e.isIntersecting) {
        if (!animId) draw();
      } else {
        cancelAnimationFrame(animId);
        animId = null;
      }
    });
  }, { threshold: 0 });

  resize();
  window.addEventListener('resize', () => {
    resize();
  });

  const hero = document.getElementById('hero');
  if (hero) heroObserver.observe(hero);
  else draw();
})();

/* ── Cert logo fallback — hide broken <img> cleanly ───────── */
document.querySelectorAll('.cert-logo').forEach(img => {
  img.addEventListener('error', () => {
    img.style.display = 'none';
    const fallback = img.closest('.cert-logo-wrap')?.querySelector('.cert-logo-fallback');
    if (fallback) fallback.style.display = 'flex';
  });
});

/* ── Company logo fallback ─────────────────────────────────── */
document.querySelectorAll('.tc-logo').forEach(img => {
  img.addEventListener('error', () => { img.style.display = 'none'; });
});

/* ── Glowing card follow cursor ────────────────────────────── */
document.querySelectorAll('.cert-card, .skill-card, .project-card').forEach(card => {
  card.addEventListener('mousemove', e => {
    const rect  = card.getBoundingClientRect();
    const x     = ((e.clientX - rect.left) / rect.width)  * 100;
    const y     = ((e.clientY - rect.top)  / rect.height) * 100;
    const glow  = card.querySelector('.cert-card-glow, .skill-card-glow');
    if (glow) {
      glow.style.background =
        `radial-gradient(circle at ${x}% ${y}%, rgba(99,179,237,0.14) 0%, transparent 65%)`;
    }
  });
  card.addEventListener('mouseleave', () => {
    const glow = card.querySelector('.cert-card-glow, .skill-card-glow');
    if (glow) glow.style.background = '';
  });
});
