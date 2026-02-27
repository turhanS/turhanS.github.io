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
  const links = document.querySelectorAll('.nav-links a');
  let current = '';
  sections.forEach(sec => {
    if (window.scrollY >= sec.offsetTop - 80) current = sec.id;
  });
  links.forEach(link => {
    link.classList.toggle('active', link.getAttribute('href') === '#' + current);
  });
}

/* ── Typewriter effect ─────────────────────────────────────── */
const phrases = [
  'Cyber Security Lead',
  'ISO 27001 Specialist',
  'Email Threat Analyst',
  'ISMS Manager',
  'Phishing Detection Specialist',
];
let phraseIdx = 0, charIdx = 0, deleting = false;
const twEl = document.getElementById('typewriter');

function typewrite() {
  const phrase = phrases[phraseIdx];
  if (deleting) {
    charIdx--;
    twEl.textContent = phrase.slice(0, charIdx);
    if (charIdx === 0) {
      deleting = false;
      phraseIdx = (phraseIdx + 1) % phrases.length;
      setTimeout(typewrite, 400);
      return;
    }
    setTimeout(typewrite, 40);
  } else {
    charIdx++;
    twEl.textContent = phrase.slice(0, charIdx);
    if (charIdx === phrase.length) {
      deleting = true;
      setTimeout(typewrite, 2000);
      return;
    }
    setTimeout(typewrite, 70);
  }
}
typewrite();

/* ── Fade-in on scroll ─────────────────────────────────────── */
const fadeEls = document.querySelectorAll(
  '.skill-card, .project-card, .timeline-item, .about-grid, .contact-grid, .section-title'
);
fadeEls.forEach(el => el.classList.add('fade-in'));

const observer = new IntersectionObserver(
  (entries) => entries.forEach(e => { if (e.isIntersecting) e.target.classList.add('visible'); }),
  { threshold: 0.12 }
);
fadeEls.forEach(el => observer.observe(el));

/* ── Matrix rain canvas ────────────────────────────────────── */
(function initMatrix() {
  const canvas = document.getElementById('matrixCanvas');
  const ctx = canvas.getContext('2d');
  const chars = '01アイウエオカキクケコサシスセソタチツテトナニヌネノ'.split('');
  let cols, drops;

  function resize() {
    canvas.width  = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;
    cols  = Math.floor(canvas.width / 18);
    drops = Array(cols).fill(1);
  }

  function draw() {
    ctx.fillStyle = 'rgba(10, 14, 26, 0.05)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = '#63b3ed';
    ctx.font = '14px JetBrains Mono, monospace';
    drops.forEach((y, i) => {
      const char = chars[Math.floor(Math.random() * chars.length)];
      ctx.fillText(char, i * 18, y * 18);
      if (y * 18 > canvas.height && Math.random() > 0.975) drops[i] = 0;
      drops[i]++;
    });
  }

  resize();
  window.addEventListener('resize', resize);
  setInterval(draw, 60);
})();
