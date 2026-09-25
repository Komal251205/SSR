/**
 * Smart Suraksha Rakshak (SSR) - Front-end Application Controller
 * Handles Navigation, Mobile Drawer, Form Validation, CAPTCHA, Modals & Dynamic Fallback
 */

document.addEventListener('DOMContentLoaded', () => {
  'use strict';

  // 1. Mobile Navigation Controls
  const mobileNavToggle = document.getElementById('mobileNavToggle');
  const mobileNavDrawer = document.getElementById('mobileNavDrawer');
  const mobileNavClose = document.getElementById('mobileNavClose');
  const mobileNavOverlay = document.getElementById('mobileNavOverlay');
  const mobileNavLinks = document.querySelectorAll('.mobile-nav-links a');

  function openMobileNav() {
    mobileNavDrawer.classList.add('open');
    mobileNavOverlay.classList.add('open');
    document.body.style.overflow = 'hidden';
  }

  function closeMobileNav() {
    mobileNavDrawer.classList.remove('open');
    mobileNavOverlay.classList.remove('open');
    document.body.style.overflow = '';
  }

  if (mobileNavToggle) mobileNavToggle.addEventListener('click', openMobileNav);
  if (mobileNavClose) mobileNavClose.addEventListener('click', closeMobileNav);
  if (mobileNavOverlay) mobileNavOverlay.addEventListener('click', closeMobileNav);

  mobileNavLinks.forEach(link => {
    link.addEventListener('click', closeMobileNav);
  });

  // 2. Active Link Highlighting & Sticky Nav Scroll Effect
  const header = document.querySelector('.site-header');
  const sections = document.querySelectorAll('section[id]');
  const navLinks = document.querySelectorAll('.nav-link');

  window.addEventListener('scroll', () => {
    if (window.scrollY > 50) {
      header.style.boxShadow = '0 6px 20px rgba(0,0,0,0.3)';
    } else {
      header.style.boxShadow = 'none';
    }
  });

  const observerOptions = {
    root: null,
    rootMargin: '-20% 0px -70% 0px',
    threshold: 0
  };

  const sectionObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const id = entry.target.getAttribute('id');
        navLinks.forEach(link => {
          if (link.getAttribute('href') === `#${id}`) {
            link.classList.add('active');
          } else {
            link.classList.remove('active');
          }
        });
      }
    });
  }, observerOptions);

  sections.forEach(section => sectionObserver.observe(section));

  // 3. Dynamic Anti-Spam Math CAPTCHA
  let captchaNum1 = 0;
  let captchaNum2 = 0;
  let captchaExpected = 0;

  function generateCaptcha() {
    const qElem = document.getElementById('captchaQuestion');
    const hiddenExpectedElem = document.getElementById('captchaExpected');
    if (!qElem || !hiddenExpectedElem) return;

    captchaNum1 = Math.floor(Math.random() * 9) + 1; // 1 to 9
    captchaNum2 = Math.floor(Math.random() * 9) + 1; // 1 to 9
    captchaExpected = captchaNum1 + captchaNum2;

    qElem.textContent = `What is ${captchaNum1} + ${captchaNum2}?`;
    hiddenExpectedElem.value = captchaExpected;
  }

  generateCaptcha();

  // 4. Toast Notification System
  function showToast(message, type = 'success') {
    let toastContainer = document.getElementById('toastContainer');
    if (!toastContainer) {
      toastContainer = document.createElement('div');
      toastContainer.id = 'toastContainer';
      toastContainer.className = 'toast-container';
      document.body.appendChild(toastContainer);
    }

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
      <span>${type === 'success' ? '✓' : '⚠️'}</span>
      <span>${escapeHtml(message)}</span>
    `;

    toastContainer.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(100%)';
      setTimeout(() => toast.remove(), 300);
    }, 4500);
  }

  // Helper function to escape HTML on client side (XSS Prevention)
  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;');
  }

  // 5. Contact Form Submission with Hybrid Express & Static GitHub Pages Support
  const contactForm = document.getElementById('ssrContactForm');
  if (contactForm) {
    contactForm.addEventListener('submit', async (e) => {
      e.preventDefault();

      const nameInput = document.getElementById('formName');
      const phoneInput = document.getElementById('formPhone');
      const serviceInput = document.getElementById('formService');
      const messageInput = document.getElementById('formMessage');
      const honeypotInput = document.getElementById('website_url_check');
      const captchaInput = document.getElementById('formCaptcha');
      const captchaExpectedInput = document.getElementById('captchaExpected');
      const submitBtn = contactForm.querySelector('button[type="submit"]');

      // Check Honeypot Field (Spam bot detection)
      if (honeypotInput && honeypotInput.value.trim() !== '') {
        showToast('Submission rejected.', 'error');
        return;
      }

      // Check Client Math CAPTCHA
      if (parseInt(captchaInput.value) !== parseInt(captchaExpectedInput.value)) {
        showToast('Incorrect security question answer. Please try again.', 'error');
        generateCaptcha();
        captchaInput.value = '';
        captchaInput.focus();
        return;
      }

      // Validate Phone Format (Indian Mobile 10-digits starting 6-9)
      const cleanPhone = phoneInput.value.trim().replace(/\s+/g, '');
      const phoneRegex = /^(?:\+91[\s-]?)?[6-9]\d{9}$/;
      if (!phoneRegex.test(cleanPhone)) {
        showToast('Please enter a valid 10-digit Indian mobile number (e.g. 9223567100).', 'error');
        phoneInput.focus();
        return;
      }

      // Disable button during call
      submitBtn.disabled = true;
      submitBtn.innerHTML = 'Sending Security Request...';

      try {
        const payload = {
          name: nameInput.value.trim(),
          phone: cleanPhone,
          service: serviceInput.value,
          message: messageInput.value.trim(),
          honeypot: honeypotInput ? honeypotInput.value : '',
          captchaAnswer: captchaInput.value,
          captchaExpected: captchaExpectedInput.value
        };

        let response = null;
        try {
          response = await fetch('/api/contact', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
          });
        } catch (fetchErr) {
          console.warn('Backend API unreached. Operating in standalone client mode.');
        }

        if (response && response.ok) {
          const result = await response.json();
          showToast(result.message, 'success');
        } else {
          // Client-side fallback message & WhatsApp option for static GitHub Pages hosting
          const successMsg = `Thank you ${escapeHtml(payload.name)}! Your request for ${escapeHtml(payload.service)} has been recorded. Our team will contact you shortly at ${escapeHtml(cleanPhone)}.`;
          showToast(successMsg, 'success');

          setTimeout(() => {
            const waMsg = encodeURIComponent(`Hi, I submitted a security guard request for ${payload.service}.\nName: ${payload.name}\nPhone: ${cleanPhone}\nDetails: ${payload.message}`);
            window.open(`https://wa.me/919223567100?text=${waMsg}`, '_blank');
          }, 1200);
        }
        contactForm.reset();
        generateCaptcha();
      } catch (err) {
        showToast('Thank you! Your request has been recorded. Call us at +91 92235 67100.', 'success');
        contactForm.reset();
        generateCaptcha();
      } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '🛡️ Send Security Request & Call Me Back';
      }
    });
  }

  // 6. Modal Popup Lightbox for Official Documents & Site Survey Estimator
  const modalBackdrop = document.getElementById('modalBackdrop');
  const modalTitle = document.getElementById('modalTitle');
  const modalBody = document.getElementById('modalBody');
  const modalClose = document.getElementById('modalClose');

  function openModal(title, contentHtml) {
    if (!modalBackdrop) return;
    modalTitle.textContent = title;
    modalBody.innerHTML = contentHtml;
    modalBackdrop.classList.add('active');
    document.body.style.overflow = 'hidden';
  }

  function closeModal() {
    if (!modalBackdrop) return;
    modalBackdrop.classList.remove('active');
    document.body.style.overflow = '';
  }

  if (modalClose) modalClose.addEventListener('click', closeModal);
  if (modalBackdrop) {
    modalBackdrop.addEventListener('click', (e) => {
      if (e.target === modalBackdrop) closeModal();
    });
  }

  // Global triggers for image modal previews
  document.querySelectorAll('[data-modal-image]').forEach(trigger => {
    trigger.addEventListener('click', (e) => {
      e.preventDefault();
      const imgSrc = trigger.getAttribute('data-modal-image');
      const imgTitle = trigger.getAttribute('data-modal-title') || 'Official Document';
      openModal(imgTitle, `
        <div style="text-align: center;">
          <img src="${imgSrc}" alt="${imgTitle}" style="max-width: 100%; max-height: 70vh; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.2);">
        </div>
      `);
    });
  });

  // Free Site Survey Request Modal Trigger
  document.querySelectorAll('[data-open-survey-modal]').forEach(trigger => {
    trigger.addEventListener('click', (e) => {
      e.preventDefault();
      openModal('Request Free Site Survey & Security Audit', `
        <p style="margin-bottom: 1rem; color: #475569;">Our senior security officers will visit your premises in Thane / MMR to conduct a thorough security assessment and prepare a tailored manpower proposal.</p>
        <div style="background: #F8FAFC; padding: 1rem; border-radius: 8px; border: 1px solid #E2E8F0; margin-bottom: 1rem;">
          <h4 style="color: #0A1F44; margin-bottom: 0.5rem;">Direct Immediate Contact:</h4>
          <p>📞 Phone: <strong><a href="tel:+919223567100" style="color:#0A1F44">+91 92235 67100</a></strong> / <strong><a href="tel:+917021703133" style="color:#0A1F44">+91 70217 03133</a></strong></p>
          <p>💬 WhatsApp: <strong><a href="https://wa.me/919223567100?text=Hi,%20I%20want%20to%20schedule%20a%20Free%20Site%20Survey%20for%20my%20property." target="_blank" rel="noopener" style="color:#25D366">Chat on WhatsApp</a></strong></p>
          <p>📍 Location: FA-34, Lake City Mall, Kapurbavdi Junction, Thane (W)</p>
        </div>
        <button class="btn btn-primary-gold" onclick="document.getElementById('contact').scrollIntoView({behavior:'smooth'}); document.getElementById('modalClose').click();" style="width: 100%;">
          Fill Quick Callback Form
        </button>
      `);
    });
  });
});
