/**
 * Smart Suraksha Rakshak (SSR) - HTTPS Express Server & Security API
 * Serves exclusively over HTTPS with self-signed SSL/TLS certificate,
 * HSTS headers, CSP upgrade-insecure-requests, and auto-redirect from HTTP to HTTPS.
 */

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const http = require('http');
const https = require('https');
const selfsigned = require('selfsigned');

const app = express();
const HTTPS_PORT = process.env.PORT || 3000;
const HTTP_PORT = process.env.HTTP_PORT || 8080;

// 1. Ensure SSL Certificate & Private Key exist (Generate if missing)
const certPath = path.join(__dirname, 'cert.pem');
const keyPath = path.join(__dirname, 'key.pem');

async function ensureSSLCertificates() {
  if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
    console.log('[HTTPS SETUP] Generating self-signed SSL/TLS certificate for localhost...');
    const attrs = [
      { name: 'commonName', value: 'localhost' },
      { name: 'organizationName', value: 'Smart Suraksha Rakshak' }
    ];
    const pems = await selfsigned.generate(attrs, {
      days: 365,
      keySize: 2048,
      algorithm: 'sha256'
    });
    fs.writeFileSync(keyPath, pems.private);
    fs.writeFileSync(certPath, pems.cert);
    console.log('[HTTPS SETUP] SSL Certificate (cert.pem) and Private Key (key.pem) created successfully.');
  }
}

// Body parsing middleware
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// 2. HTTPS Enforcement Middleware
app.use((req, res, next) => {
  const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https' || req.protocol === 'https';
  if (!isSecure && process.env.NODE_ENV === 'production') {
    const host = req.headers.host ? req.headers.host.split(':')[0] : 'localhost';
    return res.redirect(301, `https://${host}:${HTTPS_PORT}${req.url}`);
  }
  next();
});

// 3. Configure Helmet for strict Security Headers & HTTPS Enforcement
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          "'self'",
          "https://cdnjs.cloudflare.com",
          "https://fonts.googleapis.com"
        ],
        styleSrc: [
          "'self'",
          "'unsafe-inline'",
          "https://fonts.googleapis.com",
          "https://cdnjs.cloudflare.com"
        ],
        fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
        imgSrc: ["'self'", "data:", "blob:", "https:"],
        connectSrc: ["'self'"],
        frameAncestors: ["'none'"], // Disallow iframe embedding (X-Frame-Options: DENY)
        objectSrc: ["'none'"],
        scriptSrcAttr: ["'none'"],
        upgradeInsecureRequests: [] // Forces browser to convert any http:// subrequests to https://
      }
    },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" }
  })
);

// 4. Additional Security Headers (HSTS, No-Sniff, Referrer Policy)
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader(
    'Strict-Transport-Security',
    'max-age=31536000; includeSubDomains; preload'
  );
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});

// 5. CORS configuration
app.use(
  cors({
    origin: process.env.NODE_ENV === 'production' ? false : '*',
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type']
  })
);

// 6. Global Rate Limiter for Static Files
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { status: 429, message: 'Too many requests from this IP, please try again later.' }
});
app.use(globalLimiter);

// 7. Strict Rate Limiter for Contact Form API
const contactFormLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many submission attempts. Please wait 15 minutes before trying again or call us directly at +91 92235 67100.'
  }
});

// Helper for server-side HTML sanitization (XSS prevention)
function sanitizeInput(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;')
    .trim();
}

// 8. API Endpoint: Contact & Site Survey Request Handler
app.post('/api/contact', contactFormLimiter, (req, res) => {
  try {
    const { name, phone, service, message, honeypot, captchaAnswer, captchaExpected } = req.body;

    // Honeypot check: If the hidden honeypot field is filled, it's a bot
    if (honeypot && honeypot.trim() !== '') {
      return res.status(200).json({
        success: true,
        message: 'Thank you! Your request has been received.'
      });
    }

    // CAPTCHA verification check
    if (parseInt(captchaAnswer) !== parseInt(captchaExpected)) {
      return res.status(400).json({
        success: false,
        message: 'Security math check failed. Please re-enter the correct answer.'
      });
    }

    // Input Sanitization
    const cleanName = sanitizeInput(name);
    const cleanPhone = sanitizeInput(phone);
    const cleanService = sanitizeInput(service || 'General Inquiry');
    const cleanMessage = sanitizeInput(message || '');

    // Validation
    const validationErrors = [];

    if (!cleanName || cleanName.length < 2 || cleanName.length > 50) {
      validationErrors.push('Please enter a valid full name (2-50 characters).');
    }

    const phoneRegex = /^(?:\+91[\s-]?)?[6-9]\d{9}$/;
    if (!cleanPhone || !phoneRegex.test(cleanPhone.replace(/\s+/g, ''))) {
      validationErrors.push('Please enter a valid 10-digit mobile number (e.g. 9223567100).');
    }

    if (cleanMessage.length > 1000) {
      validationErrors.push('Message cannot exceed 1000 characters.');
    }

    if (validationErrors.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed.',
        errors: validationErrors
      });
    }

    console.log(`[CONTACT FORM SUBMISSION] Name: ${cleanName} | Phone: ${cleanPhone} | Service: ${cleanService}`);

    return res.status(200).json({
      success: true,
      message: `Thank you ${cleanName}! Your request for ${cleanService} has been recorded. Our team will contact you shortly at ${cleanPhone}.`
    });
  } catch (err) {
    console.error('Error handling contact form:', err);
    return res.status(500).json({
      success: false,
      message: 'A server error occurred. Please call +91 92235 67100 directly.'
    });
  }
});

// 9. Serve Static Front-End Files
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: process.env.NODE_ENV === 'production' ? '1d' : '0',
  etag: true
}));

// Fallback to index.html for SPA routing
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 10. Start HTTPS & HTTP Servers
async function startServer() {
  await ensureSSLCertificates();

  const sslOptions = {
    key: fs.readFileSync(keyPath),
    cert: fs.readFileSync(certPath)
  };

  const httpsServer = https.createServer(sslOptions, app);
  httpsServer.listen(HTTPS_PORT, () => {
    console.log(`\n=============================================================`);
    console.log(`🔒 [SSR SECURITY WEBSITE] HTTPS SERVER RUNNING LOCALLY`);
    console.log(`👉 https://localhost:${HTTPS_PORT}`);
    console.log(`=============================================================\n`);
  });

  const httpApp = express();
  httpApp.use((req, res) => {
    const host = req.headers.host ? req.headers.host.split(':')[0] : 'localhost';
    const redirectUrl = `https://${host}:${HTTPS_PORT}${req.url}`;
    return res.redirect(301, redirectUrl);
  });

  const httpServer = http.createServer(httpApp);
  httpServer.listen(HTTP_PORT, () => {
    console.log(`🔄 [HTTP-TO-HTTPS REDIRECT] Running on http://localhost:${HTTP_PORT} -> Redirecting to https://localhost:${HTTPS_PORT}\n`);
  });
}

startServer().catch(err => {
  console.error('Failed to start HTTPS server:', err);
});
