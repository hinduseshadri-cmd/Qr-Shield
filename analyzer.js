'use strict';
/**
 * QR Shield analysis engine (rule-based scoring).
 * Returns { verdict: 'safe'|'suspicious'|'malicious', score, type, findings[], summary }
 */

const SUSPICIOUS_TLDS = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'click', 'zip', 'mov', 'work', 'rest', 'icu', 'buzz'];
const PHISH_KEYWORDS = ['login', 'signin', 'verify', 'verification', 'bank', 'free', 'click', 'win', 'prize',
  'secure', 'account', 'update', 'confirm', 'password', 'wallet', 'gift', 'claim', 'reward', 'suspend',
  'unlock', 'bonus', 'urgent', 'kyc', 'otp', 'refund', 'lottery'];
const SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly',
  'cutt.ly', 'shorturl.at', 'tiny.cc', 'rb.gy', 'qrco.de', 'bl.ink'];
const BRANDS = ['paypal', 'google', 'microsoft', 'apple', 'amazon', 'facebook', 'instagram', 'netflix',
  'paytm', 'phonepe', 'gpay', 'sbi', 'hdfc', 'icici', 'axis', 'whatsapp', 'flipkart'];
const DANGEROUS_EXT = ['apk', 'exe', 'msi', 'bat', 'cmd', 'scr', 'js', 'vbs', 'jar', 'dmg', 'pkg', 'ps1', 'sh', 'iso'];

const THRESHOLDS = {
  low: { suspicious: 30, malicious: 65 },
  medium: { suspicious: 20, malicious: 45 },
  high: { suspicious: 10, malicious: 30 },
};

function isIPv4(host) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(host) && host.split('.').every((n) => Number(n) <= 255);
}
function isIPv6(host) { return host.startsWith('[') && host.endsWith(']'); }
function isDecimalOrHexIP(host) { return /^(0x[0-9a-f]+|\d{8,10})$/i.test(host); }

function registrableDomain(host) {
  const parts = host.split('.');
  return parts.slice(-2).join('.');
}

function classify(content) {
  const c = content.trim();
  if (/^https?:\/\//i.test(c)) return 'url';
  if (/^(upi|paytm|phonepe|tez):\/\//i.test(c)) return 'payment';
  if (/^wifi:/i.test(c)) return 'wifi';
  if (/^(sms|smsto|mms):/i.test(c)) return 'sms';
  if (/^tel:/i.test(c)) return 'phone';
  if (/^mailto:/i.test(c)) return 'email';
  if (/^(begin:vcard|mecard:)/i.test(c)) return 'contact';
  if (/^(geo:|begin:vevent)/i.test(c)) return 'other';
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(c)) return 'other-scheme';
  if (/^(www\.)?[a-z0-9-]+(\.[a-z0-9-]+)+(\/\S*)?$/i.test(c) && !/\s/.test(c)) return 'bare-domain';
  return 'text';
}

function analyzeUrl(raw, add) {
  let u;
  try {
    u = new URL(/^https?:\/\//i.test(raw) ? raw : 'http://' + raw);
  } catch {
    add(40, 'Malformed URL', 'The URL cannot be parsed and may be crafted to evade filters.');
    return;
  }
  const host = u.hostname.toLowerCase();
  const full = raw.toLowerCase();
  const hadScheme = /^https?:\/\//i.test(raw);

  // Protocol
  if (u.protocol === 'http:') {
    add(hadScheme ? 45 : 20, 'Non-HTTPS connection', 'Uses unencrypted HTTP; traffic can be intercepted or altered.');
  } else {
    add(-5, 'HTTPS in use', 'Connection is encrypted (this alone does not prove the site is trustworthy).', 'good');
  }

  // IP host
  if (isIPv4(host) || isIPv6(host) || isDecimalOrHexIP(host)) {
    add(45, 'IP address instead of domain', 'Legitimate services rarely use raw IP addresses; common in phishing and malware hosting.');
  }

  // Credentials in URL
  if (u.username || u.password || raw.replace(/^https?:\/\//i, '').split('/')[0].includes('@')) {
    add(40, 'Credentials / "@" in URL', 'The "@" trick hides the real destination behind a trusted-looking name.');
  }

  // Punycode / non-ASCII
  if (host.includes('xn--') || /[^\x00-\x7f]/.test(raw)) {
    add(30, 'Punycode / lookalike characters', 'Internationalised characters can imitate well-known brands (homograph attack).');
  }

  // TLD
  const tld = host.split('.').pop();
  if (!isIPv4(host) && SUSPICIOUS_TLDS.includes(tld)) {
    add(25, `Suspicious TLD (.${tld})`, 'This top-level domain is heavily abused for throwaway phishing sites.');
  }

  // Shorteners
  if (SHORTENERS.includes(host) || SHORTENERS.includes(registrableDomain(host))) {
    add(20, 'URL shortener', 'The real destination is hidden behind a redirect and cannot be verified.');
  }

  // Subdomain depth
  const labels = host.split('.');
  if (!isIPv4(host) && labels.length > 4) {
    add(15, 'Excessive subdomains', `${labels.length} domain levels; attackers nest subdomains to fake a trusted name.`);
  }

  // Hyphens
  if ((host.match(/-/g) || []).length >= 3) {
    add(12, 'Many hyphens in domain', 'Domains like "secure-login-bank-verify.com" are typical for phishing.');
  }

  // Brand impersonation: brand appears in host but not as registrable domain
  const reg = registrableDomain(host);
  for (const b of BRANDS) {
    if (host.includes(b) && !reg.startsWith(b + '.') ) {
      add(25, `Possible "${b}" impersonation`, 'A well-known brand name appears in a domain that does not belong to it.');
      break;
    }
  }

  // Keywords (host + path + query)
  const hay = (host + u.pathname + u.search).toLowerCase();
  const hits = PHISH_KEYWORDS.filter((k) => new RegExp('(^|[^a-z])' + k).test(hay));
  if (hits.length) {
    add(Math.min(10 + hits.length * 6, 30), 'Phishing keywords', `Found: ${hits.slice(0, 8).join(', ')}.`);
  }

  // Dangerous file download
  const ext = (u.pathname.split('.').pop() || '').toLowerCase();
  if (u.pathname.includes('.') && DANGEROUS_EXT.includes(ext)) {
    add(40, `Downloads a .${ext} file`, 'Executable or installer files delivered via QR code are a common malware vector.');
  }

  // Non-standard port
  if (u.port && !['80', '443'].includes(u.port)) {
    add(15, `Non-standard port (${u.port})`, 'Unusual ports are rarely used by legitimate public websites.');
  }

  // Length
  if (raw.length > 120) {
    add(15, 'Very long URL', `${raw.length} characters; long URLs often hide malicious parameters.`);
  } else if (raw.length < 12) {
    add(8, 'Very short URL', 'Extremely short URLs give little context and may be redirectors.');
  }

  // Encoding / redirect parameters
  if ((full.match(/%[0-9a-f]{2}/g) || []).length > 6) {
    add(15, 'Heavy percent-encoding', 'Obfuscated characters can hide the true target or payload.');
  }
  if (/[?&](url|redirect|redir|next|goto|return|continue|dest)=https?/i.test(raw)) {
    add(20, 'Open-redirect parameter', 'The link forwards you to another site specified in the query string.');
  }
  if (/(javascript|data|vbscript):/i.test(u.search + u.hash)) {
    add(40, 'Script injection pattern', 'Query contains a script/data scheme often used in XSS attacks.');
  }
}

function analyzeContent(content, opts = {}) {
  const sensitivity = THRESHOLDS[opts.sensitivity] ? opts.sensitivity : 'medium';
  const th = THRESHOLDS[sensitivity];
  const raw = String(content || '').trim();
  const findings = [];
  let score = 0;

  const add = (pts, title, detail, level) => {
    score += pts;
    findings.push({
      title, detail, points: pts,
      level: level || (pts >= 35 ? 'malicious' : 'suspicious'),
    });
  };

  const type = classify(raw);

  if (!raw) {
    add(0, 'Empty content', 'The QR code contained no data.', 'good');
  } else if (type === 'url' || type === 'bare-domain') {
    analyzeUrl(raw, add);
  } else if (type === 'payment') {
    add(20, 'Payment request QR', 'Payment QR codes can be swapped or tampered with. Check payee name and amount before paying.');
    if (/[?&]am=/i.test(raw)) add(10, 'Pre-filled amount', 'A payment amount is set in the code; confirm it is what you expect.');
    if (/[?&]pa=[^&]*@(?:ybl|paytm|okaxis)?/i.test(raw) === false) {
      add(5, 'Unrecognised payee format', 'The payee address does not look like a standard UPI ID.');
    }
  } else if (type === 'wifi') {
    add(20, 'Wi-Fi configuration', 'Joining an unknown network exposes your traffic. Only connect to networks you trust.');
    if (/T:\s*nopass/i.test(raw)) add(15, 'Open network', 'No password: traffic is unencrypted.');
  } else if (type === 'sms') {
    add(25, 'Pre-written SMS', 'Scanning may prepare a message to a premium or unknown number.');
  } else if (type === 'phone') {
    add(15, 'Phone number', 'Calling unknown numbers can lead to vishing or premium-rate charges.');
  } else if (type === 'email') {
    add(10, 'Email composition', 'Opens a pre-filled email; verify recipient and body before sending.');
  } else if (type === 'other-scheme') {
    const scheme = raw.split(':')[0].toLowerCase();
    add(35, `Custom app scheme (${scheme}://)`, 'Custom schemes can trigger apps or intents on your device without warning.');
  } else if (type === 'contact') {
    add(8, 'Contact card', 'Verify the details before saving to your contacts.');
  } else {
    // Plain text – scan for embedded URLs
    const m = raw.match(/https?:\/\/\S+/i);
    if (m) {
      add(10, 'Text with embedded link', 'The text contains a link that was analysed below.');
      analyzeUrl(m[0], add);
    } else {
      add(0, 'Plain text', 'No links or actions detected.', 'good');
    }
  }

  if (/<script|onerror\s*=|onload\s*=/i.test(raw)) {
    add(40, 'Embedded script', 'Content contains HTML/JS that could execute in a vulnerable reader.');
  }

  score = Math.max(0, Math.min(100, Math.round(score)));
  const verdict = score >= th.malicious ? 'malicious' : score >= th.suspicious ? 'suspicious' : 'safe';

  const bad = findings.filter((f) => f.level !== 'good');
  const summary = {
    safe: 'No significant risk indicators were found. It is still wise to verify the destination before entering personal data.',
    suspicious: `Detected ${bad.length} warning sign(s). Proceed with caution and do not enter credentials or payment details.`,
    malicious: `Detected ${bad.length} serious risk indicator(s). Do NOT open this link or follow its instructions.`,
  }[verdict];

  return { verdict, score, type, sensitivity, findings, summary };
}

module.exports = { analyzeContent, THRESHOLDS };
