// test-config.js - Level 10/16 Test Suite Metadata Definition
const TEST_SUITE_CONFIG = [
  {
    id: "TC01",
    name: "Safe HTTPS Test",
    file: "/test-pages/safe-https-test.html",
    category: "Safe Baseline",
    expectedIndicator: "No page-structure indicators (page score 0)",
    expectedClassification: "SAFE or SUSPICIOUS",
    description: "Standard page with normal content, no forms, no password fields, and no external links. Served over plain HTTP from 127.0.0.1, so the URL rules alone score 50 and the page lands at the SUSPICIOUS boundary. The page score must be 0."
  },
  {
    id: "TC02",
    name: "Normal Login Form (False Positive Test)",
    file: "/test-pages/normal-login-test.html",
    category: "False Positive Validation",
    expectedIndicator: "Password field detected (Same-Origin Form)",
    expectedClassification: "SAFE or SUSPICIOUS",
    description: "Harmless local login page with a password input submitting locally (same-origin). Tests that normal login forms are never classified DANGEROUS. The local HTTP/IP address keeps it at SUSPICIOUS at most."
  },
  {
    id: "TC03",
    name: "HTTP Indicator Test",
    file: "/test-pages/http-test.html",
    category: "URL Risk Rule",
    expectedIndicator: "Website is not using HTTPS (+20)",
    expectedClassification: "SAFE or SUSPICIOUS",
    description: "Harmless local page testing non-HTTPS protocol risk contribution."
  },
  {
    id: "TC04",
    name: "IP Address Hostname Test",
    file: "/test-pages/ip-url-test.html",
    category: "URL Risk Rule",
    expectedIndicator: "IP address used instead of domain (+30)",
    expectedClassification: "SUSPICIOUS",
    description: "Demonstrates and tests IP address hostname indicator recognition."
  },
  {
    id: "TC05",
    name: "Long URL Test",
    file: "/test-pages/long-url-test.html",
    category: "URL Risk Rule",
    expectedIndicator: "URL is unusually long (+15)",
    expectedClassification: "SAFE or SUSPICIOUS",
    description: "Harmless page with extended URL query parameter string (> 100 characters)."
  },
  {
    id: "TC06",
    name: "Suspicious Keyword Test",
    file: "/test-pages/suspicious-keyword-test.html",
    category: "URL & DOM Keyword Rule",
    expectedIndicator: "Page title contains a sensitive security-related keyword (+5)",
    expectedClassification: "SAFE or SUSPICIOUS",
    description: "Harmless local test page containing security keywords (login, verify, account) in title and URL."
  },
  {
    id: "TC07",
    name: "Password Field Form Test",
    file: "/test-pages/password-form-test.html",
    category: "DOM Structural Rule",
    expectedIndicator: "Page contains a password field (+10)",
    expectedClassification: "SAFE or SUSPICIOUS",
    description: "Harmless password input form with submission disabled (event.preventDefault())."
  },
  {
    id: "TC08",
    name: "External Form Action Test",
    file: "/test-pages/external-form-test.html",
    category: "DOM Structural Rule",
    expectedIndicator: "Form submits data to a different domain (+25)",
    expectedClassification: "SUSPICIOUS",
    description: "Harmless form pointing to an external domain (https://example.invalid/test) with submission prevented."
  },
  {
    id: "TC09",
    name: "Multiple Indicators Test (High-Risk Simulation)",
    file: "/test-pages/multiple-indicators-test.html",
    category: "Multi-Indicator Simulation",
    expectedIndicator: "Multiple accumulated risk indicators",
    expectedClassification: "DANGEROUS",
    description: "Harmless page combining password field, external form action, suspicious keyword, external iframe, and hidden link."
  },
  {
    id: "TC10",
    name: "Critical Risk Combination Test (Dangerous Classification)",
    file: "/test-pages/critical-risk-test.html",
    category: "High-Risk Security Test",
    expectedIndicator: "Accumulated High Risk (Password Field + External Form + Security Keyword + Hidden Link)",
    expectedClassification: "DANGEROUS",
    description: "Harmless local test page specifically engineered with multiple simultaneous high-risk structural features to naturally trigger the DANGEROUS threshold (Risk Score >= 60)."
  }
];

if (typeof module !== "undefined") {
  module.exports = TEST_SUITE_CONFIG;
}
