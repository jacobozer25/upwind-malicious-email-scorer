/**
 * @fileoverview Global constants for the Email Security Scorer add-on.
 *
 * All configuration values that may change between environments are defined
 * here so they can be updated in a single place.
 *
 * IMPORTANT: Do NOT commit real API keys or secrets to this file.
 * Use Google Apps Script's built-in Properties Service for secrets:
 *   PropertiesService.getScriptProperties().getProperty('MY_SECRET')
 */

// ---------------------------------------------------------------------------
// Backend API
// ---------------------------------------------------------------------------

/**
 * Base URL for the Email Security Scorer backend API.
 *
 * For local development, replace with your ngrok forwarding URL:
 *   https://YOUR_NGROK_ID.ngrok-free.app/v1
 *
 * For production, replace with your deployed Cloud Run / App Engine URL:
 *   https://email-scorer.your-domain.com/v1
 *
 * @const {string}
 */
var API_BASE_URL = 'https://litigate-woven-grooving.ngrok-free.dev/v1';

/**
 * Full URL for the analyze endpoint.
 * @const {string}
 */
var API_ANALYZE_URL = API_BASE_URL + '/analyze';

/**
 * Full URL for the health-check endpoint.
 * @const {string}
 */
var API_HEALTH_URL = API_BASE_URL + '/healthz';

// ---------------------------------------------------------------------------
// Request configuration
// ---------------------------------------------------------------------------

/**
 * Timeout for backend API calls in milliseconds.
 * Apps Script's UrlFetchApp has a hard limit of 30 seconds.
 * @const {number}
 */
var API_TIMEOUT_MS = 15000;

/**
 * Maximum body size (in characters) to send to the backend.
 * Mirrors the 1 MB cap enforced by the backend schema.
 * @const {number}
 */
var MAX_BODY_CHARS = 500000; // ~500 KB of text

// ---------------------------------------------------------------------------
// UI constants
// ---------------------------------------------------------------------------

/**
 * Add-on display name shown in the Gmail sidebar header.
 * @const {string}
 */
var ADDON_NAME = 'Email Security Scorer';

/**
 * Risk level labels for display in the UI.
 * Keys match the `risk_level` values returned by the backend API.
 * @const {Object.<string, string>}
 */
var RISK_LEVEL_LABELS = {
  benign: '✅ Benign',
  suspicious: '⚠️ Suspicious',
  likely_malicious: '🔶 Likely Malicious',
  malicious: '🚨 Malicious'
};

/**
 * Risk level colors (hex) for score badge backgrounds.
 * @const {Object.<string, string>}
 */
var RISK_LEVEL_COLORS = {
  benign: '#34a853',          // Google green
  suspicious: '#fbbc04',      // Google yellow
  likely_malicious: '#fa7b17', // Google orange
  malicious: '#ea4335'        // Google red
};
