/**
 * @fileoverview Backend API client for the Email Security Scorer add-on.
 *
 * This file handles all communication between the Gmail Add-on and the
 * FastAPI backend. It is the only place in the add-on that makes outbound
 * HTTP requests.
 *
 * Authentication
 * ==============
 * Every request includes an ``Authorization: Bearer <id_token>`` header
 * using ``ScriptApp.getIdentityToken()``. This is a Google-signed OIDC
 * token that the backend verifies via JWKS before processing the request.
 *
 * Error handling
 * ==============
 * * Network errors and timeouts throw descriptive ``Error`` objects that
 *   the ``catch`` block in ``analyzeEmailAction`` (Code.gs) can display.
 * * HTTP errors (4xx, 5xx) are detected via ``response.getResponseCode()``
 *   and thrown as descriptive errors.
 * * ``muteHttpExceptions: true`` is set so that UrlFetchApp does not throw
 *   on non-2xx responses — we handle them ourselves for better messages.
 *
 * SSRF note
 * =========
 * The add-on only ever calls ``API_ANALYZE_URL`` and ``API_HEALTH_URL``
 * (defined in Constants.gs). It never fetches URLs extracted from email
 * content.
 */

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Calls the backend ``POST /v1/analyze`` endpoint with the given email payload.
 *
 * @param {{
 *   from_address: string,
 *   subject: string,
 *   body: string,
 *   headers: Object.<string, string>,
 *   attachment_metadata: Array.<Object>
 * }} payload - The email data extracted by EmailExtractor.gs.
 *
 * @returns {{
 *   final_score: number,
 *   risk_level: string,
 *   deterministic_score: number,
 *   deterministic_findings: Array.<Object>,
 *   llm_available: boolean,
 *   llm_gated: boolean,
 *   llm_result: Object|null,
 *   semantic_warning: string,
 *   schema_version: string
 * }} The parsed JSON verdict from the backend.
 *
 * @throws {Error} On network failure, timeout, or non-200 HTTP response.
 */
function callAnalyzeApi(payload) {
  var idToken = _getIdentityToken();

  var options = {
    method:             'post',
    contentType:        'application/json',
    payload:            JSON.stringify(payload),
    muteHttpExceptions: true,
    headers: {
      'Authorization': 'Bearer ' + idToken,
      'X-Request-Source': 'gmail-addon-v1'
    }
  };

  var response;
  try {
    response = UrlFetchApp.fetch(API_ANALYZE_URL, options);
  } catch (networkErr) {
    throw new Error(
      'Network error contacting the analysis backend: ' +
      (networkErr.message || String(networkErr)) +
      '. Check that the backend is running and reachable.'
    );
  }

  return _parseResponse(response, API_ANALYZE_URL);
}

/**
 * Calls the backend ``GET /v1/healthz`` endpoint to verify connectivity.
 *
 * Useful for debugging — call this from the Apps Script editor to confirm
 * the backend URL is correct before testing the full flow.
 *
 * @returns {{status: string, [key: string]: *}} The parsed health response.
 * @throws {Error} On network failure or non-200 HTTP response.
 */
function callHealthApi() {
  var options = {
    method:             'get',
    muteHttpExceptions: true
  };

  var response;
  try {
    response = UrlFetchApp.fetch(API_HEALTH_URL, options);
  } catch (networkErr) {
    throw new Error(
      'Network error contacting the health endpoint: ' +
      (networkErr.message || String(networkErr))
    );
  }

  return _parseResponse(response, API_HEALTH_URL);
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/**
 * Retrieves a Google-signed OIDC identity token for the current user.
 *
 * The token is used as a Bearer token in the Authorization header so the
 * backend can verify the caller's identity via Google's JWKS endpoint.
 *
 * @returns {string} The OIDC identity token string.
 * @throws {Error} If the token cannot be obtained.
 * @private
 */
function _getIdentityToken() {
  try {
    var token = ScriptApp.getIdentityToken();
    if (!token) {
      throw new Error('ScriptApp.getIdentityToken() returned null or empty.');
    }
    return token;
  } catch (err) {
    throw new Error(
      'Failed to obtain Google identity token: ' +
      (err.message || String(err)) +
      '. Ensure the add-on has the required OAuth scopes.'
    );
  }
}

/**
 * Parses a UrlFetchApp response, throwing descriptive errors on failure.
 *
 * @param {UrlFetchApp.HTTPResponse} response - The HTTP response object.
 * @param {string} url - The URL that was called (for error messages).
 * @returns {Object} The parsed JSON response body.
 * @throws {Error} On non-2xx status code or invalid JSON.
 * @private
 */
function _parseResponse(response, url) {
  var statusCode = response.getResponseCode();
  var responseText = response.getContentText();

  // ── HTTP error handling ───────────────────────────────────────────────
  if (statusCode === 401) {
    throw new Error(
      'Authentication failed (HTTP 401). ' +
      'The backend rejected the Google identity token. ' +
      'Ensure the backend is configured with the correct Google Client ID.'
    );
  }

  if (statusCode === 422) {
    throw new Error(
      'Request validation failed (HTTP 422). ' +
      'The email data did not pass backend validation. ' +
      'Details: ' + responseText.substring(0, 300)
    );
  }

  if (statusCode === 429) {
    throw new Error(
      'Rate limit exceeded (HTTP 429). ' +
      'You have sent too many requests. Please wait a moment and try again.'
    );
  }

  if (statusCode >= 500) {
    throw new Error(
      'Backend server error (HTTP ' + statusCode + '). ' +
      'The analysis service encountered an internal error. ' +
      'Please try again in a few seconds.'
    );
  }

  if (statusCode < 200 || statusCode >= 300) {
    throw new Error(
      'Unexpected HTTP response ' + statusCode + ' from ' + url + '. ' +
      'Response: ' + responseText.substring(0, 200)
    );
  }

  // ── JSON parsing ──────────────────────────────────────────────────────
  try {
    return JSON.parse(responseText);
  } catch (parseErr) {
    throw new Error(
      'Failed to parse backend response as JSON. ' +
      'Raw response (first 200 chars): ' + responseText.substring(0, 200)
    );
  }
}
