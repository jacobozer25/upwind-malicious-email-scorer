/**
 * @fileoverview Entry point for the Email Security Scorer Gmail Add-on.
 *
 * This file contains the two top-level trigger functions that Google Apps
 * Script calls directly:
 *
 *  - {@link onGmailMessage}  — contextual trigger, called when a Gmail
 *    message is opened. Returns the initial "welcome" card.
 *
 *  - {@link analyzeEmailAction} — action callback, called when the user
 *    clicks "Analyze Email". Extracts email data, calls the backend API,
 *    and returns a result card (or an error card on failure).
 *
 * ─────────────────────────────────────────────────────────────────────────
 * DEPLOYMENT REMINDER
 * ─────────────────────────────────────────────────────────────────────────
 * Before deploying this add-on you must enable the manifest file in the
 * Google Apps Script editor:
 *
 *   1. Open the Apps Script project at https://script.google.com
 *   2. Click the ⚙️ gear icon (Project Settings) in the left sidebar.
 *   3. Check "Show 'appsscript.json' manifest file in editor".
 *   4. The appsscript.json file will now appear in the file list.
 *   5. Paste the contents of addon/appsscript.json into that file.
 *   6. Deploy → Test deployments → Install for your account.
 *
 * ─────────────────────────────────────────────────────────────────────────
 * FILE LOAD ORDER
 * ─────────────────────────────────────────────────────────────────────────
 * Google Apps Script loads .gs files in alphabetical order within each
 * folder, with root-level files loaded last. The dependency order is:
 *
 *   lib/Constants.gs  →  ui/CardBuilder.gs  →  api/BackendClient.gs  →  Code.gs
 *
 * All globals defined in those files (ADDON_NAME, buildMainCard, etc.) are
 * available here because GAS uses a flat global namespace — no imports needed.
 * ─────────────────────────────────────────────────────────────────────────
 */

// ---------------------------------------------------------------------------
// Contextual trigger — called when a Gmail message is opened
// ---------------------------------------------------------------------------

/**
 * Gmail contextual trigger entry point.
 *
 * Called automatically by the Gmail Add-on runtime whenever the user opens
 * a message. Returns an array of cards to display in the sidebar.
 *
 * @param {Object} e - The event object provided by the Gmail Add-on runtime.
 * @param {Object} e.gmail - Gmail-specific event data.
 * @param {string} e.gmail.messageId - The ID of the currently open message.
 * @param {string} [e.gmail.accessToken] - OAuth access token for Gmail API calls.
 * @returns {CardService.Card[]} An array containing the main welcome card.
 */
function onGmailMessage(e) {
  var messageId = e.gmail.messageId;

  console.log('onGmailMessage triggered', { messageId: messageId });

  return [buildMainCard(messageId)];
}

// ---------------------------------------------------------------------------
// Action callback — called when the user clicks "Analyze Email"
// ---------------------------------------------------------------------------

/**
 * Action callback triggered when the user clicks the "Analyze Email" button.
 *
 * This function:
 *  1. Extracts the messageId from the action parameters.
 *  2. Fetches the email metadata from Gmail using the GmailApp service.
 *  3. Calls the backend API via {@link callAnalyzeApi} (BackendClient.gs).
 *  4. Returns a result card on success or an error card on failure.
 *
 * @param {Object} e - The action event object.
 * @param {Object} e.parameters - Parameters passed via Action.setParameters().
 * @param {string} e.parameters.messageId - The Gmail message ID to analyze.
 * @returns {CardService.ActionResponse} An action response that updates the
 *   current card with the analysis result.
 */
function analyzeEmailAction(e) {
  var messageId = e.parameters.messageId;

  console.log('analyzeEmailAction triggered', { messageId: messageId });

  try {
    // ── Step 1: Fetch email data from Gmail. ─────────────────────────────
    var emailData = _extractEmailData(messageId);

    // ── Step 2: Call the backend API. ────────────────────────────────────
    // callAnalyzeApi is defined in api/BackendClient.gs.
    // If BackendClient.gs is not yet implemented, this will throw a
    // ReferenceError — the catch block below will handle it gracefully.
    var verdict = callAnalyzeApi(emailData);

    // ── Step 3: Build and return the result card. ─────────────────────────
    var resultCard = buildResultCard(verdict, messageId);

    return CardService.newActionResponseBuilder()
      .setNavigation(
        CardService.newNavigation().updateCard(resultCard)
      )
      .build();

  } catch (err) {
    console.error('analyzeEmailAction failed', {
      messageId: messageId,
      error: err.message || String(err)
    });

    var errorCard = buildErrorCard(
      err.message || 'An unexpected error occurred.',
      messageId
    );

    return CardService.newActionResponseBuilder()
      .setNavigation(
        CardService.newNavigation().updateCard(errorCard)
      )
      .build();
  }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/**
 * Extracts the email data needed for analysis from a Gmail message.
 *
 * Uses GmailApp (requires the gmail.readonly OAuth scope) to fetch the
 * message subject, plain-text body, sender, and raw headers.
 *
 * @param {string} messageId - The Gmail message ID.
 * @returns {{
 *   from_address: string,
 *   subject: string,
 *   body: string,
 *   headers: Object.<string, string>,
 *   attachment_metadata: Array.<Object>
 * }} The email data payload ready to send to the backend API.
 * @private
 */
function _extractEmailData(messageId) {
  var message = GmailApp.getMessageById(messageId);

  if (!message) {
    throw new Error('Could not retrieve message with ID: ' + messageId);
  }

  // Extract plain-text body (truncated to MAX_BODY_CHARS to stay within
  // the backend's 1 MB request cap).
  var rawBody = message.getPlainBody() || '';
  var body = rawBody.substring(0, MAX_BODY_CHARS);

  // Build a flat headers object from the most useful headers.
  var headers = {
    'From': message.getFrom() || '',
    'To': message.getTo() || '',
    'Date': message.getDate() ? message.getDate().toUTCString() : '',
    'Subject': message.getSubject() || '',
    'Reply-To': message.getReplyTo() || ''
  };

  // Extract attachment metadata (filename, MIME type, size only — no bytes).
  var attachmentMetadata = [];
  var attachments = message.getAttachments();
  for (var i = 0; i < attachments.length; i++) {
    var att = attachments[i];
    attachmentMetadata.push({
      filename: att.getName() || '',
      mime_type: att.getContentType() || '',
      size_bytes: att.getSize() || 0
    });
  }

  return {
    from_address: message.getFrom() || '',
    subject: message.getSubject() || '',
    body: body,
    headers: headers,
    attachment_metadata: attachmentMetadata
  };
}
