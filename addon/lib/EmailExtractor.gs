/**
 * @fileoverview Email extraction library for the Email Security Scorer add-on.
 *
 * This file is responsible for extracting the email data needed for analysis
 * from a Gmail message using the GmailApp service. It is intentionally
 * separate from Code.gs (the trigger entry point) so that extraction logic
 * can be tested and updated independently.
 *
 * Security notes
 * ==============
 * * Attachment *bytes* are never extracted — only metadata (filename, MIME
 *   type, size). This is a deliberate security boundary: the backend API
 *   accepts metadata only and the add-on never handles file contents.
 * * The body is truncated to MAX_BODY_CHARS (defined in Constants.gs) to
 *   stay within the backend's 1 MB request cap.
 * * No PII beyond what is strictly necessary for analysis is extracted.
 *
 * Required OAuth scope: https://www.googleapis.com/auth/gmail.readonly
 */

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Extracts the email data needed for analysis from a Gmail message.
 *
 * Uses GmailApp to fetch the message subject, plain-text body, sender,
 * recipient, date, and attachment metadata. Attachment bytes are never
 * included.
 *
 * @param {string} messageId - The Gmail message ID (from e.gmail.messageId).
 * @returns {{
 *   from_address: string,
 *   subject: string,
 *   body: string,
 *   headers: Object.<string, string>,
 *   attachment_metadata: Array.<{filename: string, mime_type: string, size_bytes: number}>
 * }} The email data payload ready to POST to the backend API.
 * @throws {Error} If the message cannot be retrieved or is null.
 */
function extractEmailData(messageId) {
  var message = GmailApp.getMessageById(messageId);

  if (!message) {
    throw new Error(
      'Could not retrieve Gmail message with ID: ' + messageId +
      '. Ensure the gmail.readonly OAuth scope is granted.'
    );
  }

  // ── Body ─────────────────────────────────────────────────────────────
  // Use plain-text body to avoid sending raw HTML to the backend.
  // Truncate to MAX_BODY_CHARS to stay within the 1 MB backend cap.
  var rawBody = message.getPlainBody() || '';
  var body = rawBody.substring(0, MAX_BODY_CHARS);

  // ── Headers ───────────────────────────────────────────────────────────
  // Extract the most security-relevant headers as a flat key→value map.
  var sendDate = message.getDate();
  var headers = {
    'From':     message.getFrom()    || '',
    'To':       message.getTo()      || '',
    'Date':     sendDate ? sendDate.toUTCString() : '',
    'Subject':  message.getSubject() || '',
    'Reply-To': message.getReplyTo() || ''
  };

  // ── Attachment metadata ───────────────────────────────────────────────
  // Collect filename, MIME type, and size for each attachment.
  // Bytes are intentionally excluded.
  var attachmentMetadata = _extractAttachmentMetadata(message);

  return {
    from_address:        message.getFrom()    || '',
    subject:             message.getSubject() || '',
    body:                body,
    headers:             headers,
    attachment_metadata: attachmentMetadata
  };
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/**
 * Extracts metadata (no bytes) for all attachments on a Gmail message.
 *
 * @param {GmailApp.GmailMessage} message - The Gmail message object.
 * @returns {Array.<{filename: string, mime_type: string, size_bytes: number}>}
 *   An array of attachment metadata objects.
 * @private
 */
function _extractAttachmentMetadata(message) {
  var metadata = [];

  try {
    var attachments = message.getAttachments();
    for (var i = 0; i < attachments.length; i++) {
      var att = attachments[i];
      metadata.push({
        filename:   att.getName()        || '',
        mime_type:  att.getContentType() || '',
        size_bytes: att.getSize()        || 0
      });
    }
  } catch (err) {
    // Log but do not throw — attachment metadata is best-effort.
    console.warn('EmailExtractor: failed to extract attachment metadata', {
      error: err.message || String(err)
    });
  }

  return metadata;
}
