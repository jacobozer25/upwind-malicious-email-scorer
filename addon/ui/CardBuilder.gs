/**
 * @fileoverview CardService UI builder for the Email Security Scorer add-on.
 *
 * This file contains all functions that construct Gmail Add-on cards using
 * the CardService API. It is intentionally kept separate from business logic
 * (Code.gs) and API calls (api/BackendClient.gs) to make each layer testable
 * in isolation.
 *
 * CardService reference:
 *   https://developers.google.com/apps-script/reference/card-service
 */

// ---------------------------------------------------------------------------
// Main card (shown when a message is opened)
// ---------------------------------------------------------------------------

/**
 * Builds the main "welcome" card shown when the user opens a Gmail message.
 *
 * The card contains:
 *  - A branded header with the add-on name.
 *  - A brief description of what the scorer does.
 *  - An "Analyze Email" button that triggers {@link analyzeEmailAction}.
 *
 * @param {string} messageId - The Gmail message ID of the currently open email.
 * @returns {CardService.Card} The constructed card to display in the sidebar.
 */
function buildMainCard(messageId) {
  // ── Header ────────────────────────────────────────────────────────────
  var header = CardService.newCardHeader()
    .setTitle(ADDON_NAME)
    .setSubtitle('Powered by deterministic + AI analysis')
    .setImageUrl(
      'https://www.gstatic.com/images/icons/material/system/2x/security_black_48dp.png'
    )
    .setImageStyle(CardService.ImageStyle.CIRCLE);

  // ── Description paragraph ─────────────────────────────────────────────
  var descriptionWidget = CardService.newTextParagraph()
    .setText(
      'This tool analyzes the open email for phishing, malware, and ' +
      'social-engineering signals using a hybrid deterministic + AI pipeline. ' +
      'Click <b>Analyze Email</b> to get a risk score and detailed findings.'
    );

  // ── Analyze button ────────────────────────────────────────────────────
  var analyzeAction = CardService.newAction()
    .setFunctionName('analyzeEmailAction')
    .setParameters({ messageId: messageId });

  var analyzeButton = CardService.newTextButton()
    .setText('🔍 Analyze Email')
    .setOnClickAction(analyzeAction)
    .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
    .setBackgroundColor('#1a73e8');

  var buttonSet = CardService.newButtonSet()
    .addButton(analyzeButton);

  // ── Section ───────────────────────────────────────────────────────────
  var section = CardService.newCardSection()
    .addWidget(descriptionWidget)
    .addWidget(buttonSet);

  // ── Card ──────────────────────────────────────────────────────────────
  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(section)
    .build();
}

// ---------------------------------------------------------------------------
// Loading card (shown while analysis is in progress)
// ---------------------------------------------------------------------------

/**
 * Builds a temporary "loading" card displayed while the backend API call
 * is in progress.
 *
 * @returns {CardService.Card} A simple loading indicator card.
 */
function buildLoadingCard() {
  var header = CardService.newCardHeader()
    .setTitle(ADDON_NAME)
    .setSubtitle('Analyzing…');

  var loadingWidget = CardService.newTextParagraph()
    .setText('⏳ <b>Analyzing email…</b><br>This usually takes 2–5 seconds.');

  var section = CardService.newCardSection()
    .addWidget(loadingWidget);

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(section)
    .build();
}

// ---------------------------------------------------------------------------
// Result card (shown after a successful analysis)
// ---------------------------------------------------------------------------

/**
 * Builds the result card displaying the full analysis verdict.
 *
 * @param {Object} verdict - The parsed JSON response from the backend API.
 * @param {number} verdict.final_score - Fused maliciousness score (0–100).
 * @param {string} verdict.risk_level - Risk band string (e.g. "suspicious").
 * @param {number} verdict.deterministic_score - Raw deterministic score.
 * @param {Array<Object>} verdict.deterministic_findings - List of findings.
 * @param {boolean} verdict.llm_available - Whether LLM analysis ran.
 * @param {boolean} verdict.llm_gated - Whether LLM was intentionally skipped.
 * @param {string} verdict.semantic_warning - Warning message if LLM unavailable.
 * @param {string} messageId - The Gmail message ID (for the "Re-analyze" button).
 * @returns {CardService.Card} The result card.
 */
function buildResultCard(verdict, messageId) {
  var riskLabel = RISK_LEVEL_LABELS[verdict.risk_level] || verdict.risk_level;
  var riskColor = RISK_LEVEL_COLORS[verdict.risk_level] || '#757575';

  // ── Header ────────────────────────────────────────────────────────────
  var header = CardService.newCardHeader()
    .setTitle(ADDON_NAME)
    .setSubtitle('Analysis complete');

  // ── Score summary section ─────────────────────────────────────────────
  var scoreText = CardService.newDecoratedText()
    .setTopLabel('Risk Score')
    .setText('<b>' + verdict.final_score + ' / 100</b>')
    .setBottomLabel(riskLabel)
    .setWrapText(false);

  var scoreSummarySection = CardService.newCardSection()
    .setHeader('📊 Verdict')
    .addWidget(scoreText);

  // ── Semantic warning (if LLM was unavailable) ─────────────────────────
  if (verdict.semantic_warning) {
    var warningWidget = CardService.newTextParagraph()
      .setText(verdict.semantic_warning);
    scoreSummarySection.addWidget(warningWidget);
  }

  // ── Findings section (Progressive Disclosure) ─────────────────────────
  var findingsSection = CardService.newCardSection()
    .setHeader('🔍 Findings (' + verdict.deterministic_findings.length + ')')
    .setCollapsible(true)
    .setNumUncollapsibleWidgets(0);

  if (verdict.deterministic_findings.length === 0) {
    findingsSection.addWidget(
      CardService.newTextParagraph().setText('No suspicious signals detected.')
    );
  } else {
    verdict.deterministic_findings.forEach(function (finding) {
      var severityIcon = _severityIcon(finding.severity);
      var findingWidget = CardService.newDecoratedText()
        .setTopLabel(severityIcon + ' ' + finding.severity + ' — ' + finding.type)
        .setText(finding.description)
        .setWrapText(true);
      findingsSection.addWidget(findingWidget);
    });
  }

  // ── Re-analyze button ─────────────────────────────────────────────────
  var reanalyzeAction = CardService.newAction()
    .setFunctionName('analyzeEmailAction')
    .setParameters({ messageId: messageId });

  var reanalyzeButton = CardService.newTextButton()
    .setText('🔄 Re-analyze')
    .setOnClickAction(reanalyzeAction);

  var buttonSection = CardService.newCardSection()
    .addWidget(CardService.newButtonSet().addButton(reanalyzeButton));

  // ── Card ──────────────────────────────────────────────────────────────
  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(scoreSummarySection)
    .addSection(findingsSection)
    .addSection(buttonSection)
    .build();
}

// ---------------------------------------------------------------------------
// Error card
// ---------------------------------------------------------------------------

/**
 * Builds an error card shown when the backend API call fails.
 *
 * @param {string} errorMessage - A human-readable error description.
 * @param {string} messageId - The Gmail message ID (for the "Retry" button).
 * @returns {CardService.Card} The error card.
 */
function buildErrorCard(errorMessage, messageId) {
  var header = CardService.newCardHeader()
    .setTitle(ADDON_NAME)
    .setSubtitle('Analysis failed');

  var errorWidget = CardService.newTextParagraph()
    .setText(
      '❌ <b>Analysis failed.</b><br><br>' +
      (errorMessage || 'An unexpected error occurred. Please try again.') +
      '<br><br>If the problem persists, check that the backend service is ' +
      'running and that your network connection is active.'
    );

  var retryAction = CardService.newAction()
    .setFunctionName('analyzeEmailAction')
    .setParameters({ messageId: messageId });

  var retryButton = CardService.newTextButton()
    .setText('🔄 Retry')
    .setOnClickAction(retryAction);

  var section = CardService.newCardSection()
    .addWidget(errorWidget)
    .addWidget(CardService.newButtonSet().addButton(retryButton));

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(section)
    .build();
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/**
 * Returns an emoji icon for a given severity level.
 *
 * @param {string} severity - One of "LOW", "MEDIUM", "HIGH", "CRITICAL".
 * @returns {string} An emoji representing the severity.
 * @private
 */
function _severityIcon(severity) {
  switch ((severity || '').toUpperCase()) {
    case 'CRITICAL': return '🚨';
    case 'HIGH':     return '🔴';
    case 'MEDIUM':   return '🟡';
    case 'LOW':      return '🔵';
    default:         return '⚪';
  }
}
