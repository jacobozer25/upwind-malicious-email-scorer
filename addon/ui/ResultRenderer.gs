/**
 * @fileoverview Result rendering functions for the Email Security Scorer add-on.
 *
 * This file is responsible for transforming a backend API verdict object into
 * CardService widgets and sections. It is intentionally separate from
 * CardBuilder.gs (which handles structural card assembly) so that rendering
 * logic can be updated independently.
 *
 * Functions in this file are called by CardBuilder.gs — they return
 * CardService widget or section objects, not full cards.
 */

// ---------------------------------------------------------------------------
// Score badge section
// ---------------------------------------------------------------------------

/**
 * Builds the score summary section for a verdict card.
 *
 * Displays the fused score, risk level label, and (if present) a semantic
 * warning when the LLM was unavailable.
 *
 * @param {Object} verdict - The parsed JSON response from the backend API.
 * @param {number} verdict.final_score - Fused maliciousness score (0–100).
 * @param {string} verdict.risk_level - Risk band (e.g. "suspicious").
 * @param {boolean} verdict.llm_available - Whether LLM analysis ran.
 * @param {boolean} verdict.llm_gated - Whether LLM was intentionally skipped.
 * @param {string} verdict.semantic_warning - Warning message if LLM unavailable.
 * @returns {CardService.CardSection} The score summary section.
 */
function renderScoreSection(verdict) {
  var riskLabel = RISK_LEVEL_LABELS[verdict.risk_level] || verdict.risk_level;

  var scoreWidget = CardService.newDecoratedText()
    .setTopLabel('Risk Score')
    .setText('<b>' + verdict.final_score + ' / 100</b>')
    .setBottomLabel(riskLabel)
    .setWrapText(false);

  var section = CardService.newCardSection()
    .setHeader('📊 Verdict')
    .addWidget(scoreWidget);

  // Deterministic score sub-label (shown when LLM was gated or failed).
  if (!verdict.llm_available && verdict.deterministic_score !== undefined) {
    var detScoreWidget = CardService.newTextParagraph()
      .setText(
        '<i>Deterministic score: ' + verdict.deterministic_score + ' / 100</i>'
      );
    section.addWidget(detScoreWidget);
  }

  // Semantic warning (informational or high-visibility alert).
  if (verdict.semantic_warning) {
    var warningWidget = CardService.newTextParagraph()
      .setText(verdict.semantic_warning);
    section.addWidget(warningWidget);
  }

  return section;
}

// ---------------------------------------------------------------------------
// Findings section (Progressive Disclosure)
// ---------------------------------------------------------------------------

/**
 * Builds the collapsible findings section for a verdict card.
 *
 * The section is collapsed by default so the user sees the score summary
 * first and can expand findings on demand ("Show More" / Progressive
 * Disclosure pattern).
 *
 * @param {Array<Object>} findings - The deterministic_findings array from the
 *   backend API response.
 * @param {string} findings[].severity - "LOW", "MEDIUM", "HIGH", or "CRITICAL".
 * @param {string} findings[].type - Finding category (e.g. "PHISHING").
 * @param {string} findings[].description - Human-readable description.
 * @returns {CardService.CardSection} The collapsible findings section.
 */
function renderFindingsSection(findings) {
  var section = CardService.newCardSection()
    .setHeader('🔍 Findings (' + findings.length + ')')
    .setCollapsible(true)
    .setNumUncollapsibleWidgets(0);

  if (!findings || findings.length === 0) {
    section.addWidget(
      CardService.newTextParagraph().setText(
        '✅ No suspicious signals detected by the deterministic layer.'
      )
    );
    return section;
  }

  // Group findings by severity for easier scanning.
  var bySeverity = { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [] };
  findings.forEach(function (f) {
    var sev = (f.severity || 'LOW').toUpperCase();
    if (bySeverity[sev]) {
      bySeverity[sev].push(f);
    } else {
      bySeverity['LOW'].push(f);
    }
  });

  var severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  severityOrder.forEach(function (sev) {
    bySeverity[sev].forEach(function (finding) {
      var icon = _severityIcon(sev);
      var widget = CardService.newDecoratedText()
        .setTopLabel(icon + ' ' + sev + ' — ' + (finding.type || ''))
        .setText(finding.description || '')
        .setWrapText(true);
      section.addWidget(widget);
    });
  });

  return section;
}

// ---------------------------------------------------------------------------
// LLM rationale section
// ---------------------------------------------------------------------------

/**
 * Builds an optional LLM rationale section shown when the LLM was available.
 *
 * @param {Object|null} llmResult - The llm_result object from the API response,
 *   or null if the LLM was not available.
 * @returns {CardService.CardSection|null} The rationale section, or null if
 *   the LLM result is absent.
 */
function renderLlmRationaleSection(llmResult) {
  if (!llmResult || !llmResult.rational) {
    return null;
  }

  var rationaleWidget = CardService.newTextParagraph()
    .setText('<i>' + llmResult.rational + '</i>');

  return CardService.newCardSection()
    .setHeader('🤖 AI Rationale')
    .setCollapsible(true)
    .setNumUncollapsibleWidgets(0)
    .addWidget(rationaleWidget);
}

// ---------------------------------------------------------------------------
// Private helpers (shared with CardBuilder.gs via global namespace)
// ---------------------------------------------------------------------------

/**
 * Returns an emoji icon for a given severity level.
 *
 * NOTE: This function is also defined in CardBuilder.gs. In GAS the last
 * definition wins. Both files define the same implementation so there is no
 * conflict — this copy is kept here so ResultRenderer.gs is self-contained.
 *
 * @param {string} severity - One of "LOW", "MEDIUM", "HIGH", "CRITICAL".
 * @returns {string} An emoji representing the severity.
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
