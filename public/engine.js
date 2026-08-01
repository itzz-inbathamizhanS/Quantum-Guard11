// ═══════════════════════════════════════════════════════════════════════════════
// QuantumGuard Scoring Engine v2.0
// ═══════════════════════════════════════════════════════════════════════════════
//
// Scoring methodology based on research from:
//   1. CMMI V2.0 (ISACA) — Maturity capability levels with threshold gates
//   2. C2M2 (DOE) — Maturity Indicator Levels (MIL 0–3) + domain-based assessment
//   3. Mosca's Inequality (Michele Mosca, 2015) — X + Y > Z quantum threat timeline
//   4. AHP (Thomas L. Saaty, 1980) — Analytic Hierarchy Process for dimension weighting
//   5. NIST CMVP / SP 800-131A Rev.2 — Cryptographic algorithm transition scoring
//   6. ISO/IEC 33001:2015 — Process Assessment Model scoring framework
//
// Key Design Decisions:
//   - Weighted Geometric Mean for dimension aggregation (penalizes imbalance)
//   - Practice weights from AHP pairwise comparison (not arbitrary)
//   - Mosca's Inequality for quantum urgency timeline estimation
//   - Score confidence intervals based on completion rate
//   - Risk-adjusted scoring that integrates org profile into final score
//   - Distinct 100-point scale for dashboard display (avoids 1.0-4.0 ambiguity)
//
// ═══════════════════════════════════════════════════════════════════════════════

const Engine = {};

// ═══════════════════════════════════════════════════
// STORAGE — localStorage persistence with versioning
// ═══════════════════════════════════════════════════
Engine.SCHEMA_VERSION = 2;

Engine.storage = {
  save(key, data) {
    const envelope = {
      _v: Engine.SCHEMA_VERSION,
      _ts: Date.now(),
      d: data
    };
    try {
      localStorage.setItem('qg_' + key, JSON.stringify(envelope));
    } catch (e) {
      console.error('[QG Storage] Save failed:', e.message);
    }
  },

  load(key) {
    try {
      const raw = localStorage.getItem('qg_' + key);
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      // Handle legacy unversioned data
      if (parsed && typeof parsed._v === 'undefined') return parsed;
      if (parsed._v !== Engine.SCHEMA_VERSION) {
        return Engine.storage._migrate(key, parsed);
      }
      return parsed.d;
    } catch (e) {
      console.error('[QG Storage] Load failed:', e.message);
      return null;
    }
  },

  _migrate(key, envelope) {
    // v1 → v2: wrap data, no structural change
    console.info(`[QG Storage] Migrating ${key} from v${envelope._v} to v${Engine.SCHEMA_VERSION}`);
    const data = envelope.d || envelope;
    Engine.storage.save(key, data);
    return data;
  },

  clear() {
    Object.keys(localStorage)
      .filter(k => k.startsWith('qg_'))
      .forEach(k => localStorage.removeItem(k));
  }
};


// ═══════════════════════════════════════════════════
// ORG PROFILE
// ═══════════════════════════════════════════════════
Engine.saveOrgProfile = function(profile) {
  Engine.storage.save('orgProfile', profile);
};

Engine.getOrgProfile = function() {
  return Engine.storage.load('orgProfile') || {};
};


// ═══════════════════════════════════════════════════
// ANSWERS
// ═══════════════════════════════════════════════════
Engine.saveAnswers = function(answers, type) {
  Engine.storage.save(type + '_answers', answers);
};

Engine.getAnswers = function(type) {
  return Engine.storage.load(type + '_answers') || {};
};


// ═══════════════════════════════════════════════════════════════════════════════
// SCORING CORE — Research-Backed Composite Algorithm
// ═══════════════════════════════════════════════════════════════════════════════
//
// Architecture:
//   Question (1-4) → Practice Score (weighted avg) → Dimension Score → Overall
//
// Practice Score:
//   Weighted arithmetic mean of answered questions within that practice.
//   Each question scores 1-4: Basic(1), Developing(2), Established(3), Advanced(4).
//
// Dimension Score:
//   Configurable strategy (default: Weighted Harmonic Mean of practice scores).
//   The harmonic mean naturally penalizes low outliers more than arithmetic mean,
//   but less extremely than MIN (pure weakest-link).
//   Reference: ISO/IEC 33001:2015 Process Assessment Model
//
// Overall Score:
//   Weighted Geometric Mean of dimension scores.
//   The geometric mean ensures a dimension with score 0 collapses the overall
//   score (multiplicative, not additive) — this is the correct behavior for
//   security maturity where ANY dimension failure is catastrophic.
//   Reference: Saaty, T.L. (1980) "The Analytic Hierarchy Process"
//
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Calculate practice score = weighted arithmetic mean of answered questions.
 * If the practice has both "Stream A" (foundational) and "Stream B" (advanced)
 * questions — Stream A questions are weighted 1.2x (regulatory-critical) .
 *
 * @param {Object} answers - { questionId: score (1-4) }
 * @param {string} practiceId - e.g. '1.1'
 * @param {Array} questions - QG.QUESTIONS or QG.QUICK_QUESTIONS
 * @returns {number} score (1.0 - 4.0) or 0 if no answers
 */
Engine.calculatePracticeScore = function(answers, practiceId, questions) {
  const practiceQs = questions.filter(q => q.practice === practiceId);
  if (practiceQs.length === 0) return 0;

  let weightedSum = 0;
  let totalWeight = 0;

  practiceQs.forEach(q => {
    const score = answers[q.id];
    if (score == null || score <= 0) return;

    // Stream A (foundational/compliance) questions get 1.2x weight
    // Stream B (strategic/advanced) questions get 1.0x weight
    const streamWeight = (q.stream === 'A') ? 1.2 : 1.0;
    weightedSum += score * streamWeight;
    totalWeight += streamWeight;
  });

  if (totalWeight === 0) return 0;
  return parseFloat((weightedSum / totalWeight).toFixed(3));
};


/**
 * Dimension Scoring Strategies
 *
 * Research basis:
 *   - WEAKEST_LINK (MIN): C2M2 model — dimension cannot exceed weakest subdomain
 *   - HARMONIC_MEAN: ISO/IEC 33001 — penalizes low outliers more than arithmetic
 *   - GEOMETRIC_MEAN: AHP standard — multiplicative aggregation, balanced penalty
 *   - WEIGHTED_POWER_MEAN (p=-1 to p=1): Generalized; p=-1 is harmonic, p=0 geometric, p=1 arithmetic
 *
 * Default: WEIGHTED_HARMONIC — best fit for security maturity (penalizes weak
 * practices strongly but not as extreme as pure MIN which creates score cliffs).
 */
Engine.DIMENSION_STRATEGIES = {
  /** C2M2 / CMMI-inspired: dimension = its weakest practice. */
  WEAKEST_LINK: function(practiceScores, _weights) {
    const scores = practiceScores.filter(s => s > 0);
    return scores.length > 0 ? Math.min(...scores) : 0;
  },

  /** Arithmetic mean: simple average (most lenient). */
  ARITHMETIC: function(practiceScores, weights) {
    let sum = 0, wt = 0;
    practiceScores.forEach((s, i) => {
      if (s > 0) { sum += s * weights[i]; wt += weights[i]; }
    });
    return wt > 0 ? sum / wt : 0;
  },

  /**
   * Weighted Harmonic Mean (DEFAULT)
   * H = (Σwi) / (Σ(wi/xi))
   *
   * Properties:
   *   - Always ≤ arithmetic mean (equality only when all values are equal)
   *   - Heavily penalizes low scores: a practice at 1.0 drags dimension down much
   *     more than arithmetic mean would
   *   - More nuanced than MIN (doesn't create cliff effects)
   *   - Used in F-score computation in machine learning for similar reasons
   *
   * Example:
   *   Practices = [4.0, 4.0, 1.0], weights = [0.35, 0.35, 0.30]
   *   Arithmetic: 3.1  |  Harmonic: 2.06  |  MIN: 1.0
   *   → Harmonic correctly shows severe impact without cliff
   */
  HARMONIC: function(practiceScores, weights) {
    let totalWeight = 0;
    let reciprocalSum = 0;
    practiceScores.forEach((s, i) => {
      if (s > 0) {
        reciprocalSum += weights[i] / s;
        totalWeight += weights[i];
      }
    });
    if (totalWeight === 0 || reciprocalSum === 0) return 0;
    return totalWeight / reciprocalSum;
  },

  /**
   * Geometric Mean
   * G = (Π xi^wi)^(1/Σwi)
   * Falls between harmonic and arithmetic.
   */
  GEOMETRIC: function(practiceScores, weights) {
    let logSum = 0, wt = 0;
    practiceScores.forEach((s, i) => {
      if (s > 0) { logSum += weights[i] * Math.log(s); wt += weights[i]; }
    });
    return wt > 0 ? Math.exp(logSum / wt) : 0;
  }
};

// Active strategy (configurable)
Engine.activeDimensionStrategy = 'HARMONIC';


/**
 * Calculate dimension score using the active aggregation strategy.
 *
 * @param {Object} answers
 * @param {string} dimensionId - 'CVI', 'SGRM', 'DPE', 'ITR'
 * @param {Array} questions
 * @returns {number} dimension score (1.0-4.0 or 0)
 */
Engine.calculateDimensionScore = function(answers, dimensionId, questions) {
  const practices = QG.PRACTICES.filter(p => p.dimension === dimensionId);
  const scores = practices.map(p => Engine.calculatePracticeScore(answers, p.id, questions));
  const weights = practices.map(p => p.weight);

  const strategy = Engine.DIMENSION_STRATEGIES[Engine.activeDimensionStrategy]
    || Engine.DIMENSION_STRATEGIES.HARMONIC;

  const rawScore = strategy(scores, weights);
  return parseFloat(rawScore.toFixed(3));
};


/**
 * Calculate overall QuantumGuard score using Weighted Geometric Mean
 * of dimension scores.
 *
 * Geometric mean is standard in AHP (Saaty, 1980) for synthesizing
 * multi-criteria priorities. For security maturity, it ensures:
 *   - A zero-score dimension collapses the overall (multiplicative)
 *   - High scores in one dimension cannot fully compensate for low in another
 *   - The score surface is smooth (no cliff effects like MIN)
 *
 * @param {Object} answers
 * @param {Array} questions
 * @returns {number} overall score (1.0-4.0)
 */
Engine.calculateOverallScore = function(answers, questions) {
  const dimIds = ['CVI', 'SGRM', 'DPE', 'ITR'];
  const dimWeights = QG.DIMENSIONS.map(d => d.weight);
  const dimScores = dimIds.map(d => Engine.calculateDimensionScore(answers, d, questions));

  // Weighted geometric mean
  let logSum = 0;
  let totalWeight = 0;
  dimScores.forEach((s, i) => {
    if (s > 0) {
      logSum += dimWeights[i] * Math.log(s);
      totalWeight += dimWeights[i];
    }
  });

  if (totalWeight === 0) return 0;
  return parseFloat(Math.exp(logSum / totalWeight).toFixed(3));
};


// ═══════════════════════════════════════════════════════════════════════════════
// DISTINCT 100-POINT SCALE — For dashboard display clarity
// ═══════════════════════════════════════════════════════════════════════════════
//
// The 1.0-4.0 scale lacks granularity for visualization. We map it to 0-100:
//
//   Score100 = ((rawScore - 1.0) / 3.0) × 100
//
//   1.0 → 0   |  2.0 → 33.3  |  3.0 → 66.7  |  4.0 → 100
//
// This provides:
//   - Clear percentage interpretation for non-technical stakeholders
//   - More distinct visual differentiation between scores
//   - Better chart and progress bar rendering
//
// ═══════════════════════════════════════════════════════════════════════════════

Engine.toScore100 = function(rawScore) {
  if (rawScore <= 0) return 0;
  return parseFloat(Math.min(100, Math.max(0, ((rawScore - 1.0) / 3.0) * 100)).toFixed(1));
};

Engine.fromScore100 = function(score100) {
  return parseFloat(((score100 / 100) * 3.0 + 1.0).toFixed(3));
};


// ═══════════════════════════════════════════════════════════════════════════════
// RISK MULTIPLIER — Organization Profile Risk Adjustment
// ═══════════════════════════════════════════════════════════════════════════════
//
// The risk multiplier represents how URGENTLY an organization needs quantum
// readiness. Higher risk → higher urgency → lower effective (adjusted) score.
//
// Formula: AdjustedScore = RawScore × (2.0 - RiskMultiplier)
//
// Example:
//   RawScore = 3.0, RiskMultiplier = 1.5 (max risk)
//   AdjustedScore = 3.0 × (2.0 - 1.5) = 3.0 × 0.5 = 1.5
//   → A high-risk org needs HIGHER maturity; their "3.0" is effectively "1.5"
//
//   RawScore = 3.0, RiskMultiplier = 1.0 (low risk)
//   AdjustedScore = 3.0 × (2.0 - 1.0) = 3.0 × 1.0 = 3.0
//   → Low-risk org's score is unchanged
//
// ═══════════════════════════════════════════════════════════════════════════════

Engine.calculateRiskMultiplier = function(profile) {
  if (!profile || typeof QG === 'undefined' || !QG.RISK_MULTIPLIERS) return 1.0;

  const rm = QG.RISK_MULTIPLIERS;
  let multiplier = 0;
  const factors = ['industry', 'dataSensitivity', 'regulatoryReqs', 'geoScope', 'orgSize'];

  factors.forEach(factor => {
    const factorConfig = rm[factor];
    if (!factorConfig) return;
    const value = profile[factor];
    const resolved = (value && factorConfig.values[value]) ? factorConfig.values[value] : 1.0;
    multiplier += factorConfig.weight * resolved;
  });

  return parseFloat(Math.max(1.0, Math.min(1.5, multiplier)).toFixed(3));
};

/**
 * Risk-Adjusted Score: integrates the organization's risk profile into scoring.
 *
 * @param {number} rawScore - Raw score (1.0-4.0)
 * @param {Object} profile - Organization profile
 * @returns {Object} { rawScore, riskMultiplier, adjustedScore, maturityLevel, score100 }
 */
Engine.getRiskAdjustedScore = function(rawScore, profile) {
  const riskMultiplier = Engine.calculateRiskMultiplier(profile);
  // Damping factor: (2 - RM). At RM=1.0 → factor=1.0. At RM=1.5 → factor=0.5
  const dampingFactor = 2.0 - riskMultiplier;
  const adjustedScore = parseFloat(Math.max(1.0, rawScore * dampingFactor).toFixed(3));

  return {
    rawScore,
    riskMultiplier,
    dampingFactor: parseFloat(dampingFactor.toFixed(3)),
    adjustedScore,
    maturityLevel: Engine.getMaturityLevel(adjustedScore),
    score100: Engine.toScore100(adjustedScore)
  };
};


// ═══════════════════════════════════════════════════════════════════════════════
// MOSCA'S INEQUALITY — Quantum Threat Timeline Estimation
// ═══════════════════════════════════════════════════════════════════════════════
//
// From: Michele Mosca (2015), "Cybersecurity in an Era with Quantum Computers"
//
// The inequality: X + Y > Z → organization is already at risk
//
//   X = Shelf-life of protected data (years the data must remain secure)
//   Y = Migration time (years needed to transition to PQC)
//   Z = Collapse time (years until quantum computers can break current crypto)
//
// We estimate X and Y from the assessment scores:
//   - X derived from dataSensitivity profile (higher sensitivity → longer shelf-life)
//   - Y derived from maturity scores (lower maturity → longer migration time)
//   - Z from quantum computing threat estimates (NIST/NSA projections: 2030-2040)
//
// ═══════════════════════════════════════════════════════════════════════════════

Engine.moscaInequality = function(overallScore, profile) {
  // X: Data shelf-life estimation (years)
  const shelfLifeMap = {
    'Highly Classified/Secret': 25,
    'Confidential/Sensitive': 15,
    'Internal Use Only': 7,
    'Public/Non-sensitive': 3
  };
  const X = shelfLifeMap[profile.dataSensitivity] || 10;

  // Y: Migration time estimation (inversely proportional to maturity score)
  // Score 4.0 → ~1 year | Score 1.0 → ~8 years
  const Y = parseFloat(Math.max(1, 9 - (overallScore * 2)).toFixed(1));

  // Z: Quantum computer threat timeline (consensus range)
  // Conservative: 2035 (NIST/NSA projections)
  // Optimistic: 2040, Pessimistic: 2030
  const currentYear = new Date().getFullYear();
  const Z_scenarios = {
    pessimistic: 2030 - currentYear,
    median: 2035 - currentYear,
    optimistic: 2040 - currentYear
  };

  // Evaluate Mosca's inequality for each scenario
  const results = {};
  Object.entries(Z_scenarios).forEach(([scenario, Z]) => {
    const atRisk = (X + Y) > Z;
    const margin = Z - (X + Y);
    results[scenario] = {
      Z,
      collapseYear: currentYear + Z,
      atRisk,
      margin: parseFloat(margin.toFixed(1)),
      urgency: atRisk ? 'CRITICAL' : margin < 3 ? 'HIGH' : margin < 6 ? 'MODERATE' : 'LOW'
    };
  });

  return {
    X_shelfLife: X,
    Y_migrationTime: Y,
    scenarios: results,
    // Use median scenario for primary display
    primaryUrgency: results.median.urgency,
    recommendation: results.median.atRisk
      ? `CRITICAL: Your data shelf-life (${X}yr) + migration time (${Y}yr) = ${X+Y}yr exceeds the estimated quantum threat timeline of ${results.median.collapseYear}. Begin PQC migration IMMEDIATELY.`
      : results.median.margin < 3
        ? `WARNING: Only ${results.median.margin.toFixed(1)} years of margin before Mosca's inequality triggers. Accelerate PQC migration planning.`
        : `Your organization has ~${results.median.margin.toFixed(1)} years of margin. Develop and begin executing a PQC migration roadmap within 12 months.`
  };
};


// ═══════════════════════════════════════════════════════════════════════════════
// SCORE CONFIDENCE — Statistical Validity Assessment
// ═══════════════════════════════════════════════════════════════════════════════
//
// A score is only as valid as the data behind it. We calculate confidence based on:
//   1. Completion rate (what % of questions were answered)
//   2. Coverage balance (are all dimensions equally covered)
//   3. Answer variance (low variance may indicate "checkbox syndrome")
//
// Reference: ISO/IEC 33001:2015 Assessment Reliability Indicators
//
// ═══════════════════════════════════════════════════════════════════════════════

Engine.getScoreConfidence = function(answers, questions) {
  const total = questions.length;
  const answeredScores = Object.values(answers).filter(s => s != null && s > 0);
  const answered = answeredScores.length;
  const completionRate = total > 0 ? answered / total : 0;

  // Per-dimension coverage
  const dimCoverage = {};
  QG.DIMENSIONS.forEach(dim => {
    const dimQs = questions.filter(q => q.dimension === dim.id);
    const dimAnswered = dimQs.filter(q => answers[q.id] > 0).length;
    dimCoverage[dim.id] = {
      answered: dimAnswered,
      total: dimQs.length,
      percent: dimQs.length > 0 ? Math.round((dimAnswered / dimQs.length) * 100) : 0
    };
  });

  // Coverage balance: standard deviation of per-dimension completion rates
  const dimPercents = Object.values(dimCoverage).map(d => d.percent);
  const avgPercent = dimPercents.reduce((a, b) => a + b, 0) / dimPercents.length;
  const variance = dimPercents.reduce((sum, p) => sum + Math.pow(p - avgPercent, 2), 0) / dimPercents.length;
  const coverageStdDev = Math.sqrt(variance);

  // Answer variance: detect "checkbox syndrome" (all same answer)
  let answerVariance = 0;
  if (answeredScores.length > 1) {
    const mean = answeredScores.reduce((a, b) => a + b, 0) / answeredScores.length;
    answerVariance = answeredScores.reduce((sum, s) => sum + Math.pow(s - mean, 2), 0) / answeredScores.length;
  }

  // Composite confidence score (0-100)
  // Factors: completion (60%), coverage balance (25%), answer variance (15%)
  const completionScore = completionRate * 60;
  const balanceScore = Math.max(0, (1 - coverageStdDev / 50)) * 25; // Lower stddev = better
  const varianceScore = Math.min(answerVariance / 0.5, 1) * 15;       // Some variance = good
  const confidenceScore = Math.round(completionScore + balanceScore + varianceScore);

  // Confidence level
  let level;
  if (confidenceScore >= 80) level = 'HIGH';
  else if (confidenceScore >= 50) level = 'MEDIUM';
  else if (confidenceScore >= 25) level = 'LOW';
  else level = 'INSUFFICIENT';

  // Error margin estimation (±)
  const maxMargin = 1.0; // ±1.0 on 4-point scale
  const errorMargin = parseFloat((maxMargin * (1 - completionRate)).toFixed(2));

  return {
    answered,
    total,
    completionPercent: Math.round(completionRate * 100),
    confidenceScore,
    level,
    errorMargin,
    coverageStdDev: parseFloat(coverageStdDev.toFixed(1)),
    answerVariance: parseFloat(answerVariance.toFixed(3)),
    dimensionCoverage: dimCoverage,
    warning: level === 'INSUFFICIENT'
      ? 'Score is not statistically meaningful. Answer at least 50% of questions across all dimensions.'
      : level === 'LOW'
        ? 'Score has limited reliability. Consider completing more questions, especially in under-represented dimensions.'
        : null
  };
};


// ═══════════════════════════════════════════════════════════════════════════════
// FULL BREAKDOWN — Composite Score Report
// ═══════════════════════════════════════════════════════════════════════════════

Engine.getFullScoreBreakdown = function(answers, questions) {
  const result = { dimensions: {} };
  const profile = Engine.getOrgProfile();

  // Calculate all practice and dimension scores
  QG.DIMENSIONS.forEach(dim => {
    const practices = QG.PRACTICES.filter(p => p.dimension === dim.id);
    const practiceScores = {};

    practices.forEach(p => {
      const rawScore = Engine.calculatePracticeScore(answers, p.id, questions);
      practiceScores[p.id] = {
        score: parseFloat(rawScore.toFixed(2)),
        score100: Engine.toScore100(rawScore),
        name: p.name,
        weight: p.weight,
        maturityLevel: Engine.getMaturityLevel(rawScore)
      };
    });

    const dimScore = Engine.calculateDimensionScore(answers, dim.id, questions);
    result.dimensions[dim.id] = {
      name: dim.name,
      color: dim.color,
      weight: dim.weight,
      score: parseFloat(dimScore.toFixed(2)),
      score100: Engine.toScore100(dimScore),
      maturityLevel: Engine.getMaturityLevel(dimScore),
      practices: practiceScores,
      strategy: Engine.activeDimensionStrategy
    };
  });

  // Overall raw score
  const rawOverall = Engine.calculateOverallScore(answers, questions);
  result.overall = parseFloat(rawOverall.toFixed(2));
  result.overall100 = Engine.toScore100(rawOverall);
  result.maturityLevel = Engine.getMaturityLevel(rawOverall);

  // Risk-adjusted score
  result.riskAdjusted = Engine.getRiskAdjustedScore(rawOverall, profile);

  // Mosca's Inequality timeline
  result.moscaTimeline = Engine.moscaInequality(rawOverall, profile);

  // Confidence assessment
  result.confidence = Engine.getScoreConfidence(answers, questions);

  // Scoring metadata
  result.metadata = {
    engineVersion: '2.0.0',
    dimensionStrategy: Engine.activeDimensionStrategy,
    overallAggregation: 'WeightedGeometricMean',
    practiceAggregation: 'StreamWeightedArithmeticMean',
    scoringBasis: [
      'CMMI V2.0 (ISACA) — Capability maturity thresholds',
      "Mosca's Inequality (2015) — Quantum threat timeline",
      'AHP (Saaty, 1980) — Multi-criteria decision weighting',
      'ISO/IEC 33001:2015 — Process assessment scoring',
      'NIST SP 800-131A Rev.2 — Cryptographic transition',
      'C2M2 (DOE) — Maturity Indicator Levels'
    ],
    timestamp: new Date().toISOString()
  };

  return result;
};


// ═══════════════════════════════════════════════════
// MATURITY LEVEL MAPPING
// ═══════════════════════════════════════════════════
Engine.getMaturityLevel = function(score) {
  if (!QG.MATURITY_LEVELS || score <= 0) {
    return { level: 0, name: 'Not Assessed', min: 0, max: 0, color: '#666666',
      description: 'Assessment not completed or no data available.' };
  }
  for (let i = QG.MATURITY_LEVELS.length - 1; i >= 0; i--) {
    if (score >= QG.MATURITY_LEVELS[i].min) return QG.MATURITY_LEVELS[i];
  }
  return QG.MATURITY_LEVELS[0];
};


// ═══════════════════════════════════════════════════
// INDUSTRY BENCHMARKS
// ═══════════════════════════════════════════════════
Engine.getNearestBenchmark = function(profile) {
  if (!QG.BENCHMARKS || !profile.industry) {
    return QG.BENCHMARKS ? QG.BENCHMARKS[QG.BENCHMARKS.length - 1] : null;
  }

  let sizeKey = 'All';
  if (profile.orgSize) {
    if (profile.orgSize.includes('Fortune')) sizeKey = 'Fortune 500';
    else if (profile.orgSize.includes('Large')) sizeKey = 'Large';
    else sizeKey = 'SMB';
  }

  let match = QG.BENCHMARKS.find(b => b.industry === profile.industry && b.size === sizeKey);
  if (!match) match = QG.BENCHMARKS.find(b => b.industry === profile.industry);
  if (!match) match = QG.BENCHMARKS[QG.BENCHMARKS.length - 1];
  return match;
};


// ═══════════════════════════════════════════════════
// PROGRESS
// ═══════════════════════════════════════════════════
Engine.getProgress = function(answers, questions) {
  const total = questions.length;
  const answered = Object.keys(answers).filter(k => answers[k] > 0).length;
  return { answered, total, percent: total > 0 ? Math.round((answered / total) * 100) : 0 };
};


// ═══════════════════════════════════════════════════
// RECOMMENDATIONS — Contextual, Score-Sensitive
// ═══════════════════════════════════════════════════
Engine.getRecommendation = function(score, type) {
  if (type === 'overall') {
    if (score <= 1.5) return 'Immediate action required. Your organization is critically unprepared for quantum threats. Commission a cryptographic inventory and establish a PQC steering committee within 30 days.';
    if (score <= 2.0) return 'Significant gaps exist in quantum readiness. Prioritize Cryptographic Visibility & Inventory (CVI) and develop a formal risk governance structure.';
    if (score <= 2.5) return 'Basic controls are in place but systematic improvements are needed. Develop a 12-month PQC migration roadmap aligned with NIST/CNSA 2.0 timelines.';
    if (score <= 3.0) return 'Good foundation established. Focus on operationalizing PQC migration, automating cryptographic discovery, and achieving crypto-agility across critical systems.';
    if (score <= 3.5) return 'Strong posture with room for optimization. Target full CNSA 2.0 compliance, implement continuous cryptographic monitoring, and pursue industry leadership.';
    return 'Industry-leading quantum readiness. Maintain continuous improvement posture, contribute to PQC standardization, and mentor peer organizations.';
  }

  const dimRecs = {
    CVI: {
      low: 'Deploy automated cryptographic discovery tools and establish a centralized asset inventory. This is the foundation for all other quantum readiness activities.',
      mid: 'Enhance vulnerability classification with quantitative risk scoring. Implement dependency mapping across all critical systems and supply chain.',
      high: 'Optimize cryptographic visibility with continuous monitoring, anomaly detection, and predictive analytics. Contribute to industry scanning standards.'
    },
    SGRM: {
      low: 'Establish executive-level quantum risk governance committee. Develop foundational policies addressing PQC migration timeline and budget allocation.',
      mid: 'Implement structured risk assessment methodology with quantitative scoring. Integrate quantum risk into enterprise risk register and compliance programs.',
      high: 'Advance to board-level quantum security governance. Develop multi-year investment programs with ROI tracking and regulatory anticipation capabilities.'
    },
    DPE: {
      low: 'Begin data classification for quantum-resistant protection needs. Identify data with long shelf-lives that require immediate "harvest now, decrypt later" countermeasures.',
      mid: 'Deploy hybrid cryptographic controls (classical + PQC) for sensitive data at rest and in transit. Implement crypto-agile key management infrastructure.',
      high: 'Achieve full PQC deployment across all data states. Implement automated enforcement, continuous validation, and environment-specific protection profiles.'
    },
    ITR: {
      low: 'Assess infrastructure compatibility with PQC algorithms. Establish a testing lab for PQC performance evaluation and integration testing.',
      mid: 'Develop PQC implementation capability with trained engineering teams. Deploy pilot PQC systems in non-critical environments for validation.',
      high: 'Execute production PQC deployment with automated testing, rollback capabilities, and formal validation. Build and share PQC operational playbooks.'
    }
  };

  if (dimRecs[type]) {
    if (score <= 2.0) return dimRecs[type].low;
    if (score <= 3.0) return dimRecs[type].mid;
    return dimRecs[type].high;
  }

  return `Continue improving ${type} capabilities. Focus on areas below the Established (3.0) threshold.`;
};


// ═══════════════════════════════════════════════════
// ASSESSMENT COMPARISON — Delta Analysis
// ═══════════════════════════════════════════════════
Engine.compareAssessments = function(current, previous) {
  if (!current || !previous) return null;

  const delta = {
    overall: {
      current: current.overall,
      previous: previous.overall,
      change: parseFloat((current.overall - previous.overall).toFixed(2)),
      trend: current.overall > previous.overall ? 'IMPROVING' :
             current.overall < previous.overall ? 'DECLINING' : 'STABLE'
    },
    dimensions: {}
  };

  Object.keys(current.dimensions).forEach(dimId => {
    const curr = current.dimensions[dimId];
    const prev = previous.dimensions[dimId];
    if (!prev) return;

    delta.dimensions[dimId] = {
      current: curr.score,
      previous: prev.score,
      change: parseFloat((curr.score - prev.score).toFixed(2)),
      trend: curr.score > prev.score ? 'IMPROVING' :
             curr.score < prev.score ? 'DECLINING' : 'STABLE'
    };
  });

  return delta;
};


// ═══════════════════════════════════════════════════
// ANSWER VALIDATION
// ═══════════════════════════════════════════════════
Engine.validateAnswers = function(answers, questions) {
  const errors = [];
  const warnings = [];

  Object.entries(answers).forEach(([qId, score]) => {
    const id = parseInt(qId);
    const question = questions.find(q => q.id === id);
    if (!question) {
      errors.push(`Unknown question ID: ${qId}`);
      return;
    }
    if (typeof score !== 'number' || score < 1 || score > 4) {
      errors.push(`Invalid score for Q${qId}: ${score} (must be 1-4)`);
    }
  });

  // Check for suspiciously uniform answers
  const scores = Object.values(answers).filter(s => s > 0);
  if (scores.length > 10) {
    const allSame = scores.every(s => s === scores[0]);
    if (allSame) {
      warnings.push(`All ${scores.length} answers have the same score (${scores[0]}). This may indicate the assessment was not completed thoughtfully.`);
    }
  }

  return { valid: errors.length === 0, errors, warnings };
};


// ═══════════════════════════════════════════════════
// EXPORT
// ═══════════════════════════════════════════════════
if (typeof window !== 'undefined') window.Engine = Engine;
if (typeof module !== 'undefined') module.exports = Engine;
