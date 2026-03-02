// lib/hsd/hardcoded_secrets_rules.dart
//
// Rule engine for Hardcoded Secrets Detection.
// Two detection layers:
//   1. Rule matching — regex patterns from JSON rules (each rule has a secretType)
//   2. Heuristic — entropy + keyword hint (infers secretType from context)

import 'dart:io';
import 'dart:math';

class DynamicRule {
  final String id;
  final String name;
  final String pattern;
  final String severity;
  final String description;
  final bool enabled;
  final String? messageTemplate;
  final RegExp regex;

  /// What type of secret this rule detects.
  /// Values: API_KEY, SECRET_KEY, JWT_TOKEN, PASSWORD, DATABASE_CREDENTIAL,
  ///         OAUTH_SECRET, FIREBASE_KEY, ENCRYPTION_KEY, GENERIC_SECRET
  final String secretType;

  DynamicRule({
    required this.id,
    required this.name,
    required this.pattern,
    required this.severity,
    required this.description,
    required this.enabled,
    required this.messageTemplate,
    required this.regex,
    required this.secretType,
  });

  static DynamicRule? tryFromJson(Map<String, dynamic> r) {
    try {
      final enabled = (r['enabled'] as bool?) ?? true;
      final pat = (r['pattern'] as String?)?.trim() ?? '';
      if (!enabled || pat.isEmpty) return null;

      final id = (r['id'] ?? '').toString().trim();
      final name = (r['name'] ?? id).toString().trim();
      if (id.isEmpty) return null;

      // Read secretType from rule JSON, default to GENERIC_SECRET
      final secretType = (r['secretType'] as String?)?.trim().toUpperCase();
      final validTypes = {
        'API_KEY', 'SECRET_KEY', 'JWT_TOKEN', 'PASSWORD',
        'DATABASE_CREDENTIAL', 'OAUTH_SECRET', 'FIREBASE_KEY',
        'ENCRYPTION_KEY', 'GENERIC_SECRET',
      };
      final resolvedType = (secretType != null && validTypes.contains(secretType))
          ? secretType
          : 'GENERIC_SECRET';

      stderr.writeln('🧠 Compiled pattern for rule "$id": $pat [type=$resolvedType]');

      return DynamicRule(
        id: id,
        name: name.isEmpty ? id : name,
        pattern: pat,
        severity: (r['severity'] as String?) ?? 'warning',
        description: (r['description'] as String?) ?? '',
        enabled: enabled,
        messageTemplate: r['messageTemplate'] as String?,
        regex: RegExp(
          pat,
          caseSensitive: false,
          dotAll: true,
          multiLine: true,
        ),
        secretType: resolvedType,
      );
    } catch (_) {
      return null;
    }
  }
}

enum MatchSource { rule, heuristic }

class MatchHit {
  final MatchSource source;
  final String ruleId;
  final String message;
  final String severity;

  /// The classified type of secret detected.
  final String secretType;

  MatchHit(this.source, this.ruleId, this.message, this.severity, this.secretType);
}

class HeuristicsCfg {
  final int minLength;
  final double minEntropy;
  final List<String> sensitiveKeywords;
  final List<String> benignMarkers;

  const HeuristicsCfg({
    required this.minLength,
    required this.minEntropy,
    required this.sensitiveKeywords,
    required this.benignMarkers,
  });

  /// Heuristics are disabled when config is missing/empty/invalid.
  factory HeuristicsCfg.disabled() => const HeuristicsCfg(
        minLength: 1 << 30,
        minEntropy: double.infinity,
        sensitiveKeywords: <String>[],
        benignMarkers: <String>[],
      );

  /// STRICT parser: requires valid types in JSON.
  factory HeuristicsCfg.fromJsonStrict(Map<String, dynamic> json) {
    final ml = json['minLength'];
    final me = json['minEntropy'];
    final sk = json['sensitiveKeywords'];
    final bm = json['benignMarkers'];

    if (ml is! int) {
      throw const FormatException('heuristics.minLength must be an int');
    }
    if (me is! num) {
      throw const FormatException('heuristics.minEntropy must be a number');
    }
    if (sk is! List) {
      throw const FormatException('heuristics.sensitiveKeywords must be a list');
    }
    if (bm is! List) {
      throw const FormatException('heuristics.benignMarkers must be a list');
    }

    return HeuristicsCfg(
      minLength: ml,
      minEntropy: me.toDouble(),
      sensitiveKeywords: sk.map((e) => e.toString()).toList(),
      benignMarkers: bm.map((e) => e.toString()).toList(),
    );
  }
}

// ---------------------------------------------------------------------------
// Secret type inference for heuristic detections
// ---------------------------------------------------------------------------

/// Infer secret type from variable/context name and string value.
/// Used when heuristic detection fires (no rule with explicit secretType).
class SecretTypeInferrer {
  // Keyword → type mapping (checked against context name + value)
  static const _keywordTypeMap = <String, String>{
    // API keys
    'apikey': 'API_KEY',
    'api_key': 'API_KEY',
    'apiKey': 'API_KEY',
    'api-key': 'API_KEY',
    'appkey': 'API_KEY',
    'app_key': 'API_KEY',
    'appKey': 'API_KEY',
    'accesskey': 'API_KEY',
    'access_key': 'API_KEY',
    'accessKey': 'API_KEY',

    // Secret keys
    'secret': 'SECRET_KEY',
    'secretkey': 'SECRET_KEY',
    'secret_key': 'SECRET_KEY',
    'secretKey': 'SECRET_KEY',
    'privatekey': 'SECRET_KEY',
    'private_key': 'SECRET_KEY',
    'privateKey': 'SECRET_KEY',

    // JWT / tokens
    'jwt': 'JWT_TOKEN',
    'jwttoken': 'JWT_TOKEN',
    'jwt_token': 'JWT_TOKEN',
    'jwtToken': 'JWT_TOKEN',
    'bearer': 'JWT_TOKEN',
    'bearertoken': 'JWT_TOKEN',
    'bearer_token': 'JWT_TOKEN',
    'bearerToken': 'JWT_TOKEN',
    'authtoken': 'JWT_TOKEN',
    'auth_token': 'JWT_TOKEN',
    'authToken': 'JWT_TOKEN',
    'accesstoken': 'JWT_TOKEN',
    'access_token': 'JWT_TOKEN',
    'accessToken': 'JWT_TOKEN',
    'refreshtoken': 'JWT_TOKEN',
    'refresh_token': 'JWT_TOKEN',
    'refreshToken': 'JWT_TOKEN',
    'token': 'JWT_TOKEN',

    // Passwords
    'password': 'PASSWORD',
    'passwd': 'PASSWORD',
    'pass': 'PASSWORD',
    'pwd': 'PASSWORD',
    'userpassword': 'PASSWORD',
    'user_password': 'PASSWORD',
    'userPassword': 'PASSWORD',
    'dbpassword': 'PASSWORD',
    'db_password': 'PASSWORD',
    'dbPassword': 'PASSWORD',

    // Database
    'connectionstring': 'DATABASE_CREDENTIAL',
    'connection_string': 'DATABASE_CREDENTIAL',
    'connectionString': 'DATABASE_CREDENTIAL',
    'dburl': 'DATABASE_CREDENTIAL',
    'db_url': 'DATABASE_CREDENTIAL',
    'dbUrl': 'DATABASE_CREDENTIAL',
    'databaseurl': 'DATABASE_CREDENTIAL',
    'database_url': 'DATABASE_CREDENTIAL',
    'databaseUrl': 'DATABASE_CREDENTIAL',
    'dbhost': 'DATABASE_CREDENTIAL',
    'db_host': 'DATABASE_CREDENTIAL',

    // OAuth
    'clientsecret': 'OAUTH_SECRET',
    'client_secret': 'OAUTH_SECRET',
    'clientSecret': 'OAUTH_SECRET',
    'clientid': 'OAUTH_SECRET',
    'client_id': 'OAUTH_SECRET',
    'clientId': 'OAUTH_SECRET',
    'oauthsecret': 'OAUTH_SECRET',
    'oauth_secret': 'OAUTH_SECRET',
    'oauthSecret': 'OAUTH_SECRET',

    // Firebase
    'firebase': 'FIREBASE_KEY',
    'firebasekey': 'FIREBASE_KEY',
    'firebase_key': 'FIREBASE_KEY',
    'firebaseKey': 'FIREBASE_KEY',
    'fcmkey': 'FIREBASE_KEY',
    'fcm_key': 'FIREBASE_KEY',
    'gcmkey': 'FIREBASE_KEY',

    // Encryption
    'encryptionkey': 'ENCRYPTION_KEY',
    'encryption_key': 'ENCRYPTION_KEY',
    'encryptionKey': 'ENCRYPTION_KEY',
    'signingkey': 'ENCRYPTION_KEY',
    'signing_key': 'ENCRYPTION_KEY',
    'signingKey': 'ENCRYPTION_KEY',
    'aeskey': 'ENCRYPTION_KEY',
    'aes_key': 'ENCRYPTION_KEY',
    'hmackey': 'ENCRYPTION_KEY',
    'hmac_key': 'ENCRYPTION_KEY',
  };

  /// Infer the secret type from context name and value.
  /// Returns the best matching type, or GENERIC_SECRET if no match.
  static String infer(String contextName, String value) {
    final ctxLower = contextName.toLowerCase().replaceAll(RegExp(r'[^a-z0-9_]'), '');
    final valLower = value.toLowerCase();

    // 1) Check context name against keyword map
    for (final entry in _keywordTypeMap.entries) {
      if (ctxLower.contains(entry.key.toLowerCase())) {
        return entry.value;
      }
    }

    // 2) Check value patterns
    // JWT pattern: xxxxx.xxxxx.xxxxx (three base64 segments)
    if (RegExp(r'^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$').hasMatch(value.trim())) {
      return 'JWT_TOKEN';
    }

    // Connection string patterns
    if (valLower.contains('server=') || valLower.contains('host=') ||
        valLower.contains('database=') || valLower.contains('uid=') ||
        valLower.startsWith('mongodb://') || valLower.startsWith('postgresql://') ||
        valLower.startsWith('mysql://')) {
      return 'DATABASE_CREDENTIAL';
    }

    // Firebase patterns
    if (value.trim().startsWith('AIzaSy')) {
      return 'FIREBASE_KEY';
    }

    // AWS-style patterns
    if (RegExp(r'^AKIA[0-9A-Z]{16}$').hasMatch(value.trim())) {
      return 'API_KEY';
    }

    // Stripe-style patterns
    if (value.trim().startsWith('sk_live_') || value.trim().startsWith('sk_test_')) {
      return 'SECRET_KEY';
    }
    if (value.trim().startsWith('pk_live_') || value.trim().startsWith('pk_test_')) {
      return 'API_KEY';
    }

    // 3) Fallback
    return 'GENERIC_SECRET';
  }
}


class RulesEngine {
  final List<DynamicRule> _rules = [];
  HeuristicsCfg _cfg = HeuristicsCfg.disabled();

  /// rules = merged list already (user first + base next) produced by extension
  void loadDynamicRules(List<Map<String, dynamic>> raw) {
    _rules
      ..clear()
      ..addAll(raw.map(DynamicRule.tryFromJson).whereType<DynamicRule>());

    stderr.writeln('✅ Loaded ${_rules.length} rule(s) from merged rule list.');
  }

  /// NO FALLBACK:
  /// - if json empty/invalid => heuristics disabled (so you can verify downloads)
  void loadHeuristics(Map<String, dynamic> json) {
    if (json.isEmpty) {
      _cfg = HeuristicsCfg.disabled();
      stderr.writeln('❌ Heuristics config missing/empty → heuristics DISABLED.');
      return;
    }

    try {
      _cfg = HeuristicsCfg.fromJsonStrict(json);
      stderr.writeln('✅ Loaded heuristics config from JSON (strict).');
    } catch (e) {
      _cfg = HeuristicsCfg.disabled();
      stderr.writeln('❌ Invalid heuristics JSON → heuristics DISABLED. Error: $e');
    }
  }

  MatchHit? detect(String value, String contextName, String nodeKind) {
    final trimmed = value.trim();
    if (trimmed.isEmpty || trimmed.length < 3) return null;

    final lc = trimmed.toLowerCase();
    final ctxLower = contextName.toLowerCase();

    // Skip obvious URLs (avoid false positives)
    if (lc.startsWith('http://') || lc.startsWith('https://')) {
      return null;
    }

    // Benign markers (from heuristics.json)
    for (final m in _cfg.benignMarkers) {
      final mm = m.toLowerCase().trim();
      if (mm.isEmpty) continue;
      if (lc.contains(mm) || ctxLower.contains(mm)) return null;
    }

    // 1) RULE MATCHING (main detection)
    for (final r in _rules) {
      if (r.regex.hasMatch(trimmed)) {
        final msg = r.messageTemplate ??
            '${r.name} hardcoded in $nodeKind${contextName.isNotEmpty ? ' in "$contextName"' : ''}';
        return MatchHit(MatchSource.rule, r.id, msg, r.severity, r.secretType);
      }
    }

    // 2) HEURISTIC (entropy + keyword hint) — disabled if config missing/invalid
    if (trimmed.length < _cfg.minLength) return null;

    final hasKeyword = _cfg.sensitiveKeywords.any((kw) {
      final k = kw.toLowerCase().trim();
      if (k.isEmpty) return false;
      return ctxLower.contains(k) || lc.contains(k);
    });

    if (!hasKeyword) return null;

    final e = _entropy(trimmed);
    if (e < _cfg.minEntropy) return null;

    // Infer secret type from context name and value
    final inferredType = SecretTypeInferrer.infer(contextName, trimmed);

    return MatchHit(
      MatchSource.heuristic,
      'FLUSEC.SEC.H001',
      'Possible hardcoded secret (entropy heuristic) in $nodeKind${contextName.isNotEmpty ? ' in "$contextName"' : ''}',
      'warning',
      inferredType,
    );
  }

  double _entropy(String input) {
    if (input.isEmpty) return 0;
    final freq = <int, int>{};
    for (final code in input.codeUnits) {
      freq[code] = (freq[code] ?? 0) + 1;
    }
    final len = input.length.toDouble();
    double h = 0.0;
    freq.forEach((_, count) {
      final p = count / len;
      h -= p * (log(p) / ln2);
    });
    return h;
  }
}