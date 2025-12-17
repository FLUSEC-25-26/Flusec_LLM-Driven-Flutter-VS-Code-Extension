// lib/hsd/hardcoded_secrets_rules.dart
//
// This file contains ONLY the "rules + detection engine" for your component (HSD).
// It is NOT in core because it is specific to hardcoded secrets detection.
//
// Other components idea (future):
// - insecure_network will have its own engine (TLS rules, http usage rules, etc.)
// - insecure_storage will have its own engine (SharedPreferences/File/DB storage rules)
// - input_validation will have its own engine (regex patterns, sanitization rules, etc.)

import 'dart:io';
import 'dart:math';

/// ------------------------------
/// Models & engine (your original code, preserved)
/// ------------------------------

class DynamicRule {
  final String id;
  final String name;
  final String pattern;
  final String severity;
  final String description;
  final bool enabled;
  final String? messageTemplate;
  final RegExp regex;

  DynamicRule({
    required this.id,
    required this.name,
    required this.pattern,
    required this.severity,
    required this.description,
    required this.enabled,
    required this.messageTemplate,
    required this.regex,
  });
}

enum MatchSource { dynamicRule, builtinRule, heuristic }

class MatchHit {
  final MatchSource source;
  final String ruleId;
  final String message;
  final String severity;

  MatchHit(this.source, this.ruleId, this.message, this.severity);
}

class RulesEngine {
  final List<DynamicRule> _dynamic = [];
  final Set<String> _dynamicPatternSet = {};

  final RegExp _googleKey = RegExp(r'^AIza[0-9A-Za-z\-_]{35}$');
  final RegExp _awsAccessKey = RegExp(r'^AKIA[0-9A-Z]{16}$');
  final RegExp _stripeLive = RegExp(r'^sk_live_[0-9A-Za-z]{16,}$');
  final RegExp _jwt =
      RegExp(r'eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+');

  final List<String> _sensitiveKeywords = const [
    'password',
    'passwd',
    'pwd',
    'secret',
    'token',
    'apikey',
    'api_key',
    'auth',
    'authorization',
    'bearer',
    'private',
    'key',
  ];

  final List<String> _benignMarkers = const [
    'test',
    'dummy',
    'sample',
    'example',
    'fake',
    'placeholder',
    'changeme',
  ];

  final int _globalMinLen = 10;
  final double _globalMinEntropy = 3.3;

  void loadDynamicRules(List<Map<String, dynamic>> raw) {
    _dynamic
      ..clear()
      ..addAll(raw.map((r) {
        final enabled = (r['enabled'] as bool?) ?? true;
        final pat = (r['pattern'] as String).trim();

        // Keeping your debug output exactly:
        stderr.writeln('🧠 Compiled pattern for rule "${r['id']}": $pat');

        return DynamicRule(
          id: r['id'] as String,
          name: (r['name'] as String?) ?? (r['id'] as String),
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
        );
      }).where((r) => r.enabled));

    _dynamicPatternSet
      ..clear()
      ..addAll(_dynamic.map((r) => r.pattern));

    stderr.writeln('✅ Loaded ${_dynamic.length} dynamic rules.');
  }

  MatchHit? detect(String value, String contextName, String nodeKind) {
    final trimmed = value.trim();
    if (trimmed.isEmpty || trimmed.length < 3) return null;

    final lc = trimmed.toLowerCase();
    if (lc.contains('dummy') || lc.contains('example') || lc.contains('sample')) {
      return null;
    }

    final bool isHttp =
        trimmed.startsWith('http://') || trimmed.startsWith('https://');

    // 1️⃣ dynamic
    for (final r in _dynamic) {
      if (r.regex.hasMatch(trimmed)) {
        final msg =
            '${r.name} hardcoded in $nodeKind${contextName.isNotEmpty ? ' in "$contextName"' : ''}';
        return MatchHit(MatchSource.dynamicRule, r.id, msg, r.severity);
      }
    }

    // 2️⃣ built-in
    MatchHit? builtIn;

    if (!_dynamicPatternSet.contains(_googleKey.pattern) &&
        _googleKey.hasMatch(trimmed)) {
      builtIn = MatchHit(
        MatchSource.builtinRule,
        'FLUSEC.GOOGLE_API_KEY',
        'Google API Key hardcoded in $nodeKind',
        'warning',
      );
    } else if (!_dynamicPatternSet.contains(_awsAccessKey.pattern) &&
        _awsAccessKey.hasMatch(trimmed)) {
      builtIn = MatchHit(
        MatchSource.builtinRule,
        'FLUSEC.AWS_ACCESS_KEY',
        'AWS Access Key hardcoded in $nodeKind',
        'warning',
      );
    } else if (!_dynamicPatternSet.contains(_stripeLive.pattern) &&
        _stripeLive.hasMatch(trimmed)) {
      builtIn = MatchHit(
        MatchSource.builtinRule,
        'FLUSEC.STRIPE_LIVE_KEY',
        'Stripe Live Secret Key hardcoded in $nodeKind',
        'warning',
      );
    } else if (!_dynamicPatternSet.contains(_jwt.pattern) &&
        _jwt.hasMatch(trimmed)) {
      builtIn = MatchHit(
        MatchSource.builtinRule,
        'FLUSEC.JWT',
        'JWT Token hardcoded in $nodeKind',
        'warning',
      );
    }

    if (builtIn != null) return builtIn;

    // 3️⃣ heuristics
    final e = _entropy(trimmed);
    final ctxLower = contextName.toLowerCase();
    final hasKeyword = _sensitiveKeywords.any((kw) => ctxLower.contains(kw));

    final hasBenignValueMarker = _benignMarkers.any((m) => lc.contains(m));
    final hasBenignContextMarker = _benignMarkers.any((m) => ctxLower.contains(m));
    if (hasBenignValueMarker || hasBenignContextMarker) return null;

    if (isHttp && !_isSensitiveUrl(trimmed)) return null;

    if (!isHttp &&
        trimmed.length >= max(_globalMinLen, 17) &&
        e > max(_globalMinEntropy, 3.6)) {
      return MatchHit(
        MatchSource.heuristic,
        'FLUSEC.SEC_HEUR',
        'Possible hardcoded secret in $nodeKind',
        'warning',
      );
    }

    if (hasKeyword && trimmed.length >= _globalMinLen && e > _globalMinEntropy) {
      return MatchHit(
        MatchSource.heuristic,
        'FLUSEC.SEC_HEUR',
        'Possible hardcoded secret in $nodeKind',
        'warning',
      );
    }

    return null;
  }

  bool _isSensitiveUrl(String s) {
    final slack = RegExp(
      r'^https://hooks\.slack\.com/services/[A-Za-z0-9]{9,}/[A-Za-z0-9]{9,}/[A-Za-z0-9]{24,}$',
    );
    final discord = RegExp(
      r'^https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]{30,}',
    );
    return slack.hasMatch(s) ||
        discord.hasMatch(s) ||
        (s.contains('?') && s.toLowerCase().contains('sig='));
  }

  double _entropy(String s) {
    if (s.isEmpty) return 0;

    final freq = <int, int>{};
    for (final code in s.codeUnits) {
      freq.update(code, (v) => v + 1, ifAbsent: () => 1);
    }

    final len = s.length;
    double h = 0.0;
    freq.forEach((_, count) {
      final p = count / len;
      h -= p * (log(p) / log(2));
    });

    return h;
  }
}
