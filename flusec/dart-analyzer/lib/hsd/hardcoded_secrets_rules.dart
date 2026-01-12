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

  static DynamicRule? tryFromJson(Map<String, dynamic> r) {
    try {
      final enabled = (r['enabled'] as bool?) ?? true;
      final pat = (r['pattern'] as String?)?.trim() ?? '';
      if (!enabled || pat.isEmpty) return null;

      final id = (r['id'] ?? '').toString().trim();
      final name = (r['name'] ?? id).toString().trim();

      if (id.isEmpty) return null;

      stderr.writeln('🧠 Compiled pattern for rule "$id": $pat');

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

  MatchHit(this.source, this.ruleId, this.message, this.severity);
}

class HeuristicsCfg {
  int minLength;
  double minEntropy;
  List<String> sensitiveKeywords;
  List<String> benignMarkers;

  HeuristicsCfg({
    required this.minLength,
    required this.minEntropy,
    required this.sensitiveKeywords,
    required this.benignMarkers,
  });

  // Fallback only if heuristics.json missing/empty
  factory HeuristicsCfg.defaults() => HeuristicsCfg(
        minLength: 14,
        minEntropy: 3.2,
        sensitiveKeywords: const [
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
        ],
        benignMarkers: const [
          'test',
          'dummy',
          'sample',
          'example',
          'fake',
          'placeholder',
          'changeme',
        ],
      );

  factory HeuristicsCfg.fromJson(Map<String, dynamic> json) {
    final d = HeuristicsCfg.defaults();

    final ml = json['minLength'];
    final me = json['minEntropy'];
    final sk = json['sensitiveKeywords'];
    final bm = json['benignMarkers'];

    return HeuristicsCfg(
      minLength: ml is int ? ml : d.minLength,
      minEntropy: me is num ? me.toDouble() : d.minEntropy,
      sensitiveKeywords: sk is List
          ? sk.map((e) => e.toString()).toList()
          : d.sensitiveKeywords,
      benignMarkers: bm is List
          ? bm.map((e) => e.toString()).toList()
          : d.benignMarkers,
    );
  }
}

class RulesEngine {
  final List<DynamicRule> _rules = [];
  HeuristicsCfg _cfg = HeuristicsCfg.defaults();

  /// rules = merged list already (user first + base next) produced by extension
  void loadDynamicRules(List<Map<String, dynamic>> raw) {
    _rules
      ..clear()
      ..addAll(
        raw.map(DynamicRule.tryFromJson).whereType<DynamicRule>(),
      );

    stderr.writeln('✅ Loaded ${_rules.length} rule(s) from merged rule list.');
  }

  void loadHeuristics(Map<String, dynamic> json) {
    if (json.isEmpty) {
      _cfg = HeuristicsCfg.defaults();
      stderr.writeln('⚠️ Heuristics config missing/empty → using defaults.');
      return;
    }
    _cfg = HeuristicsCfg.fromJson(json);
    stderr.writeln('✅ Loaded heuristics config from JSON.');
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

    // 1) RULE MATCHING (this is the main detection now)
    for (final r in _rules) {
      if (r.regex.hasMatch(trimmed)) {
        final msg = r.messageTemplate ??
            '${r.name} hardcoded in $nodeKind${contextName.isNotEmpty ? ' in "$contextName"' : ''}';
        return MatchHit(MatchSource.rule, r.id, msg, r.severity);
      }
    }

    // 2) HEURISTIC (entropy + keyword hint)
    if (trimmed.length < _cfg.minLength) return null;

    final hasKeyword = _cfg.sensitiveKeywords.any((kw) {
      final k = kw.toLowerCase().trim();
      if (k.isEmpty) return false;
      return ctxLower.contains(k) || lc.contains(k);
    });

    if (!hasKeyword) return null;

    final e = _entropy(trimmed);
    if (e < _cfg.minEntropy) return null;

    return MatchHit(
      MatchSource.heuristic,
      'FLUSEC.SEC.H001',
      'Possible hardcoded secret (entropy heuristic) in $nodeKind${contextName.isNotEmpty ? ' in "$contextName"' : ''}',
      'warning',
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
