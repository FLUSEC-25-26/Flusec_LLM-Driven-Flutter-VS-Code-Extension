// lib/iiv/iiv_rules.dart
//
// Rule model for Insufficient Input Validation detection.

class IivRule {
  final String id;
  final String name;
  final String description;

  /// VS Code diagnostic severity: error | warning | information | hint.
  final String diagnosticSeverity;

  /// Security impact: critical | high | medium | low.
  final String securitySeverity;

  /// Default detector confidence: high | medium | low.
  final String defaultConfidence;

  final String category;
  final String remediation;
  final String? cwe;
  final String checkKey;
  final bool enabled;
  final List<String> targetFunctions;
  final List<String> sourceFunctions;
  final List<String> sinkFunctions;
  final List<String> validatorFunctions;

  IivRule({
    required this.id,
    required this.name,
    required this.description,
    required this.diagnosticSeverity,
    required this.securitySeverity,
    required this.defaultConfidence,
    required this.category,
    required this.remediation,
    required this.cwe,
    required this.checkKey,
    required this.enabled,
    required this.targetFunctions,
    required this.sourceFunctions,
    required this.sinkFunctions,
    required this.validatorFunctions,
  });

  /// Backward-compatible getter used by older analyzer code.
  String get severity => diagnosticSeverity;

  factory IivRule.fromJson(Map<String, dynamic> json) {
    return IivRule(
      id: json['id'] as String? ?? '',
      name: json['name'] as String? ?? '',
      description: json['description'] as String? ?? '',
      diagnosticSeverity:
          json['diagnosticSeverity'] as String? ??
          json['severity'] as String? ??
          'warning',
      securitySeverity: json['securitySeverity'] as String? ?? 'low',
      defaultConfidence: json['defaultConfidence'] as String? ?? 'medium',
      category: json['category'] as String? ?? 'vulnerability',
      remediation: json['remediation'] as String? ?? '',
      cwe: json['cwe'] as String?,
      checkKey: json['checkKey'] as String? ?? '',
      enabled: json['enabled'] as bool? ?? true,
      targetFunctions: _stringList(json['targetFunctions']),
      sourceFunctions: _stringList(json['sourceFunctions']),
      sinkFunctions: _stringList(json['sinkFunctions']),
      validatorFunctions: _stringList(json['validatorFunctions']),
    );
  }

  static List<String> _stringList(dynamic value) {
    if (value is! List) return const [];
    return value.whereType<String>().toList(growable: false);
  }
}

class IivRulesEngine {
  final List<IivRule> _rules = [];

  List<IivRule> get allRules => List.unmodifiable(_rules);

  void loadRules(List<Map<String, dynamic>> rawRules) {
    _rules.clear();
    for (final json in rawRules) {
      try {
        final rule = IivRule.fromJson(json);
        if (rule.id.isNotEmpty && rule.checkKey.isNotEmpty) {
          _rules.add(rule);
        }
      } catch (_) {
        // Ignore an invalid rule and continue loading the remaining rules.
      }
    }
  }

  IivRule? ruleFor(String checkKey) {
    for (final rule in _rules) {
      if (rule.enabled && rule.checkKey == checkKey) return rule;
    }
    return null;
  }

  IivRule? ruleForFunction(String functionName) {
    for (final rule in _rules) {
      if (rule.enabled && rule.targetFunctions.contains(functionName)) {
        return rule;
      }
    }
    return null;
  }

  bool isDeepLinkSource(String functionName) {
    final rule = ruleFor('deep_link_poisoning');
    return rule?.sourceFunctions.contains(functionName) ?? false;
  }

  bool isDeepLinkSink(String functionName) {
    final rule = ruleFor('deep_link_poisoning');
    return rule?.sinkFunctions.contains(functionName) ?? false;
  }

  String ruleId(String checkKey) =>
      ruleFor(checkKey)?.id ?? 'FLUSEC.IIV.UNKNOWN';

  String message(String checkKey) =>
      ruleFor(checkKey)?.description ?? 'Input validation issue detected';

  String severity(String checkKey) =>
      ruleFor(checkKey)?.diagnosticSeverity ?? 'warning';
}
