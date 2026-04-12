// lib/iiv/iiv_rules.dart
//
// IIV (Insufficient Input Validation) rules engine.
// Loads detection rules from JSON (rule-repo approach).
// Follows the same pattern as NetworkRulesEngine and IdsRulesEngine.

class IivRule {
  final String id;
  final String name;
  final String description;
  final String severity;
  final String remediation;
  final String checkKey;
  final List<String> targetFunctions;

  IivRule({
    required this.id,
    required this.name,
    required this.description,
    required this.severity,
    required this.remediation,
    required this.checkKey,
    required this.targetFunctions,
  });

  factory IivRule.fromJson(Map<String, dynamic> json) {
    return IivRule(
      id: json['id'] as String? ?? '',
      name: json['name'] as String? ?? '',
      description: json['description'] as String? ?? '',
      severity: json['severity'] as String? ?? 'warning',
      remediation: json['remediation'] as String? ?? '',
      checkKey: json['checkKey'] as String? ?? '',
      targetFunctions: json['targetFunctions'] != null
          ? (json['targetFunctions'] as List<dynamic>).cast<String>()
          : [],
    );
  }
}

class IivRulesEngine {
  final List<IivRule> _rules = [];

  List<IivRule> get allRules => List.unmodifiable(_rules);

  void loadRules(List<Map<String, dynamic>> rawRules) {
    _rules.clear();
    for (final json in rawRules) {
      try {
        _rules.add(IivRule.fromJson(json));
      } catch (_) {}
    }
  }

  IivRule? ruleFor(String checkKey) {
    for (final r in _rules) {
      if (r.checkKey == checkKey) return r;
    }
    return null;
  }

  IivRule? ruleForFunction(String functionName) {
    for (final r in _rules) {
      if (r.targetFunctions.contains(functionName)) return r;
    }
    return null;
  }

  String ruleId(String checkKey) => ruleFor(checkKey)?.id ?? 'FLUSEC.IIV.UNKNOWN';
  String message(String checkKey) => ruleFor(checkKey)?.description ?? 'Input validation issue detected';
  String severity(String checkKey) => ruleFor(checkKey)?.severity ?? 'warning';
}