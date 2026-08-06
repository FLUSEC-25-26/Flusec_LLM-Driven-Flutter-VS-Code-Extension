// lib/ids/ids_rules.dart
//
// Policy-driven rules for the Insecure Data Storage (IDS) component.
//
// IMPORTANT:
// - diagnosticSeverity controls VS Code presentation. FLUSEC currently uses
//   warning for all security findings.
// - securitySeverity describes the possible security impact.
// - confidence describes how certain the detector is about the finding.

import 'dart:io';

class IdsRule {
  final String id;
  final String checkKey;
  final String name;
  final String description;

  /// VS Code diagnostic severity: error | warning | information | hint.
  final String diagnosticSeverity;

  /// Security impact: critical | high | medium | low.
  final String securitySeverity;

  /// Default detection confidence: high | medium | low.
  final String defaultConfidence;

  final String category;
  final String remediation;
  final String? cwe;
  final bool enabled;
  final List<String> targetFunctions;
  final List<String> requiresImport;

  IdsRule({
    required this.id,
    required this.checkKey,
    required this.name,
    required this.description,
    required this.diagnosticSeverity,
    required this.securitySeverity,
    required this.defaultConfidence,
    required this.category,
    required this.remediation,
    required this.cwe,
    required this.enabled,
    required this.targetFunctions,
    required this.requiresImport,
  });

  /// Backward-compatible alias used by older code.
  String get severity => diagnosticSeverity;

  factory IdsRule.fromJson(Map<String, dynamic> json) {
    return IdsRule(
      id: json['id'] as String? ?? '',
      checkKey: json['checkKey'] as String? ?? '',
      name: json['name'] as String? ?? '',
      description: json['description'] as String? ?? '',
      diagnosticSeverity:
          json['diagnosticSeverity'] as String? ??
          json['severity'] as String? ??
          'warning',
      securitySeverity: json['securitySeverity'] as String? ?? 'medium',
      defaultConfidence: json['defaultConfidence'] as String? ?? 'medium',
      category: json['category'] as String? ?? 'vulnerability',
      remediation: json['remediation'] as String? ?? '',
      cwe: json['cwe'] as String?,
      enabled: json['enabled'] as bool? ?? true,
      targetFunctions: _stringList(
        json['targetFunctions'] ?? json['patterns'],
      ),
      requiresImport: _stringList(json['requiresImport']),
    );
  }

  static List<String> _stringList(dynamic value) {
    if (value is! List) return const [];
    return value.whereType<String>().toList(growable: false);
  }
}

class IdsRulesEngine {
  final List<IdsRule> _rules = [];

  List<IdsRule> get allRules => List.unmodifiable(_rules);

  void loadRules(List<Map<String, dynamic>> rawRules) {
    _rules.clear();

    for (final json in rawRules) {
      try {
        final rule = IdsRule.fromJson(json);
        if (rule.id.isNotEmpty && rule.checkKey.isNotEmpty) {
          _rules.add(rule);
        }
      } catch (error) {
        stderr.writeln('[IDS] Failed to load a rule: $error');
      }
    }

    stderr.writeln('[IDS] Loaded ${_rules.length} storage rule(s).');
  }

  IdsRule? ruleFor(String checkKey) {
    for (final rule in _rules) {
      if (rule.enabled && rule.checkKey == checkKey) return rule;
    }
    return null;
  }

  IdsRule? ruleForFunction(String functionName) {
    for (final rule in _rules) {
      if (rule.enabled && rule.targetFunctions.contains(functionName)) {
        return rule;
      }
    }
    return null;
  }

  String ruleId(String checkKey) =>
      ruleFor(checkKey)?.id ?? 'FLUSEC.IDS.UNKNOWN';

  String message(String checkKey) =>
      ruleFor(checkKey)?.description ??
      'Potential insecure storage of sensitive data.';

  String severity(String checkKey) =>
      ruleFor(checkKey)?.diagnosticSeverity ?? 'warning';
}
