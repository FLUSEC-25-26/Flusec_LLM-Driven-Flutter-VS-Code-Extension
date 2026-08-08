// lib/net/network_rules.dart
//
// Rule definitions for FLUSEC Insecure Network Communication (NET).
//
// The AST visitor owns detection logic. This rules engine only supplies
// policy metadata such as rule ID, diagnostic severity, security severity,
// confidence, remediation, and CWE information.

import 'dart:io';

class NetworkRule {
  final String id;
  final String checkKey;
  final String name;

  /// VS Code diagnostic severity. During the current FLUSEC research phase,
  /// security findings are intentionally emitted as warnings.
  final String severity;

  /// Security impact, independent from the editor diagnostic severity.
  final String securitySeverity;

  /// Default detector confidence for this rule.
  final String defaultConfidence;

  final String category;
  final String description;
  final String messageTemplate;
  final String remediation;
  final String? cwe;
  final bool enabled;

  NetworkRule({
    required this.id,
    required this.checkKey,
    required this.name,
    required this.severity,
    required this.securitySeverity,
    required this.defaultConfidence,
    required this.category,
    required this.description,
    required this.messageTemplate,
    required this.remediation,
    required this.cwe,
    required this.enabled,
  });

  static NetworkRule? tryFromJson(Map<String, dynamic> raw) {
    try {
      final id = (raw['id'] ?? '').toString().trim();
      final checkKey = (raw['checkKey'] ?? '').toString().trim();
      if (id.isEmpty || checkKey.isEmpty) return null;

      return NetworkRule(
        id: id,
        checkKey: checkKey,
        name: (raw['name'] ?? id).toString().trim(),
        severity: (raw['severity'] ?? 'warning').toString().trim(),
        securitySeverity:
            (raw['securitySeverity'] ?? 'medium').toString().trim(),
        defaultConfidence:
            (raw['defaultConfidence'] ?? 'medium').toString().trim(),
        category: (raw['category'] ?? 'vulnerability').toString().trim(),
        description: (raw['description'] ?? '').toString().trim(),
        messageTemplate:
            (raw['messageTemplate'] ?? 'Network security issue detected.')
                .toString()
                .trim(),
        remediation: (raw['remediation'] ?? '').toString().trim(),
        cwe: raw['cwe']?.toString().trim(),
        enabled: (raw['enabled'] as bool?) ?? true,
      );
    } catch (_) {
      return null;
    }
  }
}

class NetworkRulesEngine {
  final Map<String, NetworkRule> _rulesByKey = {};

  void loadRules(List<Map<String, dynamic>> rawRules) {
    _rulesByKey.clear();

    for (final raw in rawRules) {
      final rule = NetworkRule.tryFromJson(raw);
      if (rule != null && rule.enabled) {
        _rulesByKey[rule.checkKey] = rule;
      }
    }

    if (_rulesByKey.isEmpty) {
      stderr.writeln(
        '[NET] No valid network rules loaded -> network detection disabled.',
      );
    } else {
      stderr.writeln('[NET] Loaded ${_rulesByKey.length} network rule(s).');
    }
  }

  NetworkRule? ruleFor(String checkKey) => _rulesByKey[checkKey];

  String ruleId(String checkKey) =>
      _rulesByKey[checkKey]?.id ?? 'FLUSEC.NET.${checkKey.toUpperCase()}';

  String message(String checkKey) =>
      _rulesByKey[checkKey]?.messageTemplate ??
      'Network security issue detected.';

  String severity(String checkKey) =>
      _rulesByKey[checkKey]?.severity ?? 'warning';
}
