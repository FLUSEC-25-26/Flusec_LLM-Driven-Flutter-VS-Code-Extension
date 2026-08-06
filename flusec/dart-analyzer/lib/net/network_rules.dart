// lib/net/network_rules.dart
//
// Rule definitions for Insecure Network Communication component.
//
// DESIGN:
// The NetworkVisitor detects patterns using AST analysis (the ALGORITHM).
// Each detection has a "check key" (e.g. 'http_url', 'websocket_insecure').
// This rules engine maps check keys → rule ID, message template, severity, enabled.
//
// Rules are loaded ONLY from insecure_network_rules.json (from rulepack repo).
// If no rules file is found, no rules are loaded and detections are skipped.
// The extension handles offline fallback via bundled baseline files
// (same approach as HSD).

import 'dart:io';

class NetworkRule {
  final String id;
  final String checkKey; // maps to a specific detection in NetworkVisitor
  final String name;
  final String severity;
  final String messageTemplate;
  final bool enabled;

  NetworkRule({
    required this.id,
    required this.checkKey,
    required this.name,
    required this.severity,
    required this.messageTemplate,
    required this.enabled,
  });

  static NetworkRule? tryFromJson(Map<String, dynamic> r) {
    try {
      final enabled = (r['enabled'] as bool?) ?? true;
      final id = (r['id'] ?? '').toString().trim();
      final checkKey = (r['checkKey'] ?? '').toString().trim();
      if (id.isEmpty || checkKey.isEmpty) return null;

      return NetworkRule(
        id: id,
        checkKey: checkKey,
        name: (r['name'] ?? id).toString().trim(),
        severity: (r['severity'] as String?) ?? 'warning',
        messageTemplate: (r['messageTemplate'] as String?) ?? '',
        enabled: enabled,
      );
    } catch (_) {
      return null;
    }
  }
}

class NetworkRulesEngine {
  final Map<String, NetworkRule> _rulesByKey = {};

  /// Load rules from parsed JSON array (from insecure_network_rules.json).
  /// Each rule must have a 'checkKey' that maps to a detection in NetworkVisitor.
  void loadRules(List<Map<String, dynamic>> raw) {
    _rulesByKey.clear();

    for (final r in raw) {
      final rule = NetworkRule.tryFromJson(r);
      if (rule != null && rule.enabled) {
        _rulesByKey[rule.checkKey] = rule;
      }
    }

    if (_rulesByKey.isEmpty) {
      stderr.writeln(
        '[NET] ❌ No valid network rules loaded → network detection DISABLED.',
      );
    } else {
      stderr.writeln('[NET] ✅ Loaded ${_rulesByKey.length} network rule(s).');
    }
  }

  /// Check if a detection (by checkKey) is enabled.
  /// Returns null if the checkKey has no rule or is disabled.
  NetworkRule? ruleFor(String checkKey) => _rulesByKey[checkKey];

  /// Get rule ID for a check key.
  String ruleId(String checkKey) =>
      _rulesByKey[checkKey]?.id ?? 'FLUSEC.NETWORK.${checkKey.toUpperCase()}';

  /// Get the message for a check key, with optional context substitution.
  String message(String checkKey, {String? context}) {
    final rule = _rulesByKey[checkKey];
    if (rule == null) return context ?? 'Network security issue detected.';

    if (context != null && context.isNotEmpty) {
      return '${rule.messageTemplate} ($context)';
    }
    return rule.messageTemplate;
  }

  /// Get severity for a check key.
  String severity(String checkKey) =>
      _rulesByKey[checkKey]?.severity ?? 'warning';
}
