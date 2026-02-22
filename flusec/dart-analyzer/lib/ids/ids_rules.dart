// lib/ids/ids_rules.dart
//
// IDS Rules Engine — mirrors NetworkRulesEngine pattern.
// Rules are loaded from insecure_data_storage_rules.json via the rule repo,
// NOT hardcoded. This enables cloud-managed rule updates.

import 'dart:io';

class IdsRule {
  final String id;
  final String checkKey;       // e.g. 'shared_prefs', 'file_storage', etc.
  final String name;
  final String description;
  final String severity;       // warning | error
  final String remediation;
  final List<String> patterns;
  final String category;
  final List<String> dataTypes;
  final String riskLevel;      // CRITICAL | HIGH | MEDIUM | LOW
  final List<String> requiresImport;

  IdsRule({
    required this.id,
    required this.checkKey,
    required this.name,
    required this.description,
    required this.severity,
    required this.remediation,
    required this.patterns,
    required this.category,
    this.dataTypes = const [],
    this.riskLevel = 'MEDIUM',
    this.requiresImport = const [],
  });

  factory IdsRule.fromJson(Map<String, dynamic> json) {
    return IdsRule(
      id: json['id'] as String? ?? '',
      checkKey: json['checkKey'] as String? ?? '',
      name: json['name'] as String? ?? '',
      description: json['description'] as String? ?? '',
      severity: json['severity'] as String? ?? 'warning',
      remediation: json['remediation'] as String? ?? '',
      patterns: (json['patterns'] as List<dynamic>?)?.cast<String>() ?? [],
      category: json['category'] as String? ?? 'insecure_storage',
      dataTypes: (json['dataTypes'] as List<dynamic>?)?.cast<String>() ?? [],
      riskLevel: json['riskLevel'] as String? ?? 'MEDIUM',
      requiresImport: (json['requiresImport'] as List<dynamic>?)?.cast<String>() ?? [],
    );
  }
}

/// Rules engine for IDS component — loaded from JSON (rule repo approach).
class IdsRulesEngine {
  final Map<String, IdsRule> _byKey = {};

  /// Load rules from parsed JSON list (from insecure_data_storage_rules.json).
  void loadRules(List<Map<String, dynamic>> rawRules) {
    _byKey.clear();
    for (final raw in rawRules) {
      try {
        final rule = IdsRule.fromJson(raw);
        if (rule.checkKey.isNotEmpty) {
          _byKey[rule.checkKey] = rule;
        }
      } catch (e) {
        stderr.writeln('[IDS] Warning: failed to load rule: $e');
      }
    }
    stderr.writeln('[IDS] ✅ Loaded ${_byKey.length} storage rule(s).');
  }

  IdsRule? ruleFor(String checkKey) => _byKey[checkKey];
  String ruleId(String checkKey) => _byKey[checkKey]?.id ?? 'FLUSEC.IDS.UNKNOWN';
  String message(String checkKey) => _byKey[checkKey]?.description ?? 'Insecure data storage detected.';
  String severity(String checkKey) => _byKey[checkKey]?.severity ?? 'warning';
  String riskLevel(String checkKey) => _byKey[checkKey]?.riskLevel ?? 'MEDIUM';
  String remediation(String checkKey) => _byKey[checkKey]?.remediation ?? '';
  List<String> dataTypes(String checkKey) => _byKey[checkKey]?.dataTypes ?? [];
  List<String> patterns(String checkKey) => _byKey[checkKey]?.patterns ?? [];
  List<String> requiresImport(String checkKey) => _byKey[checkKey]?.requiresImport ?? [];

  List<IdsRule> get allRules => _byKey.values.toList();
}