// lib/ids/insecure_storage_rules.dart
//
// Rules for detecting insecure data storage patterns in Flutter/Dart applications

class InsecureStorageRule {
  final String id;
  final String name;
  final String description;
  final String severity;
  final String remediation;
  final List<String> patterns;
  final String category;

  InsecureStorageRule({
    required this.id,
    required this.name,
    required this.description,
    required this.severity,
    required this.remediation,
    required this.patterns,
    required this.category,
  });

  factory InsecureStorageRule.fromJson(Map<String, dynamic> json) {
    return InsecureStorageRule(
      id: json['id'] as String,
      name: json['name'] as String,
      description: json['description'] as String,
      severity: json['severity'] as String,
      remediation: json['remediation'] as String,
      patterns: (json['patterns'] as List<dynamic>).cast<String>(),
      category: json['category'] as String? ?? 'insecure_storage',
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'name': name,
      'description': description,
      'severity': severity,
      'remediation': remediation,
      'patterns': patterns,
      'category': category,
    };
  }
}

class InsecureStorageRulesEngine {
  final List<InsecureStorageRule> _rules = [];

  InsecureStorageRulesEngine() {
    _loadBuiltInRules();
  }

  void _loadBuiltInRules() {
    // Rule 1: Unencrypted SharedPreferences
    _rules.add(InsecureStorageRule(
      id: 'IDS-001',
      name: 'Unencrypted SharedPreferences',
      description: 'Sensitive data stored in SharedPreferences without encryption',
      severity: 'HIGH',
      remediation: 'Use flutter_secure_storage or encrypt data before storing in SharedPreferences',
      patterns: [
        'SharedPreferences',
        'setString',
        'setInt',
        'setBool',
        'setDouble',
        'setStringList',
      ],
      category: 'insecure_storage',
    ));

    // Rule 2: Unencrypted File Storage
    _rules.add(InsecureStorageRule(
      id: 'IDS-002',
      name: 'Unencrypted File Storage',
      description: 'Sensitive data written to files without encryption',
      severity: 'HIGH',
      remediation: 'Encrypt sensitive data before writing to files using packages like encrypt or pointycastle',
      patterns: [
        'File(',
        'writeAsString',
        'writeAsBytes',
        'openWrite',
      ],
      category: 'insecure_storage',
    ));

    // Rule 3: Insecure SQLite Storage
    _rules.add(InsecureStorageRule(
      id: 'IDS-003',
      name: 'Insecure SQLite Storage',
      description: 'Sensitive data stored in SQLite database without encryption',
      severity: 'MEDIUM',
      remediation: 'Use sqflite_sqlcipher or encrypt sensitive columns before storing',
      patterns: [
        'sqflite',
        'openDatabase',
        'insert',
        'rawInsert',
      ],
      category: 'insecure_storage',
    ));

    // Rule 4: Hardcoded Sensitive Storage Keys
    _rules.add(InsecureStorageRule(
      id: 'IDS-004',
      name: 'Hardcoded Sensitive Storage Keys',
      description: 'Sensitive keys or identifiers hardcoded in storage operations',
      severity: 'MEDIUM',
      remediation: 'Use secure key management and avoid hardcoding sensitive identifiers',
      patterns: [
        'password',
        'token',
        'api_key',
        'secret',
        'auth',
        'credential',
      ],
      category: 'insecure_storage',
    ));

    // Rule 5: Insecure Cache Storage
    _rules.add(InsecureStorageRule(
      id: 'IDS-005',
      name: 'Insecure Cache Storage',
      description: 'Sensitive data stored in application cache without protection',
      severity: 'MEDIUM',
      remediation: 'Avoid caching sensitive data or use encrypted cache storage',
      patterns: [
        'CacheManager',
        'getTemporaryDirectory',
        'cache',
      ],
      category: 'insecure_storage',
    ));
  }

  void loadDynamicRules(List<Map<String, dynamic>> rawRules) {
    for (final ruleJson in rawRules) {
      try {
        final rule = InsecureStorageRule.fromJson(ruleJson);
        _rules.add(rule);
      } catch (e) {
        // Skip invalid rules
        print('Warning: Failed to load rule: $e');
      }
    }
  }

  List<InsecureStorageRule> get rules => List.unmodifiable(_rules);

  InsecureStorageRule? getRuleById(String id) {
    try {
      return _rules.firstWhere((r) => r.id == id);
    } catch (e) {
      return null;
    }
  }
}
