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
  
  // New fields for enhanced detection
  final List<String> dataTypes; // Types of sensitive data: CREDENTIALS, PII, FINANCIAL, etc.
  final String riskLevel; // CRITICAL, HIGH, MEDIUM, LOW
  final List<String> requiresImport; // Required imports to trigger rule
  final List<String> pathPatterns; // File path patterns for storage location rules

  InsecureStorageRule({
    required this.id,
    required this.name,
    required this.description,
    required this.severity,
    required this.remediation,
    required this.patterns,
    required this.category,
    this.dataTypes = const [],
    this.riskLevel = 'MEDIUM',
    this.requiresImport = const [],
    this.pathPatterns = const [],
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
      dataTypes: json['dataTypes'] != null 
          ? (json['dataTypes'] as List<dynamic>).cast<String>() 
          : [],
      riskLevel: json['riskLevel'] as String? ?? 'MEDIUM',
      requiresImport: json['requiresImport'] != null
          ? (json['requiresImport'] as List<dynamic>).cast<String>()
          : [],
      pathPatterns: json['pathPatterns'] != null
          ? (json['pathPatterns'] as List<dynamic>).cast<String>()
          : [],
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
      'dataTypes': dataTypes,
      'riskLevel': riskLevel,
      'requiresImport': requiresImport,
      'pathPatterns': pathPatterns,
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
      dataTypes: ['CREDENTIALS', 'PII'],
      riskLevel: 'HIGH',
      requiresImport: ['package:shared_preferences/shared_preferences.dart'],
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
        'writeStringSync',
      ],
      category: 'insecure_storage',
      dataTypes: ['CREDENTIALS', 'PII', 'FINANCIAL'],
      riskLevel: 'HIGH',
      requiresImport: ['dart:io'],
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
        'execute',
      ],
      category: 'insecure_storage',
      dataTypes: ['CREDENTIALS', 'PII', 'FINANCIAL'],
      riskLevel: 'MEDIUM',
      requiresImport: ['package:sqflite/sqflite.dart'],
    ));

    // Rule 10: Hardcoded Sensitive Storage Keys (moved from IDS-004)
    _rules.add(InsecureStorageRule(
      id: 'IDS-010',
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
      dataTypes: ['CREDENTIALS'],
      riskLevel: 'MEDIUM',
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
        'getApplicationSupportDirectory',
        'cache',
        'temp',
        'Directory.systemTemp',
      ],
      category: 'insecure_storage',
      dataTypes: ['CREDENTIALS', 'PII'],
      riskLevel: 'MEDIUM',
      requiresImport: ['package:path_provider/path_provider.dart'],
      pathPatterns: ['tmp', 'cache', 'temp'],
    ));

    // Rule 4: External Public Storage (NEW)
    _rules.add(InsecureStorageRule(
      id: 'IDS-004',
      name: 'External Public Storage',
      description: 'Sensitive data written to external/public storage directories',
      severity: 'CRITICAL',
      remediation: 'Use internal app storage (getApplicationDocumentsDirectory) with encryption',
      patterns: [
        'getExternalStorageDirectory',
        'getExternalStorageDirectories',
      ],
      category: 'insecure_storage',
      dataTypes: ['ANY_SENSITIVE'],
      riskLevel: 'CRITICAL',
      requiresImport: ['package:path_provider/path_provider.dart'],
      pathPatterns: ['/sdcard', '/storage/', 'external'],
    ));

    // Rule 6: WebView LocalStorage (NEW)
    _rules.add(InsecureStorageRule(
      id: 'IDS-006',
      name: 'WebView LocalStorage Usage',
      description: 'Sensitive data stored in WebView localStorage/sessionStorage',
      severity: 'HIGH',
      remediation: 'Avoid storing sensitive data in WebView storage; use secure native storage',
      patterns: [
        'runJavascript',
        'evaluateJavascript',
        'localStorage.setItem',
        'sessionStorage.setItem',
        'document.cookie',
      ],
      category: 'insecure_storage',
      dataTypes: ['CREDENTIALS', 'PII'],
      riskLevel: 'HIGH',
    ));

    // Rule 7: Insecure Serialization (NEW)
    _rules.add(InsecureStorageRule(
      id: 'IDS-007',
      name: 'Insecure Serialization',
      description: 'Serialized objects with sensitive fields written to disk without encryption',
      severity: 'HIGH',
      remediation: 'Encrypt serialized data before writing to disk or exclude sensitive fields',
      patterns: [
        'jsonEncode',
        'toJson',
      ],
      category: 'insecure_storage',
      dataTypes: ['CREDENTIALS', 'PII', 'FINANCIAL'],
      riskLevel: 'HIGH',
      requiresImport: ['dart:convert'],
    ));

    // Rule 8: Logging Secrets (NEW)
    _rules.add(InsecureStorageRule(
      id: 'IDS-008',
      name: 'Logging Secrets',
      description: 'Sensitive data logged to console or analytics (may persist in crash logs)',
      severity: 'MEDIUM',
      remediation: 'Remove sensitive data from logs or use conditional logging (debug-only)',
      patterns: [
        'print',
        'debugPrint',
        'log',
        'Logger',
      ],
      category: 'insecure_storage',
      dataTypes: ['CREDENTIALS', 'PII'],
      riskLevel: 'MEDIUM',
    ));

    // Rule 9: Unprotected Backup (NEW)
    _rules.add(InsecureStorageRule(
      id: 'IDS-009',
      name: 'Unprotected Backup',
      description: 'App data backups created in user-accessible locations',
      severity: 'HIGH',
      remediation: 'Encrypt backups and store in secure internal directories',
      patterns: [
        'backup',
        'export',
        'share',
        'copy',
      ],
      category: 'insecure_storage',
      dataTypes: ['ANY_SENSITIVE'],
      riskLevel: 'HIGH',
      pathPatterns: ['backup.db', '.bak', 'export', '/sdcard'],
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
