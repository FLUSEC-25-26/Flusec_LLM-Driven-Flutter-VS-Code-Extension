// lib/ids/heuristic_analyzer.dart
//
// Heuristic analysis for sensitive variable naming and severity classification

/// Result of sensitive variable analysis
class SensitivityResult {
  final bool isSensitive;
  final String dataType; // CREDENTIALS, PII, FINANCIAL, HEALTH, GENERIC_SENSITIVE
  final double confidenceScore; // 0.0 to 1.0
  final List<String> matchedKeywords;

  SensitivityResult({
    required this.isSensitive,
    required this.dataType,
    required this.confidenceScore,
    required this.matchedKeywords,
  });
}

/// Analyzes variable names to detect sensitive data
class SensitiveVariableAnalyzer {
  // Keyword categories with confidence weights
  static const Map<String, List<String>> keywordCategories = {
    'CREDENTIALS': [
      'password', 'passwd', 'pwd', 'pass',
      'secret', 'token', 'auth', 'authentication',
      'apikey', 'api_key', 'accesstoken', 'access_token',
      'refreshtoken', 'refresh_token', 'bearer',
      'credential', 'credentials', 'key', 'privatekey',
      'private_key', 'sessionid', 'session_id',
    ],
    'PII': [
      'ssn', 'social', 'socialsecurity', 'social_security',
      'email', 'phone', 'phonenumber', 'phone_number',
      'address', 'name', 'firstname', 'first_name',
      'lastname', 'last_name', 'dob', 'dateofbirth',
      'date_of_birth', 'birthdate', 'birth_date',
      'license', 'passport', 'userid', 'user_id',
    ],
    'FINANCIAL': [
      'creditcard', 'credit_card', 'cardnumber', 'card_number',
      'cvv', 'cvc', 'pin', 'account', 'accountnumber',
      'account_number', 'routing', 'routingnumber', 'routing_number',
      'balance', 'payment', 'bank', 'bankaccount', 'bank_account',
      'iban', 'swift', 'sortcode', 'sort_code',
    ],
    'HEALTH': [
      'medical', 'health', 'diagnosis', 'prescription',
      'medication', 'patient', 'doctor', 'hospital',
      'insurance', 'healthrecord', 'health_record',
    ],
  };

  /// Analyze a variable name and return sensitivity result
  SensitivityResult analyze(String variableName) {
    final normalized = variableName.toLowerCase().replaceAll(RegExp(r'[_\s-]'), '');
    final matchedKeywords = <String>[];
    String? detectedType;
    double maxConfidence = 0.0;

    // Check each category
    for (final entry in keywordCategories.entries) {
      final category = entry.key;
      final keywords = entry.value;

      for (final keyword in keywords) {
        if (normalized.contains(keyword)) {
          matchedKeywords.add(keyword);
          
          // Calculate confidence based on match quality
          double confidence = 0.5; // Base confidence
          
          // Exact match increases confidence
          if (normalized == keyword) {
            confidence = 1.0;
          } 
          // Starts with keyword
          else if (normalized.startsWith(keyword)) {
            confidence = 0.9;
          }
          // Ends with keyword
          else if (normalized.endsWith(keyword)) {
            confidence = 0.8;
          }
          // Contains keyword
          else {
            confidence = 0.6;
          }

          if (confidence > maxConfidence) {
            maxConfidence = confidence;
            detectedType = category;
          }
        }
      }
    }

    final isSensitive = matchedKeywords.isNotEmpty;
    final dataType = detectedType ?? 'GENERIC_SENSITIVE';

    return SensitivityResult(
      isSensitive: isSensitive,
      dataType: dataType,
      confidenceScore: maxConfidence,
      matchedKeywords: matchedKeywords,
    );
  }

  /// Check if a string literal value looks sensitive
  bool isValueSensitive(String value) {
    // Check for patterns that look like secrets
    if (value.length < 8) return false;

    // High entropy check (simple version)
    final uniqueChars = value.split('').toSet().length;
    final entropy = uniqueChars / value.length;
    
    if (entropy > 0.6 && value.length > 20) {
      return true; // Likely a token or key
    }

    // Pattern checks
    final patterns = [
      RegExp(r'^[A-Za-z0-9+/]{40,}={0,2}$'), // Base64
      RegExp(r'^[0-9a-f]{32,}$'), // Hex strings
      RegExp(r'^[A-Z0-9]{20,}$'), // API keys
      RegExp(r'Bearer\s+[A-Za-z0-9\-._~+/]+=*', caseSensitive: false),
    ];

    return patterns.any((pattern) => pattern.hasMatch(value));
  }
}

/// Classifies severity based on data type and storage context
class SeverityClassifier {
  /// Classify severity based on multiple factors
  String classify({
    required String dataType,
    required String storageType,
    bool isEncrypted = false,
    bool isPublicStorage = false,
  }) {
    // Critical: Sensitive data in public/external storage
    if (isPublicStorage && !isEncrypted) {
      return 'CRITICAL';
    }

    // Critical: Financial or health data unencrypted
    if ((dataType == 'FINANCIAL' || dataType == 'HEALTH') && !isEncrypted) {
      return 'CRITICAL';
    }

    // High: Credentials unencrypted in any storage
    if (dataType == 'CREDENTIALS' && !isEncrypted) {
      return 'HIGH';
    }

    // High: PII in insecure storage
    if (dataType == 'PII' && !isEncrypted && 
        (storageType == 'shared_prefs' || storageType == 'file' || storageType == 'sqlite')) {
      return 'HIGH';
    }

    // Medium: Other sensitive data in logs or cache
    if (storageType == 'log' || storageType == 'cache') {
      return 'MEDIUM';
    }

    // Medium: Generic sensitive data
    if (dataType == 'GENERIC_SENSITIVE') {
      return 'MEDIUM';
    }

    // Low: Encrypted or low-risk scenarios
    if (isEncrypted) {
      return 'LOW';
    }

    return 'MEDIUM'; // Default
  }

  /// Get risk level description
  String getRiskDescription(String riskLevel) {
    switch (riskLevel) {
      case 'CRITICAL':
        return 'Immediate security risk - data may be accessible to unauthorized parties';
      case 'HIGH':
        return 'Significant security risk - sensitive data inadequately protected';
      case 'MEDIUM':
        return 'Moderate security risk - potential for data exposure';
      case 'LOW':
        return 'Low security risk - consider additional hardening';
      default:
        return 'Unknown risk level';
    }
  }
}
