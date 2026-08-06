// lib/ids/heuristic_analyzer.dart
//
// Lightweight sensitive-data classification used by IDS.
// This module intentionally does not perform vendor secret-pattern matching or
// entropy-based hardcoded-secret detection. Those responsibilities belong to
// the HSD component.

class SensitivityResult {
  final bool isSensitive;
  final String dataType;
  final double confidenceScore;
  final List<String> matchedKeywords;

  const SensitivityResult({
    required this.isSensitive,
    required this.dataType,
    required this.confidenceScore,
    required this.matchedKeywords,
  });
}

class SensitiveVariableAnalyzer {
  static const Map<String, List<String>> keywordCategories = {
    'CREDENTIALS': [
      'password',
      'passwd',
      'pwd',
      'secret',
      'token',
      'authToken',
      'auth_token',
      'accessToken',
      'access_token',
      'refreshToken',
      'refresh_token',
      'bearerToken',
      'bearer_token',
      'apiKey',
      'api_key',
      'credential',
      'credentials',
      'privateKey',
      'private_key',
      'sessionId',
      'session_id',
      'sessionToken',
      'session_token',
    ],
    'PII': [
      'email',
      'phoneNumber',
      'phone_number',
      'homeAddress',
      'home_address',
      'postalAddress',
      'postal_address',
      'firstName',
      'first_name',
      'lastName',
      'last_name',
      'fullName',
      'full_name',
      'dateOfBirth',
      'date_of_birth',
      'birthDate',
      'birth_date',
      'passportNumber',
      'passport_number',
      'nationalId',
      'national_id',
      'nicNumber',
      'nic_number',
    ],
    'FINANCIAL': [
      'creditCard',
      'credit_card',
      'cardNumber',
      'card_number',
      'cvv',
      'cvc',
      'bankAccount',
      'bank_account',
      'accountNumber',
      'account_number',
      'routingNumber',
      'routing_number',
      'iban',
      'swiftCode',
      'swift_code',
    ],
    'HEALTH': [
      'medicalRecord',
      'medical_record',
      'healthData',
      'health_data',
      'diagnosis',
      'prescription',
      'patientRecord',
      'patient_record',
      'insuranceNumber',
      'insurance_number',
    ],
  };

  SensitivityResult analyze(String value) {
    final normalized = _normalize(value);
    final matches = <String>[];
    var dataType = 'GENERIC_SENSITIVE';
    var confidence = 0.0;

    for (final entry in keywordCategories.entries) {
      for (final keyword in entry.value) {
        final normalizedKeyword = _normalize(keyword);
        if (!normalized.contains(normalizedKeyword)) continue;

        matches.add(keyword);
        final currentConfidence = _confidenceForMatch(
          normalized,
          normalizedKeyword,
        );

        if (currentConfidence > confidence) {
          confidence = currentConfidence;
          dataType = entry.key;
        }
      }
    }

    return SensitivityResult(
      isSensitive: matches.isNotEmpty,
      dataType: dataType,
      confidenceScore: confidence,
      matchedKeywords: matches,
    );
  }

  String _normalize(String value) {
    return value.toLowerCase().replaceAll(RegExp(r'[^a-z0-9]'), '');
  }

  double _confidenceForMatch(String value, String keyword) {
    if (value == keyword) return 1.0;
    if (value.startsWith(keyword) || value.endsWith(keyword)) return 0.9;
    return 0.75;
  }
}

class IdsSeverityClassifier {
  String classify({
    required String baseSeverity,
    required String dataType,
    required String storageContext,
  }) {
    final normalizedBase = baseSeverity.toLowerCase();

    if (storageContext == 'external_storage' &&
        const {'CREDENTIALS', 'FINANCIAL', 'HEALTH'}.contains(dataType)) {
      return 'critical';
    }

    if (const {'CREDENTIALS', 'FINANCIAL', 'HEALTH'}.contains(dataType)) {
      return _maxSeverity(normalizedBase, 'high');
    }

    if (dataType == 'PII') {
      return _maxSeverity(normalizedBase, 'medium');
    }

    return normalizedBase;
  }

  String _maxSeverity(String left, String right) {
    const rank = {
      'low': 1,
      'medium': 2,
      'high': 3,
      'critical': 4,
    };

    return (rank[left] ?? 1) >= (rank[right] ?? 1) ? left : right;
  }
}
