// lib/ids/ids_models.dart
//
// IDS-specific data models for insecure data storage detection

/// Represents a detected insecure data storage issue
class IDSIssue {
  final String ruleId;
  final String message;
  final String severity;
  final int line;
  final int column;
  final String codeSnippet;
  final String dataType;
  final String storageContext;
  final String riskLevel;
  final String recommendation;

  IDSIssue({
    required this.ruleId,
    required this.message,
    required this.severity,
    required this.line,
    required this.column,
    required this.codeSnippet,
    required this.dataType,
    required this.storageContext,
    required this.riskLevel,
    required this.recommendation,
  });

  /// Convert issue to JSON for extension consumption
  Map<String, dynamic> toJson() {
    return {
      'ruleId': ruleId,
      'message': message,
      'severity': severity,
      'line': line,
      'column': column,
      'codeSnippet': codeSnippet,
      'dataType': dataType,
      'storageContext': storageContext,
      'riskLevel': riskLevel,
      'recommendation': recommendation,
    };
  }

  /// Create issue from JSON
  factory IDSIssue.fromJson(Map<String, dynamic> json) {
    return IDSIssue(
      ruleId: json['ruleId'] as String,
      message: json['message'] as String,
      severity: json['severity'] as String,
      line: json['line'] as int,
      column: json['column'] as int,
      codeSnippet: json['codeSnippet'] as String,
      dataType: json['dataType'] as String,
      storageContext: json['storageContext'] as String,
      riskLevel: json['riskLevel'] as String,
      recommendation: json['recommendation'] as String,
    );
  }

  @override
  String toString() {
    return 'IDSIssue{ruleId: $ruleId, severity: $severity, line: $line, dataType: $dataType}';
  }
}
