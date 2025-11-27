import 'dart:convert';

class SecurityRule {
  final String id;
  final String description;
  final String severity;
  final String category;
  final String remediation;
  final List<String> patterns;

  SecurityRule({
    required this.id,
    required this.description,
    required this.severity,
    required this.category,
    required this.remediation,
    required this.patterns,
  });

  factory SecurityRule.fromJson(Map<String, dynamic> json) {
    return SecurityRule(
      id: json['id'],
      description: json['description'],
      severity: json['severity'],
      category: json['category'],
      remediation: json['remediation'],
      patterns: List<String>.from(json['patterns'] ?? []),
    );
  }
}

class Finding {
  final String ruleId;
  final String message;
  final String severity;
  final String filePath;
  final int lineNumber;
  final int columnNumber;
  final String codeSnippet;
  final String remediation;

  Finding({
    required this.ruleId,
    required this.message,
    required this.severity,
    required this.filePath,
    required this.lineNumber,
    required this.columnNumber,
    required this.codeSnippet,
    required this.remediation,
  });

  Map<String, dynamic> toJson() {
    return {
      'ruleId': ruleId,
      'message': message,
      'severity': severity,
      'filePath': filePath,
      'lineNumber': lineNumber,
      'columnNumber': columnNumber,
      'codeSnippet': codeSnippet,
      'remediation': remediation,
    };
  }
}
