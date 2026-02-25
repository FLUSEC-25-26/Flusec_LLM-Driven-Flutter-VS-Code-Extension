// lib/core/issue.dart
//
// Shared model used by ALL analyzer components.
// HSD fills functionName/complexity/nestingDepth/functionLoc.
// IDS fills riskLevel/dataType/storageContext.
// Other components (network/validation) can set them to null.

class Issue {
  final String filePath;
  final String ruleId;
  final String message;
  final String severity;
  final int line;
  final int column;

  // HSD contribution: where the finding is located and how complex that context is.
  // Other components can ignore these fields or later reuse them.
  final String? functionName;
  final int? complexity;
  final int? nestingDepth;
  final int? functionLoc;

  /// IDS contribution: risk classification and storage metadata.
  final String? riskLevel;      // CRITICAL | HIGH | MEDIUM | LOW
  final String? dataType;       // e.g. PASSWORD, API_KEY, GENERIC_SENSITIVE
  final String? storageContext; // e.g. shared_prefs, file, sqlite, log

  /// Which component produced this issue.
  /// Values: 'hsd', 'net', 'ids', 'iiv'
  final String component;

  Issue(
    this.filePath,
    this.ruleId,
    this.message,
    this.severity,
    this.line,
    this.column, {
    this.functionName,
    this.complexity,
    this.nestingDepth,
    this.functionLoc,
    this.riskLevel,
    this.dataType,
    this.storageContext,
    this.component = 'hsd',
  });
}