// lib/core/issue.dart
//
// Shared model used by ALL analyzer components.
// HSD fills functionName/complexity/nestingDepth/functionLoc.
// Other components (network/storage/validation) can set them to null
// or compute their own if needed later.

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
    this.component = 'hsd',
  });
}