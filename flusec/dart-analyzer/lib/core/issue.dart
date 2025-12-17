// lib/core/issue.dart
//
// Shared model used by the analyzer output.
// Even though ONLY your HSD module currently fills functionName/complexity,
// keeping the Issue model in core makes it easy to integrate other components later.
//
// Other components idea (future):
// - insecure_network module can also output Issue(ruleId/message/severity/line/column)
// - insecure_storage module can output Issue(...)
// - input_validation module can output Issue(...)
// They may set functionName/complexity as null (or compute their own later).

class Issue {
  final String ruleId;
  final String message;
  final String severity;
  final int line;
  final int column;

  // Your contribution: where the secret is located and how complex that context is.
  // Other components can ignore these fields or later reuse them.
  final String? functionName; // enclosing function/method name, if any
  final int? complexity; // cyclomatic complexity of that executable

  Issue(
    this.ruleId,
    this.message,
    this.severity,
    this.line,
    this.column, {
    this.functionName,
    this.complexity,
  });
}
