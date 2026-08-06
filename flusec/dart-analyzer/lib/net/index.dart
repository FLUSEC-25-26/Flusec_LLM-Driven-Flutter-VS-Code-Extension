// lib/net/index.dart
//
// Barrel file + entry point for Insecure Network Communication component.

import 'package:analyzer/dart/ast/ast.dart';
import 'package:dart_analyzer/core/issue.dart';
import 'network_rules.dart';
import 'network_visitor.dart';

export 'network_rules.dart';
export 'network_visitor.dart';
export 'url_utils.dart';

class NetworkAnalyzer {
  /// Run the network security analysis on a compilation unit.
  /// [rules] is a NetworkRulesEngine loaded from config or defaults.
  static List<Issue> run(
    CompilationUnit unit,
    String content,
    String filePath,
    NetworkRulesEngine rules,
  ) {
    final visitor = NetworkVisitor(unit, filePath, rules);
    unit.accept(visitor);
    visitor.debugCounters();
    return visitor.issues;
  }
}
