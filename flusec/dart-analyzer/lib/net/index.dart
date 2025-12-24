
// lib/net/index.dart
import 'package:analyzer/dart/ast/ast.dart';
import 'package:dart_analyzer/core/issue.dart';
import 'network_visitor.dart';

class NetworkAnalyzer {
  static List<Issue> run(CompilationUnit unit, String content, String filePath) {
    final visitor = NetworkVisitor(unit, filePath);
    unit.accept(visitor);
    visitor.debugCounters(); // DEBUG: show node counts
    return visitor.issues;
  }
}
