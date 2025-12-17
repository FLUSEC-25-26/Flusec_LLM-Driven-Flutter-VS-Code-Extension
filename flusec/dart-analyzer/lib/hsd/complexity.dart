// lib/hsd/complexity.dart
//
// Cyclomatic complexity computation.
// This is your unique component feature, so it lives inside hsd/.
//
// Other components (future) may keep complexity as null,
// or later compute their own if required.

import 'package:analyzer/dart/ast/ast.dart';

class Complexity {
  /// Simple cyclomatic complexity:
  /// counts branches (if/for/while/switch/?:) and && / ||.
  static int computeCyclomaticComplexity(AstNode exec) {
    int complexity = 1; // default path

    void walk(AstNode n) {
      if (n is IfStatement ||
          n is ForStatement ||
          n is WhileStatement ||
          n is DoStatement ||
          n is SwitchCase ||
          n is ConditionalExpression) {
        complexity++;
      }

      if (n is CatchClause) {
        complexity++;
      }

      if (n is BinaryExpression) {
        final op = n.operator.lexeme;
        if (op == '&&' || op == '||') {
          complexity++;
        }
      }

      for (final child in n.childEntities) {
        if (child is AstNode) {
          walk(child);
        }
      }
    }

    walk(exec);
    return complexity;
  }
}
