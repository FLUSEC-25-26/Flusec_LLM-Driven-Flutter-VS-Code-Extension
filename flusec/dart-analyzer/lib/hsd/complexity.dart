// lib/hsd/complexity.dart

import 'package:analyzer/dart/ast/ast.dart';

class Complexity {
  /// Simple cyclomatic complexity:
  /// counts branches (if/for/while/switch/?:) and && / ||.
  static int computeCyclomaticComplexity(AstNode exec) {
    int complexity = 1; // default path

    void walk(AstNode n) {
      // 1) Skip nested executables — only measure `exec`
      if (n != exec &&
          (n is FunctionDeclaration ||
              n is MethodDeclaration ||
              n is ConstructorDeclaration ||
              n is FunctionExpression)) {
        return;
      }

      // 2) Decision points
      if (n is IfStatement ||
          n is ForStatement ||        // includes for-each loops too
          n is WhileStatement ||
          n is DoStatement ||
          n is SwitchCase ||
          n is ConditionalExpression) {
        complexity++;
      }

      // 3) Catch clauses
      if (n is CatchClause) {
        complexity++;
      }

      // 4) Logical AND / OR
      if (n is BinaryExpression) {
        final op = n.operator.lexeme;
        if (op == '&&' || op == '||') {
          complexity++;
        }
      }

      // 5) Recurse
      for (final child in n.childEntities) {
        if (child is AstNode) {
          walk(child);
        }
      }
    }

    walk(exec);
    return complexity;
  }

  /// Human-readable level
  static String levelFor(int score) {
    if (score <= 5) return 'low';
    if (score <= 10) return 'medium';
    return 'high';
  }
}
