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
          n is ForStatement || // includes for-each loops too
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

  // ---------------------------------------------------------------------------
  // NEW: maximum nesting depth
  // ---------------------------------------------------------------------------
  //
  // We consider nesting of control-flow constructs like:
  //   if / for / while / do-while / switch / try-catch
  //
  // Example:
  //   if (...) {              // depth = 1
  //     if (...) {            // depth = 2
  //       for (...) {         // depth = 3
  //         ...
  //       }
  //     }
  //   }
  //
  // This gives a simple measure of "how deep" the code is, which helps estimate
  // how hard it is to refactor around the secret.

  static int computeMaxNestingDepth(AstNode exec) {
    int maxDepth = 0;

    void walk(AstNode n, int currentDepth) {
      int depth = currentDepth;

      // Skip nested executables (same idea as cyclomatic)
      if (n != exec &&
          (n is FunctionDeclaration ||
              n is MethodDeclaration ||
              n is ConstructorDeclaration ||
              n is FunctionExpression)) {
        return;
      }

      // Any new control-flow structure increases nesting depth.
      if (n is IfStatement ||
          n is ForStatement ||
          n is WhileStatement ||
          n is DoStatement ||
          n is SwitchStatement ||
          n is TryStatement) {
        depth = currentDepth + 1;
        if (depth > maxDepth) {
          maxDepth = depth;
        }
      }

      for (final child in n.childEntities) {
        if (child is AstNode) {
          walk(child, depth);
        }
      }
    }

    // Start at depth 0 at the executable boundary
    walk(exec, 0);
    return maxDepth;
  }

  // ---------------------------------------------------------------------------
  // NEW: function size (LOC) of the enclosing executable
  // ---------------------------------------------------------------------------
  //
  // We approximate size using line numbers from the CompilationUnit's lineInfo.
  // It counts from the start of the executable to its end, inclusive.

  static int computeFunctionLoc(AstNode exec) {
    final root = exec.root;
    if (root is! CompilationUnit) {
      // Fallback: we can't compute without a CompilationUnit
      return 0;
    }

    final lineInfo = root.lineInfo;
    final startLoc = lineInfo.getLocation(exec.offset);
    final endLoc = lineInfo.getLocation(exec.end);

    final loc = endLoc.lineNumber - startLoc.lineNumber + 1;
    return loc < 1 ? 1 : loc;
  }

  /// Human-readable level for cyclomatic complexity
  static String levelFor(int score) {
    if (score <= 5) return 'low';
    if (score <= 10) return 'medium';
    return 'high';
  }

  /// Human-readable level for nesting depth.
  /// You can adjust thresholds later if you want.
  static String nestingLevelFor(int depth) {
    if (depth <= 1) return 'low';
    if (depth <= 3) return 'medium';
    return 'high';
  }

  /// Human-readable level for function size (lines of code).
  static String sizeLevelFor(int loc) {
    if (loc <= 30) return 'small';
    if (loc <= 80) return 'medium';
    return 'large';
  }

}
