// lib/core/code_context.dart
//
// Shared function-level maintainability context for every FLUSEC security
// component. These metrics describe the surrounding code only; they never
// determine vulnerability security severity or detector confidence.

import 'package:analyzer/dart/ast/ast.dart';

class MaintainabilityContext {
  final int score;
  final String level;
  final int complexityScore;
  final int nestingScore;
  final int locScore;

  const MaintainabilityContext({
    required this.score,
    required this.level,
    required this.complexityScore,
    required this.nestingScore,
    required this.locScore,
  });

  Map<String, dynamic> toJson() => {
        'score': score,
        'level': level,
        'weights': const {
          'complexity': 0.40,
          'nestingDepth': 0.35,
          'functionLoc': 0.25,
        },
        'normalized': {
          'complexity': complexityScore,
          'nestingDepth': nestingScore,
          'functionLoc': locScore,
        },
      };
}

class CodeContext {
  final String? functionName;
  final int complexity;
  final int nestingDepth;
  final int functionLoc;
  final MaintainabilityContext maintainability;

  const CodeContext({
    required this.functionName,
    required this.complexity,
    required this.nestingDepth,
    required this.functionLoc,
    required this.maintainability,
  });

  int get maintainabilityScore => maintainability.score;
  String get maintainabilityLevel => maintainability.level;

  Map<String, dynamic> maintainabilityEvidence() => {
        ...maintainability.toJson(),
        'complexity': complexity,
        'nestingDepth': nestingDepth,
        'functionLoc': functionLoc,
        'note':
            'FLUSEC-defined maintainability context; not a security-severity score.',
      };
}

class CodeContextAnalyzer {
  /// Returns function-level context for [node], or null when the finding is at
  /// top level / class level and has no enclosing executable.
  static CodeContext? fromNode(AstNode node) {
    final executable = enclosingExecutable(node);
    if (executable == null) return null;

    final rawName = executableName(executable);
    final functionName = rawName == '<anonymous>' ? null : rawName;

    final complexity = Complexity.computeCyclomaticComplexity(executable);
    final nestingDepth = Complexity.computeMaxNestingDepth(executable);
    final functionLoc = Complexity.computeFunctionLoc(executable);
    final maintainability = Complexity.computeMaintainabilityContext(
      complexity: complexity,
      nestingDepth: nestingDepth,
      functionLoc: functionLoc,
    );

    return CodeContext(
      functionName: functionName,
      complexity: complexity,
      nestingDepth: nestingDepth,
      functionLoc: functionLoc,
      maintainability: maintainability,
    );
  }

  /// Finds the closest enclosing function/method/constructor/lambda.
  static AstNode? enclosingExecutable(AstNode node) {
    AstNode? current = node;
    while (current != null) {
      if (current is FunctionDeclaration ||
          current is MethodDeclaration ||
          current is ConstructorDeclaration ||
          current is FunctionExpression) {
        return current;
      }
      current = current.parent;
    }
    return null;
  }

  /// Human-readable name for an executable node.
  static String executableName(AstNode exec) {
    if (exec is FunctionDeclaration) {
      return exec.name.lexeme;
    }

    if (exec is MethodDeclaration) {
      return exec.name.lexeme;
    }

    if (exec is ConstructorDeclaration) {
      final typeName = exec.returnType?.toSource() ?? '';
      final ctorName = exec.name?.lexeme ?? '';
      return ctorName.isEmpty ? typeName : '$typeName.$ctorName';
    }

    if (exec is FunctionExpression) {
      final parent = exec.parent;
      if (parent is FunctionDeclaration) {
        return parent.name.lexeme;
      }
      if (parent is MethodDeclaration) {
        return parent.name.lexeme;
      }
      if (parent is ConstructorDeclaration) {
        final typeName = parent.returnType?.toSource() ?? '';
        final ctorName = parent.name?.lexeme ?? '';
        return ctorName.isEmpty ? typeName : '$typeName.$ctorName';
      }
    }

    return '<anonymous>';
  }
}

class Complexity {
  /// Simple cyclomatic complexity for the enclosing executable.
  /// Counts the base path plus decisions/branches.
  static int computeCyclomaticComplexity(AstNode exec) {
    var complexity = 1;

    void walk(AstNode node) {
      // Measure only this executable, not nested functions/lambdas.
      if (node != exec &&
          (node is FunctionDeclaration ||
              node is MethodDeclaration ||
              node is ConstructorDeclaration ||
              node is FunctionExpression)) {
        return;
      }

      if (node is IfStatement ||
          node is ForStatement ||
          node is WhileStatement ||
          node is DoStatement ||
          node is SwitchCase ||
          node is ConditionalExpression ||
          node is CatchClause) {
        complexity++;
      }

      if (node is BinaryExpression) {
        final operator = node.operator.lexeme;
        if (operator == '&&' || operator == '||') {
          complexity++;
        }
      }

      for (final child in node.childEntities) {
        if (child is AstNode) {
          walk(child);
        }
      }
    }

    walk(exec);
    return complexity;
  }

  /// Maximum nesting of control-flow structures in the enclosing executable.
  static int computeMaxNestingDepth(AstNode exec) {
    var maxDepth = 0;

    void walk(AstNode node, int currentDepth) {
      var depth = currentDepth;

      if (node != exec &&
          (node is FunctionDeclaration ||
              node is MethodDeclaration ||
              node is ConstructorDeclaration ||
              node is FunctionExpression)) {
        return;
      }

      if (node is IfStatement ||
          node is ForStatement ||
          node is WhileStatement ||
          node is DoStatement ||
          node is SwitchStatement ||
          node is TryStatement) {
        depth = currentDepth + 1;
        if (depth > maxDepth) {
          maxDepth = depth;
        }
      }

      for (final child in node.childEntities) {
        if (child is AstNode) {
          walk(child, depth);
        }
      }
    }

    walk(exec, 0);
    return maxDepth;
  }

  /// Function size from executable start line to end line, inclusive.
  static int computeFunctionLoc(AstNode exec) {
    final root = exec.root;
    if (root is! CompilationUnit) return 0;

    final start = root.lineInfo.getLocation(exec.offset);
    final end = root.lineInfo.getLocation(exec.end);
    final loc = end.lineNumber - start.lineNumber + 1;
    return loc < 1 ? 1 : loc;
  }

  // Complexity uses a literature-informed starting point around 10. The
  // nesting/LOC thresholds and the combined weighting are FLUSEC-defined
  // engineering heuristics and must not be described as universal standards.
  static String levelFor(int score) {
    if (score <= 10) return 'low';
    if (score <= 15) return 'moderate';
    if (score <= 20) return 'high';
    return 'very_high';
  }

  static String nestingLevelFor(int depth) {
    if (depth <= 2) return 'low';
    if (depth == 3) return 'moderate';
    if (depth <= 5) return 'high';
    return 'very_high';
  }

  static String sizeLevelFor(int loc) {
    if (loc <= 30) return 'low';
    if (loc <= 60) return 'moderate';
    if (loc <= 100) return 'high';
    return 'very_high';
  }

  /// FLUSEC Maintainability Context Score (0-100):
  ///   0.40 * normalized cyclomatic complexity
  /// + 0.35 * normalized nesting depth
  /// + 0.25 * normalized function LOC
  ///
  /// This is contextual maintainability metadata, not a security-risk score.
  static MaintainabilityContext computeMaintainabilityContext({
    required int complexity,
    required int nestingDepth,
    required int functionLoc,
  }) {
    final complexityScore = _complexityScore(complexity);
    final nestingScore = _nestingScore(nestingDepth);
    final locScore = _locScore(functionLoc);

    final weighted =
        complexityScore * 0.40 + nestingScore * 0.35 + locScore * 0.25;
    final score = weighted.round().clamp(0, 100).toInt();

    return MaintainabilityContext(
      score: score,
      level: maintainabilityLevelFor(score),
      complexityScore: complexityScore,
      nestingScore: nestingScore,
      locScore: locScore,
    );
  }

  static String maintainabilityLevelFor(int score) {
    if (score <= 24) return 'low';
    if (score <= 49) return 'moderate';
    if (score <= 74) return 'high';
    return 'very_high';
  }

  static int _complexityScore(int complexity) {
    if (complexity <= 10) return 0;
    if (complexity <= 15) return 33;
    if (complexity <= 20) return 67;
    return 100;
  }

  static int _nestingScore(int depth) {
    if (depth <= 2) return 0;
    if (depth == 3) return 33;
    if (depth <= 5) return 67;
    return 100;
  }

  static int _locScore(int loc) {
    if (loc <= 30) return 0;
    if (loc <= 60) return 33;
    if (loc <= 100) return 67;
    return 100;
  }
}
