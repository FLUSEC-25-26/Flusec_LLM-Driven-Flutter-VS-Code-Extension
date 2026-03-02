// lib/hsd/taint_tracker.dart
//
// Simplified Taint Analysis for HSD.
//
// After SecretVisitor detects a hardcoded secret in a variable declaration,
// TaintTracker traces where that variable is used throughout the enclosing
// scope (function body or compilation unit for top-level declarations).
//
// It produces a list of TaintFlowStep objects describing each usage site.
//
// IMPORTANT: Storage and logging sinks are EXCLUDED because the IDS component
// already handles those. This avoids overlap between HSD and IDS.
//
// Tracked sink types:
//   NETWORK_REQUEST  — passed to HTTP/Dio/WebSocket calls
//   FUNCTION_ARGUMENT — passed as argument to any function/method
//   RETURN_VALUE     — returned from a function
//   ASSIGNMENT       — assigned to another variable (taint propagation)
//   MAP_VALUE        — used as a value in a map literal (e.g., headers map)
//   STRING_INTERPOLATION — embedded in a string interpolation
//
// Excluded sink types (IDS handles these):
//   STORAGE_WRITE    — SharedPreferences, SQLite, file writes
//   LOG_OUTPUT       — print(), debugPrint(), log(), Logger calls

import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';

/// A single step in the taint flow path.
class TaintFlowStep {
  /// The type of usage/sink.
  final String type;

  /// Line number where the usage occurs.
  final int line;

  /// Column number where the usage occurs.
  final int column;

  /// Human-readable description of what happens at this step.
  final String description;

  TaintFlowStep({
    required this.type,
    required this.line,
    required this.column,
    required this.description,
  });

  Map<String, dynamic> toJson() => {
        'type': type,
        'line': line,
        'column': column,
        'description': description,
      };
}

/// Track where a tainted variable flows within a given AST scope.
class TaintTracker extends RecursiveAstVisitor<void> {
  /// The name of the tainted variable to track.
  final String taintedName;

  /// The CompilationUnit (needed for line/column resolution).
  final CompilationUnit unit;

  /// The line where the secret was originally declared (to exclude from results).
  final int sourceLine;

  /// Collected flow steps.
  final List<TaintFlowStep> steps = [];

  /// Tracking set to avoid duplicate reports for same location.
  final Set<String> _seen = {};

  TaintTracker({
    required this.taintedName,
    required this.unit,
    required this.sourceLine,
  });

  // ─── Storage / logging sinks to SKIP (IDS handles these) ────────────

  static const _storageMethods = {
    // SharedPreferences
    'setString', 'setBool', 'setInt', 'setDouble', 'setStringList',
    // File I/O
    'writeAsString', 'writeAsStringSync', 'writeAsBytes', 'writeAsBytesSync',
    'openWrite',
    // SQLite
    'insert', 'rawInsert', 'execute', 'rawQuery',
    // Hive
    'put', 'putAll',
    // SecureStorage
    'write',
  };

  static const _loggingMethods = {
    'print', 'debugPrint', 'log', 'info', 'warning', 'severe', 'fine',
    'finest', 'config', 'shout',
    // Logger class methods
    'd', 'i', 'w', 'e', 'v', 'wtf',
  };

  // ─── Network sink methods ──────────────────────────────────────────

  static const _networkMethods = {
    // http package
    'get', 'post', 'put', 'patch', 'delete', 'head', 'read', 'readBytes',
    // Dio
    'fetch', 'request',
    // WebSocket
    'connect',
    // Generic
    'send', 'emit',
  };

  // ─── Helpers ───────────────────────────────────────────────────────

  (int, int) _loc(AstNode node) {
    final info = unit.lineInfo.getLocation(node.offset);
    return (info.lineNumber, info.columnNumber);
  }

  bool _addStep(String type, int line, int col, String description) {
    // Skip the source declaration line itself
    if (line == sourceLine) return false;

    final key = '$line:$col:$type';
    if (!_seen.add(key)) return false;

    steps.add(TaintFlowStep(
      type: type,
      line: line,
      column: col,
      description: description,
    ));
    return true;
  }

  /// Check if an expression references our tainted variable.
  bool _isTainted(Expression? expr) {
    if (expr == null) return false;

    // Direct identifier reference
    if (expr is SimpleIdentifier && expr.name == taintedName) return true;

    // Prefixed (e.g., this.apiKey — unlikely but possible)
    if (expr is PrefixedIdentifier && expr.identifier.name == taintedName) {
      return true;
    }

    // Property access (e.g., obj.apiKey)
    if (expr is PropertyAccess && expr.propertyName.name == taintedName) {
      return true;
    }

    // String interpolation containing the variable
    if (expr is StringInterpolation) {
      for (final element in expr.elements) {
        if (element is InterpolationExpression) {
          if (_isTainted(element.expression)) return true;
        }
      }
    }

    // Adjacent strings (e.g., 'Bearer ' + apiKey)
    if (expr is AdjacentStrings) {
      for (final s in expr.strings) {
        if (_isTainted(s)) return true;
      }
    }

    // Binary expression (e.g., 'Bearer ' + apiKey)
    if (expr is BinaryExpression) {
      if (_isTainted(expr.leftOperand) || _isTainted(expr.rightOperand)) {
        return true;
      }
    }

    // Conditional (ternary): condition ? apiKey : other
    if (expr is ConditionalExpression) {
      if (_isTainted(expr.thenExpression) ||
          _isTainted(expr.elseExpression)) {
        return true;
      }
    }

    // Parenthesized: (apiKey)
    if (expr is ParenthesizedExpression) {
      return _isTainted(expr.expression);
    }

    return false;
  }

  /// Check if a method name is a storage/logging sink (to skip).
  bool _isExcludedSink(String methodName) {
    return _storageMethods.contains(methodName) ||
        _loggingMethods.contains(methodName);
  }

  // ─── Visitor methods ───────────────────────────────────────────────

  @override
  void visitMethodInvocation(MethodInvocation node) {
    final methodName = node.methodName.name;

    // Skip excluded sinks (IDS handles these)
    if (_isExcludedSink(methodName)) {
      super.visitMethodInvocation(node);
      return;
    }

    // Check if any argument references our tainted variable
    bool hasTaintedArg = false;
    String? taintedArgDesc;

    for (final arg in node.argumentList.arguments) {
      Expression argExpr = arg;
      String argName = '';

      if (arg is NamedExpression) {
        argExpr = arg.expression;
        argName = arg.name.label.name;
      }

      if (_isTainted(argExpr)) {
        hasTaintedArg = true;
        taintedArgDesc = argName.isNotEmpty
            ? 'named parameter "$argName"'
            : 'positional argument';
        break;
      }
    }

    if (!hasTaintedArg) {
      super.visitMethodInvocation(node);
      return;
    }

    final loc = _loc(node);

    // Classify the sink type
    if (_networkMethods.contains(methodName)) {
      // Check if it's in a target/receiver that looks like http/dio/websocket
      final targetStr = node.target?.toSource().toLowerCase() ?? '';
      final isNetwork = targetStr.contains('http') ||
          targetStr.contains('dio') ||
          targetStr.contains('client') ||
          targetStr.contains('socket') ||
          targetStr.contains('api') ||
          _networkMethods.contains(methodName);

      if (isNetwork) {
        _addStep(
          'NETWORK_REQUEST',
          loc.$1,
          loc.$2,
          'Passed to ${node.target != null ? "${node.target}." : ""}$methodName() as $taintedArgDesc',
        );
      } else {
        _addStep(
          'FUNCTION_ARGUMENT',
          loc.$1,
          loc.$2,
          'Passed to $methodName() as $taintedArgDesc',
        );
      }
    } else {
      _addStep(
        'FUNCTION_ARGUMENT',
        loc.$1,
        loc.$2,
        'Passed to $methodName() as $taintedArgDesc',
      );
    }

    super.visitMethodInvocation(node);
  }

  @override
  void visitFunctionExpressionInvocation(FunctionExpressionInvocation node) {
    for (final arg in node.argumentList.arguments) {
      Expression argExpr = arg;
      if (arg is NamedExpression) argExpr = arg.expression;

      if (_isTainted(argExpr)) {
        final loc = _loc(node);
        final fnSource = node.function.toSource();
        final shortFn = fnSource.length > 30
            ? '${fnSource.substring(0, 27)}...'
            : fnSource;
        _addStep(
          'FUNCTION_ARGUMENT',
          loc.$1,
          loc.$2,
          'Passed to $shortFn()',
        );
        break;
      }
    }
    super.visitFunctionExpressionInvocation(node);
  }

  @override
  void visitInstanceCreationExpression(InstanceCreationExpression node) {
    final typeName = node.constructorName.type.toSource();

    // Skip storage-related constructors (IDS handles)
    final typeNameLower = typeName.toLowerCase();
    if (typeNameLower.contains('file') ||
        typeNameLower.contains('database') ||
        typeNameLower.contains('hive')) {
      super.visitInstanceCreationExpression(node);
      return;
    }

    for (final arg in node.argumentList.arguments) {
      Expression argExpr = arg;
      String argName = '';
      if (arg is NamedExpression) {
        argExpr = arg.expression;
        argName = arg.name.label.name;
      }

      if (_isTainted(argExpr)) {
        final loc = _loc(node);
        final desc = argName.isNotEmpty
            ? 'Passed to $typeName() as named parameter "$argName"'
            : 'Passed to $typeName() constructor';
        _addStep('FUNCTION_ARGUMENT', loc.$1, loc.$2, desc);
        break;
      }
    }
    super.visitInstanceCreationExpression(node);
  }

  @override
  void visitReturnStatement(ReturnStatement node) {
    if (node.expression != null && _isTainted(node.expression)) {
      final loc = _loc(node);
      _addStep(
        'RETURN_VALUE',
        loc.$1,
        loc.$2,
        'Secret returned from function',
      );
    }
    super.visitReturnStatement(node);
  }

  @override
  void visitAssignmentExpression(AssignmentExpression node) {
    if (_isTainted(node.rightHandSide)) {
      final lhsName = node.leftHandSide.toSource();
      final loc = _loc(node);
      _addStep(
        'ASSIGNMENT',
        loc.$1,
        loc.$2,
        'Assigned to "$lhsName" (taint propagation)',
      );
    }
    super.visitAssignmentExpression(node);
  }

  @override
  void visitVariableDeclaration(VariableDeclaration node) {
    // Another variable initialized with our tainted variable
    if (node.initializer != null && _isTainted(node.initializer)) {
      final newVarName = node.name.lexeme;
      // Don't report the original declaration
      if (newVarName != taintedName) {
        final loc = _loc(node);
        _addStep(
          'ASSIGNMENT',
          loc.$1,
          loc.$2,
          'Assigned to new variable "$newVarName" (taint propagation)',
        );
      }
    }
    super.visitVariableDeclaration(node);
  }

  @override
  void visitMapLiteralEntry(MapLiteralEntry node) {
    if (_isTainted(node.value)) {
      final keyStr = node.key.toSource();
      final loc = _loc(node);

      // Check if the key suggests a network context (headers, auth)
      final keyLower = keyStr.toLowerCase().replaceAll(RegExp('[\'"]'), '');
      final isNetworkContext = keyLower.contains('authorization') ||
          keyLower.contains('auth') ||
          keyLower.contains('token') ||
          keyLower.contains('bearer') ||
          keyLower.contains('x-api-key') ||
          keyLower.contains('api-key');

      if (isNetworkContext) {
        _addStep(
          'NETWORK_REQUEST',
          loc.$1,
          loc.$2,
          'Used as value for header key $keyStr (likely network request)',
        );
      } else {
        _addStep(
          'MAP_VALUE',
          loc.$1,
          loc.$2,
          'Used as map value for key $keyStr',
        );
      }
    }
    super.visitMapLiteralEntry(node);
  }

  @override
  void visitStringInterpolation(StringInterpolation node) {
    for (final element in node.elements) {
      if (element is InterpolationExpression) {
        if (element.expression is SimpleIdentifier &&
            (element.expression as SimpleIdentifier).name == taintedName) {
          final loc = _loc(node);
          _addStep(
            'STRING_INTERPOLATION',
            loc.$1,
            loc.$2,
            'Embedded in string interpolation',
          );
          break;
        }
      }
    }
    super.visitStringInterpolation(node);
  }

  @override
  void visitNamedExpression(NamedExpression node) {
    // Already handled in method/constructor visitors above
    super.visitNamedExpression(node);
  }
}

// ---------------------------------------------------------------------------
// Public API: run taint tracking for a tainted variable within a scope.
// ---------------------------------------------------------------------------

/// Run simplified taint analysis on a variable within its enclosing scope.
///
/// [taintedVarName] — the variable name holding the hardcoded secret.
/// [declarationNode] — the AST node where the secret was declared.
/// [unit] — the CompilationUnit for line/column resolution.
/// [sourceLine] — the line where the secret was declared (excluded from results).
///
/// Returns a list of TaintFlowStep objects (may be empty if no flows found).
List<TaintFlowStep> trackTaintFlow({
  required String taintedVarName,
  required AstNode declarationNode,
  required CompilationUnit unit,
  required int sourceLine,
}) {
  if (taintedVarName.isEmpty) return [];

  // Determine the scope to search:
  // 1. If inside a function → search that function body
  // 2. If top-level → search the entire compilation unit
  AstNode scope = _findEnclosingScope(declarationNode) ?? unit;

  final tracker = TaintTracker(
    taintedName: taintedVarName,
    unit: unit,
    sourceLine: sourceLine,
  );

  scope.accept(tracker);

  // Sort by line number
  tracker.steps.sort((a, b) => a.line.compareTo(b.line));

  return tracker.steps;
}

/// Find the enclosing function/method body to limit taint scope.
AstNode? _findEnclosingScope(AstNode node) {
  AstNode? current = node.parent;
  while (current != null) {
    if (current is FunctionDeclaration) return current.functionExpression.body;
    if (current is MethodDeclaration) return current.body;
    if (current is ConstructorDeclaration) return current.body;
    if (current is FunctionExpression) return current.body;
    current = current.parent;
  }
  // Top-level — return null to use CompilationUnit
  return null;
}