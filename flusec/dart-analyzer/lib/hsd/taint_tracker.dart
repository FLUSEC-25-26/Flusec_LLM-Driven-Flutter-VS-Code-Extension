// lib/hsd/taint_tracker.dart
//
// Bounded same-scope taint context for HSD findings.
//
// The taint analysis does not decide whether a hardcoded secret exists. HSD
// already made that decision. This module only records how the detected value
// appears to propagate within the enclosing function/compilation unit.
//
// Tracked evidence types:
//   ASSIGNMENT
//   STRING_INTERPOLATION
//   MAP_VALUE
//   FUNCTION_ARGUMENT
//   NETWORK_REQUEST
//   STORAGE_WRITE
//   SECURE_STORAGE_WRITE
//   LOG_OUTPUT
//   RETURN_VALUE

import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';

class TaintFlowStep {
  final String type;
  final int line;
  final int column;
  final String description;

  const TaintFlowStep({
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

class TaintTracker extends RecursiveAstVisitor<void> {
  final CompilationUnit unit;
  final int sourceLine;

  /// Supports simple same-scope propagation:
  ///   secret -> copy -> header -> sink
  final Set<String> _taintedNames;

  final List<TaintFlowStep> steps = [];
  final Set<String> _seen = {};

  TaintTracker({
    required String taintedName,
    required this.unit,
    required this.sourceLine,
  }) : _taintedNames = {taintedName};

  static const _sharedPreferencesMethods = {
    'setString',
    'setBool',
    'setInt',
    'setDouble',
    'setStringList',
  };

  static const _fileWriteMethods = {
    'writeAsString',
    'writeAsStringSync',
    'writeAsBytes',
    'writeAsBytesSync',
    'openWrite',
  };

  static const _sqlWriteMethods = {
    'insert',
    'rawInsert',
    'update',
    'rawUpdate',
    'execute',
  };

  static const _networkMethods = {
    'get',
    'post',
    'put',
    'patch',
    'delete',
    'head',
    'fetch',
    'request',
    'send',
    'connect',
    'emit',
  };

  (int, int) _loc(AstNode node) {
    final location = unit.lineInfo.getLocation(node.offset);
    return (location.lineNumber, location.columnNumber);
  }

  bool _isBeforeSource(AstNode node) {
    return _loc(node).$1 < sourceLine;
  }

  void _addStep(String type, AstNode node, String description) {
    final loc = _loc(node);

    // Only record propagation at/after the source location. This prevents an
    // earlier same-name variable/use in the enclosing scope from being
    // incorrectly described as downstream taint. The source line itself is
    // omitted from evidence to avoid echoing the declaration as a sink.
    if (loc.$1 <= sourceLine) return;

    final key = '${loc.$1}:${loc.$2}:$type:$description';
    if (!_seen.add(key)) return;

    steps.add(TaintFlowStep(
      type: type,
      line: loc.$1,
      column: loc.$2,
      description: description,
    ));
  }

  bool _isTainted(Expression? expression) {
    if (expression == null) return false;

    if (expression is SimpleIdentifier) {
      return _taintedNames.contains(expression.name);
    }

    if (expression is PrefixedIdentifier) {
      return _taintedNames.contains(expression.identifier.name) ||
          _isTainted(expression.prefix);
    }

    if (expression is PropertyAccess) {
      return _taintedNames.contains(expression.propertyName.name) ||
          _isTainted(expression.target);
    }

    if (expression is ParenthesizedExpression) {
      return _isTainted(expression.expression);
    }

    if (expression is BinaryExpression) {
      return _isTainted(expression.leftOperand) ||
          _isTainted(expression.rightOperand);
    }

    if (expression is ConditionalExpression) {
      return _isTainted(expression.thenExpression) ||
          _isTainted(expression.elseExpression);
    }

    if (expression is StringInterpolation) {
      for (final element in expression.elements) {
        if (element is InterpolationExpression &&
            _isTainted(element.expression)) {
          return true;
        }
      }
      return false;
    }

    if (expression is AdjacentStrings) {
      for (final string in expression.strings) {
        if (_isTainted(string)) return true;
      }
      return false;
    }

    return false;
  }

  String _targetText(MethodInvocation node) {
    return node.target?.toSource().toLowerCase() ?? '';
  }

  bool _isLoggingInvocation(MethodInvocation node) {
    final method = node.methodName.name;
    final target = _targetText(node);

    if (method == 'print' || method == 'debugPrint') return true;

    if (method == 'log' &&
        (target.isEmpty || target.contains('log') || target.contains('logger'))) {
      return true;
    }

    const loggerMethods = {
      'd',
      'i',
      'w',
      'e',
      'v',
      'wtf',
      'info',
      'warning',
      'severe',
      'fine',
      'finest',
      'config',
      'shout',
    };

    return loggerMethods.contains(method) &&
        (target.contains('log') || target.contains('logger'));
  }

  String? _storageKind(MethodInvocation node) {
    final method = node.methodName.name;
    final target = _targetText(node);

    if (_sharedPreferencesMethods.contains(method)) {
      return 'STORAGE_WRITE';
    }

    if (_fileWriteMethods.contains(method)) {
      return 'STORAGE_WRITE';
    }

    if (_sqlWriteMethods.contains(method) &&
        (target.contains('db') ||
            target.contains('database') ||
            target.contains('sqlite') ||
            target.contains('sql'))) {
      return 'STORAGE_WRITE';
    }

    if ((method == 'put' || method == 'putAll') &&
        (target.contains('hive') || target.contains('box'))) {
      return 'STORAGE_WRITE';
    }

    if (method == 'write' &&
        (target.contains('securestorage') ||
            target.contains('secure_storage') ||
            target.contains('secure'))) {
      return 'SECURE_STORAGE_WRITE';
    }

    return null;
  }

  bool _isNetworkInvocation(MethodInvocation node) {
    final method = node.methodName.name;
    if (!_networkMethods.contains(method)) return false;

    final target = _targetText(node);
    if (target.isEmpty) return false;

    return target.contains('http') ||
        target.contains('dio') ||
        target.contains('websocket') ||
        target.contains('socket') ||
        target.contains('channel') ||
        target.contains('apiclient') ||
        target.contains('api_client') ||
        target.endsWith('client') ||
        target.contains('.client');
  }

  (bool, String) _taintedArgument(ArgumentList arguments) {
    for (final arg in arguments.arguments) {
      Expression expression = arg;
      var description = 'positional argument';

      if (arg is NamedExpression) {
        expression = arg.expression;
        description = 'named parameter "${arg.name.label.name}"';
      }

      if (_isTainted(expression)) {
        return (true, description);
      }
    }

    return (false, '');
  }

  @override
  void visitVariableDeclaration(VariableDeclaration node) {
    if (_isBeforeSource(node)) {
      super.visitVariableDeclaration(node);
      return;
    }

    if (node.initializer != null && _isTainted(node.initializer)) {
      final newName = node.name.lexeme;
      if (!_taintedNames.contains(newName)) {
        _taintedNames.add(newName);
        _addStep(
          'ASSIGNMENT',
          node,
          'Propagated to variable "$newName"',
        );
      }
    }

    super.visitVariableDeclaration(node);
  }

  @override
  void visitAssignmentExpression(AssignmentExpression node) {
    if (_isBeforeSource(node)) {
      super.visitAssignmentExpression(node);
      return;
    }

    if (_isTainted(node.rightHandSide)) {
      final lhs = node.leftHandSide;
      final name = _simpleAssignedName(lhs);
      if (name != null && name.isNotEmpty) {
        _taintedNames.add(name);
      }

      _addStep(
        'ASSIGNMENT',
        node,
        'Propagated by assignment to "${lhs.toSource()}"',
      );
    }

    super.visitAssignmentExpression(node);
  }

  @override
  void visitMethodInvocation(MethodInvocation node) {
    if (_isBeforeSource(node)) {
      super.visitMethodInvocation(node);
      return;
    }

    final tainted = _taintedArgument(node.argumentList);
    if (!tainted.$1) {
      super.visitMethodInvocation(node);
      return;
    }

    final method = node.methodName.name;
    final target = node.target?.toSource();
    final callName = target == null || target.isEmpty
        ? '$method()'
        : '$target.$method()';

    if (_isLoggingInvocation(node)) {
      _addStep(
        'LOG_OUTPUT',
        node,
        'Secret-derived value passed to logging call $callName',
      );
    } else {
      final storageKind = _storageKind(node);
      if (storageKind != null) {
        _addStep(
          storageKind,
          node,
          'Secret-derived value passed to storage call $callName',
        );
      } else if (_isNetworkInvocation(node)) {
        _addStep(
          'NETWORK_REQUEST',
          node,
          'Secret-derived value passed to network call $callName as ${tainted.$2}',
        );
      } else {
        _addStep(
          'FUNCTION_ARGUMENT',
          node,
          'Secret-derived value passed to $callName as ${tainted.$2}',
        );
      }
    }

    super.visitMethodInvocation(node);
  }

  @override
  void visitFunctionExpressionInvocation(FunctionExpressionInvocation node) {
    if (_isBeforeSource(node)) {
      super.visitFunctionExpressionInvocation(node);
      return;
    }

    final tainted = _taintedArgument(node.argumentList);
    if (tainted.$1) {
      final source = node.function.toSource();
      final display = source.length > 30
          ? '${source.substring(0, 27)}...'
          : source;
      _addStep(
        'FUNCTION_ARGUMENT',
        node,
        'Secret-derived value passed to $display()',
      );
    }

    super.visitFunctionExpressionInvocation(node);
  }

  @override
  void visitInstanceCreationExpression(InstanceCreationExpression node) {
    if (_isBeforeSource(node)) {
      super.visitInstanceCreationExpression(node);
      return;
    }

    final tainted = _taintedArgument(node.argumentList);
    if (tainted.$1) {
      final typeName = node.constructorName.type.toSource();
      _addStep(
        'FUNCTION_ARGUMENT',
        node,
        'Secret-derived value passed to $typeName() as ${tainted.$2}',
      );
    }

    super.visitInstanceCreationExpression(node);
  }

  @override
  void visitMapLiteralEntry(MapLiteralEntry node) {
    if (_isBeforeSource(node)) {
      super.visitMapLiteralEntry(node);
      return;
    }

    if (_isTainted(node.value)) {
      final key = node.key.toSource();
      final keyLower = key.toLowerCase();

      final headerLike = keyLower.contains('authorization') ||
          keyLower.contains('bearer') ||
          keyLower.contains('x-api-key') ||
          keyLower.contains('api-key');

      _addStep(
        headerLike ? 'NETWORK_REQUEST' : 'MAP_VALUE',
        node,
        headerLike
            ? 'Secret-derived value used in authentication/header map entry $key'
            : 'Secret-derived value used as map value for $key',
      );
    }

    super.visitMapLiteralEntry(node);
  }

  @override
  void visitStringInterpolation(StringInterpolation node) {
    if (_isBeforeSource(node)) {
      super.visitStringInterpolation(node);
      return;
    }

    if (_isTainted(node)) {
      _addStep(
        'STRING_INTERPOLATION',
        node,
        'Secret-derived value embedded in string interpolation',
      );
    }

    super.visitStringInterpolation(node);
  }

  @override
  void visitReturnStatement(ReturnStatement node) {
    if (_isBeforeSource(node)) {
      super.visitReturnStatement(node);
      return;
    }

    if (_isTainted(node.expression)) {
      _addStep(
        'RETURN_VALUE',
        node,
        'Secret-derived value returned from function',
      );
    }

    super.visitReturnStatement(node);
  }

  String? _simpleAssignedName(Expression expression) {
    if (expression is SimpleIdentifier) return expression.name;
    if (expression is PrefixedIdentifier) return expression.identifier.name;
    if (expression is PropertyAccess) return expression.propertyName.name;
    return null;
  }
}

List<TaintFlowStep> trackTaintFlow({
  required String taintedVarName,
  required AstNode declarationNode,
  required CompilationUnit unit,
  required int sourceLine,
}) {
  if (taintedVarName.trim().isEmpty) return [];

  final scope = _findEnclosingScope(declarationNode) ?? unit;
  final tracker = TaintTracker(
    taintedName: taintedVarName,
    unit: unit,
    sourceLine: sourceLine,
  );

  scope.accept(tracker);
  tracker.steps.sort((a, b) {
    final line = a.line.compareTo(b.line);
    return line != 0 ? line : a.column.compareTo(b.column);
  });

  return tracker.steps;
}

AstNode? _findEnclosingScope(AstNode node) {
  AstNode? current = node.parent;

  while (current != null) {
    if (current is FunctionDeclaration) return current.functionExpression.body;
    if (current is MethodDeclaration) return current.body;
    if (current is ConstructorDeclaration) return current.body;
    if (current is FunctionExpression) return current.body;
    current = current.parent;
  }

  return null;
}
