// lib/iiv/iiv_visitor.dart
//
// Syntax-based IIV detector with lightweight local evidence tracking.
// It deliberately avoids claiming full interprocedural taint analysis.

import 'dart:io';
import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';

import '../core/issue.dart';
import 'iiv_rules.dart';

class IivVisitor extends RecursiveAstVisitor<void> {
  final CompilationUnit unit;
  final String filePath;
  final IivRulesEngine rules;
  final List<Issue> issues = [];

  final Map<int, Map<String, Expression>> _initializersByScope = {};
  final Map<int, Set<String>> _deepLinkVariablesByScope = {};
  final Set<String> _emitted = {};

  IivVisitor(this.unit, this.filePath, this.rules);

  // -------------------------------------------------------------------------
  // Common helpers
  // -------------------------------------------------------------------------

  String? _getEnclosingFunctionName(AstNode node) {
    AstNode? current = node;
    while (current != null) {
      if (current is FunctionDeclaration) return current.name.lexeme;
      if (current is MethodDeclaration) return current.name.lexeme;
      if (current is ConstructorDeclaration) {
        final classNode = current.parent;
        if (classNode is ClassDeclaration) return classNode.name.lexeme;
      }
      current = current.parent;
    }
    return null;
  }

  int _scopeKey(AstNode node) {
    AstNode? current = node;
    while (current != null) {
      if (current is FunctionDeclaration ||
          current is MethodDeclaration ||
          current is ConstructorDeclaration ||
          current is FunctionExpression) {
        return current.offset;
      }
      current = current.parent;
    }
    return -1;
  }

  Map<String, Expression> _scopeInitializers(AstNode node) {
    return _initializersByScope.putIfAbsent(_scopeKey(node), () => {});
  }

  Set<String> _scopeDeepLinkVariables(AstNode node) {
    return _deepLinkVariablesByScope.putIfAbsent(_scopeKey(node), () => {});
  }

  void _emit(
    AstNode node,
    IivRule rule, {
    String? confidence,
    Map<String, dynamic>? evidence,
  }) {
    final location = unit.lineInfo.getLocation(node.offset);
    final dedupeKey = '${rule.id}:${node.offset}';
    if (!_emitted.add(dedupeKey)) return;

    issues.add(
      Issue(
        filePath,
        rule.id,
        rule.description,
        rule.diagnosticSeverity,
        location.lineNumber,
        location.columnNumber,
        securitySeverity: rule.securitySeverity,
        confidence: confidence ?? rule.defaultConfidence,
        category: rule.category,
        remediation: rule.remediation,
        cwe: rule.cwe,
        evidence: {
          'checkKey': rule.checkKey,
          ...?evidence,
        },
        functionName: _getEnclosingFunctionName(node),
        component: 'iiv',
      ),
    );

    stderr.writeln(
      '[IIV] ${rule.id} at ${location.lineNumber}:${location.columnNumber}',
    );
  }

  NamedExpression? _namedArgument(ArgumentList arguments, String name) {
    for (final argument in arguments.arguments) {
      if (argument is NamedExpression && argument.name.label.name == name) {
        return argument;
      }
    }
    return null;
  }

  bool _namedBooleanEquals(
    ArgumentList arguments,
    String name,
    bool expected,
  ) {
    final named = _namedArgument(arguments, name);
    final expression = named?.expression;
    return expression is BooleanLiteral && expression.value == expected;
  }

  Expression _unwrap(Expression expression) {
    var current = expression;
    while (true) {
      if (current is ParenthesizedExpression) {
        current = current.expression;
        continue;
      }
      if (current is AwaitExpression) {
        current = current.expression;
        continue;
      }
      return current;
    }
  }

  Expression? _resolveInitializer(
    SimpleIdentifier identifier,
    AstNode context,
    Set<String> visited,
  ) {
    if (!visited.add(identifier.name)) return null;
    return _scopeInitializers(context)[identifier.name];
  }

  bool _isDynamicExpression(
    Expression expression,
    AstNode context, [
    Set<String>? visited,
  ]) {
    final seen = visited ?? <String>{};
    final current = _unwrap(expression);

    if (current is StringInterpolation) return true;

    if (current is AdjacentStrings) {
      return current.strings.any(
        (value) => _isDynamicExpression(value, context, seen),
      );
    }

    if (current is BinaryExpression) {
      if (current.operator.lexeme == '+') {
        return _isDynamicExpression(current.leftOperand, context, seen) ||
            _isDynamicExpression(current.rightOperand, context, seen);
      }
      return true;
    }

    if (current is ConditionalExpression) {
      return _isDynamicExpression(current.thenExpression, context, seen) ||
          _isDynamicExpression(current.elseExpression, context, seen);
    }

    if (current is ListLiteral) {
      for (final element in current.elements) {
        if (element is Expression &&
            _isDynamicExpression(element, context, seen)) {
          return true;
        }
      }
      return false;
    }

    if (current is SimpleIdentifier) {
      final initializer = _resolveInitializer(current, context, seen);
      if (initializer == null) return true;
      return _isDynamicExpression(initializer, context, seen);
    }

    if (current is StringLiteral ||
        current is IntegerLiteral ||
        current is DoubleLiteral ||
        current is BooleanLiteral ||
        current is NullLiteral) {
      return false;
    }

    // Property access, method calls and other expressions are runtime values.
    return true;
  }

  bool _containsLikelyExternalInput(Expression expression) {
    final source = expression.toSource().toLowerCase();
    const indicators = <String>[
      '.text',
      'userinput',
      'user_input',
      'username',
      'request',
      'parameter',
      'queryparam',
      'query_param',
      'deeplink',
      'deep_link',
      'external',
      'stdin',
    ];
    return indicators.any(source.contains);
  }

  String _confidenceForDynamicExpression(Expression expression) {
    return _containsLikelyExternalInput(expression) ? 'high' : 'medium';
  }

  // -------------------------------------------------------------------------
  // Local variable tracking
  // -------------------------------------------------------------------------

  @override
  void visitVariableDeclaration(VariableDeclaration node) {
    final initializer = node.initializer;
    if (initializer != null) {
      _scopeInitializers(node)[node.name.lexeme] = initializer;
      if (_containsDeepLinkSource(initializer)) {
        _scopeDeepLinkVariables(node).add(node.name.lexeme);
      }
    }
    super.visitVariableDeclaration(node);
  }

  @override
  void visitAssignmentExpression(AssignmentExpression node) {
    final left = node.leftHandSide;
    if (left is SimpleIdentifier) {
      _scopeInitializers(node)[left.name] = node.rightHandSide;
      if (_containsDeepLinkSource(node.rightHandSide)) {
        _scopeDeepLinkVariables(node).add(left.name);
      }
    }
    super.visitAssignmentExpression(node);
  }

  // -------------------------------------------------------------------------
  // Method invocation checks
  // -------------------------------------------------------------------------

  @override
  void visitMethodInvocation(MethodInvocation node) {
    final methodName = node.methodName.name;
    final rule = rules.ruleForFunction(methodName);

    if (rule != null) {
      switch (rule.checkKey) {
        case 'sql_injection':
          _checkSqlInvocation(node, rule);
          break;
        case 'command_injection':
          _checkCommandInvocation(node, rule);
          break;
        case 'unsafe_file_upload':
          _checkFileSelection(node, rule);
          break;
        case 'missing_form_validation':
          _checkTextFormField(node, node.argumentList, rule);
          break;
      }
    }

    if (rules.isDeepLinkSink(methodName)) {
      final deepLinkRule = rules.ruleFor('deep_link_poisoning');
      if (deepLinkRule != null) {
        _checkDeepLinkSink(node, deepLinkRule);
      }
    }

    super.visitMethodInvocation(node);
  }

  void _checkSqlInvocation(MethodInvocation node, IivRule rule) {
    if (node.argumentList.arguments.isEmpty) return;

    final firstArgument = node.argumentList.arguments.first;
    if (firstArgument is! Expression) return;

    // The presence of a separate bind-arguments list is strong evidence of a
    // parameterized query. We intentionally avoid reporting it here.
    if (node.argumentList.arguments.length >= 2) {
      return;
    }

    if (!_isDynamicExpression(firstArgument, node)) return;

    _emit(
      node,
      rule,
      confidence: _confidenceForDynamicExpression(firstArgument),
      evidence: {
        'sink': node.methodName.name,
        'queryExpression': firstArgument.toSource(),
        'parameterListDetected': false,
        'analysisScope': 'local-expression',
      },
    );
  }

  void _checkCommandInvocation(MethodInvocation node, IivRule rule) {
    if (node.target?.toString() != 'Process') return;
    if (node.argumentList.arguments.isEmpty) return;

    final dynamicArguments = <String>[];
    var highConfidence = false;

    for (final argument in node.argumentList.arguments) {
      final expression = argument is NamedExpression
          ? argument.expression
          : argument is Expression
              ? argument
              : null;

      if (expression == null) continue;
      if (_isDynamicExpression(expression, node)) {
        dynamicArguments.add(expression.toSource());
        highConfidence =
            highConfidence || _containsLikelyExternalInput(expression);
      }
    }

    // Constant executable and constant argument lists are not command injection.
    if (dynamicArguments.isEmpty) return;

    _emit(
      node,
      rule,
      confidence: highConfidence ? 'high' : 'medium',
      evidence: {
        'sink': 'Process.${node.methodName.name}',
        'dynamicArguments': dynamicArguments,
        'analysisScope': 'local-expression',
      },
    );
  }

  void _checkFileSelection(MethodInvocation node, IivRule rule) {
    // FilePicker.pickFiles is the API where FileType and allowedExtensions are
    // relevant. ImagePicker.pickImage/pickVideo are already media-specific and
    // should not be reported merely because they lack allowedExtensions.
    if (node.methodName.name != 'pickFiles') return;

    final allowedExtensions =
        _namedArgument(node.argumentList, 'allowedExtensions')?.expression;
    if (allowedExtensions is ListLiteral && allowedExtensions.elements.isNotEmpty) {
      return;
    }

    final typeExpression = _namedArgument(node.argumentList, 'type')?.expression;
    final typeText = typeExpression?.toSource().toLowerCase() ?? 'filetype.any';

    const restrictedTypes = <String>[
      'filetype.image',
      'filetype.video',
      'filetype.audio',
      'filetype.media',
    ];

    if (restrictedTypes.any(typeText.contains)) return;

    _emit(
      node,
      rule,
      confidence: 'medium',
      evidence: {
        'source': 'FilePicker.pickFiles',
        'fileType': typeExpression?.toSource() ?? 'FileType.any (default)',
        'allowedExtensionsDetected': false,
        'note': 'File type validation must also be repeated before upload or processing.',
      },
    );
  }

  // -------------------------------------------------------------------------
  // Deep-link source-to-sink heuristic
  // -------------------------------------------------------------------------

  bool _containsDeepLinkSource(Expression expression) {
    final source = expression.toSource();
    final rule = rules.ruleFor('deep_link_poisoning');
    if (rule == null) return false;

    for (final function in rule.sourceFunctions) {
      final pattern = RegExp('\\b${RegExp.escape(function)}\\s*\\(');
      if (pattern.hasMatch(source)) return true;
    }
    return false;
  }

  Set<String> _identifiersInExpression(Expression expression) {
    final collector = _IdentifierCollector();
    expression.accept(collector);
    return collector.names;
  }

  void _checkDeepLinkSink(MethodInvocation node, IivRule rule) {
    final taintedVariables = _scopeDeepLinkVariables(node);
    final usedTaintedVariables = <String>{};
    var directSource = false;

    for (final argument in node.argumentList.arguments) {
      final expression = argument is NamedExpression
          ? argument.expression
          : argument is Expression
              ? argument
              : null;
      if (expression == null) continue;

      directSource = directSource || _containsDeepLinkSource(expression);
      final identifiers = _identifiersInExpression(expression);
      usedTaintedVariables.addAll(identifiers.intersection(taintedVariables));
    }

    if (!directSource && usedTaintedVariables.isEmpty) return;
    if (_isProtectedByValidationGuard(node, usedTaintedVariables)) return;

    _emit(
      node,
      rule,
      confidence: directSource ? 'high' : 'medium',
      evidence: {
        'sink': node.methodName.name,
        'deepLinkVariables': usedTaintedVariables.toList()..sort(),
        'directSourceToSink': directSource,
        'validationGuardDetected': false,
        'analysisScope': 'same-function',
      },
    );
  }

  bool _isProtectedByValidationGuard(
    AstNode node,
    Set<String> variableNames,
  ) {
    AstNode? current = node.parent;
    while (current != null) {
      if (current is IfStatement) {
        final condition = current.expression.toSource().toLowerCase();
        final referencesVariable = variableNames.isEmpty ||
            variableNames.any(
              (name) => RegExp('\\b${RegExp.escape(name.toLowerCase())}\\b')
                  .hasMatch(condition),
            );

        if (referencesVariable && _looksLikeValidation(condition)) {
          return true;
        }
      }

      if (current is FunctionDeclaration ||
          current is MethodDeclaration ||
          current is ConstructorDeclaration) {
        break;
      }
      current = current.parent;
    }
    return false;
  }

  bool _looksLikeValidation(String condition) {
    final rule = rules.ruleFor('deep_link_poisoning');
    final configured = rule?.validatorFunctions ?? const <String>[];
    const builtInIndicators = <String>[
      '.scheme',
      '.host',
      'startswith',
      'regexp',
      'tryparse',
      'allowlist',
      'whitelist',
      'isallowed',
      'isvalid',
      'validate',
      'permitted',
    ];

    return configured.any(
          (name) => condition.contains(name.toLowerCase()),
        ) ||
        builtInIndicators.any(condition.contains);
  }

  // -------------------------------------------------------------------------
  // TextFormField checks
  // -------------------------------------------------------------------------

  @override
  void visitInstanceCreationExpression(InstanceCreationExpression node) {
    final typeName = node.constructorName.type.name2.lexeme;
    final rule = rules.ruleForFunction(typeName);

    if (rule != null && rule.checkKey == 'missing_form_validation') {
      _checkTextFormField(node, node.argumentList, rule);
    }

    super.visitInstanceCreationExpression(node);
  }

  void _checkTextFormField(
    AstNode node,
    ArgumentList arguments,
    IivRule rule,
  ) {
    final hasValidator = _namedArgument(arguments, 'validator') != null;
    final readOnly = _namedBooleanEquals(arguments, 'readOnly', true);
    final disabled = _namedBooleanEquals(arguments, 'enabled', false);

    if (hasValidator || readOnly || disabled) return;

    _emit(
      node,
      rule,
      confidence: 'medium',
      evidence: {
        'widget': 'TextFormField',
        'validatorDetected': false,
        'readOnly': false,
        'enabled': true,
        'note': 'Validation may exist outside the widget; manual review is recommended.',
      },
    );
  }

  void debugCounters() {
    stderr.writeln('[IIV] Found ${issues.length} input validation issue(s).');
  }
}

class _IdentifierCollector extends RecursiveAstVisitor<void> {
  final Set<String> names = {};

  @override
  void visitSimpleIdentifier(SimpleIdentifier node) {
    names.add(node.name);
    super.visitSimpleIdentifier(node);
  }
}
