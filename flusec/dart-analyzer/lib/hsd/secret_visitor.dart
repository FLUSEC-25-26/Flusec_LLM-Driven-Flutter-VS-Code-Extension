// lib/hsd/secret_visitor.dart
//
// AST visitor for refined FLUSEC Hardcoded Secrets Detection (HSD).
//
// Detection coverage:
// - variable declarations
// - assignments
// - map values
// - named/positional arguments
// - list values
// - simple compile-time string concatenation/adjacent strings
// - String.fromEnvironment(..., defaultValue: <hardcoded secret>)
//
// HSD/IDS boundary:
// A hardcoded secret remains an HSD finding even when it is passed directly to
// an insecure storage API. IDS may separately report the storage weakness.

import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/token.dart';
import 'package:analyzer/dart/ast/visitor.dart';

import '../core/issue.dart';
import 'complexity.dart';
import 'function_utils.dart';
import 'hardcoded_secrets_rules.dart';
import 'taint_tracker.dart';

class SecretVisitor extends RecursiveAstVisitor<void> {
  final RulesEngine engine;
  final String raw;
  final String filePath;

  final List<Issue> issues = [];
  final Set<String> _seen = {};

  CompilationUnit? _unit;

  SecretVisitor(this.engine, this.raw, this.filePath);

  void setUnit(CompilationUnit unit) {
    _unit = unit;
  }

  String _nodeKindName(AstNode node) {
    final rawName = node.runtimeType.toString();
    return rawName.endsWith('Impl')
        ? rawName.substring(0, rawName.length - 4)
        : rawName;
  }

  List<Map<String, dynamic>>? _runTaintTracking(
    AstNode declarationNode,
    String variableName,
    int sourceLine,
  ) {
    if (_unit == null || variableName.trim().isEmpty) return null;

    try {
      final steps = trackTaintFlow(
        taintedVarName: variableName,
        declarationNode: declarationNode,
        unit: _unit!,
        sourceLine: sourceLine,
      );

      if (steps.isEmpty) return null;
      return steps.map((step) => step.toJson()).toList();
    } catch (_) {
      // Taint context is best-effort and must never fail secret detection.
      return null;
    }
  }

  void _maybeReport(
    AstNode reportNode,
    String? value,
    String contextName, {
    AstNode? taintDeclarationNode,
    String? taintVarName,
  }) {
    if (value == null || value.trim().isEmpty) return;

    final nodeKind = _nodeKindName(reportNode);
    final hit = engine.detect(value, contextName, nodeKind);
    if (hit == null) return;

    final loc = _nodeLocation(reportNode);
    final dedupKey = '$filePath:${loc.$1}:${loc.$2}:${hit.ruleId}';
    if (!_seen.add(dedupKey)) return;

    String? functionName;
    int? complexity;
    int? nestingDepth;
    int? functionLoc;
    int? maintainabilityScore;
    String? maintainabilityLevel;
    MaintainabilityContext? maintainability;

    final executable = FunctionUtils.enclosingExecutable(reportNode);
    if (executable != null) {
      functionName = FunctionUtils.executableName(executable);
      if (functionName == '<anonymous>') {
        functionName = null;
      }

      complexity = Complexity.computeCyclomaticComplexity(executable);
      nestingDepth = Complexity.computeMaxNestingDepth(executable);
      functionLoc = Complexity.computeFunctionLoc(executable);

      maintainability = Complexity.computeMaintainabilityContext(
        complexity: complexity,
        nestingDepth: nestingDepth,
        functionLoc: functionLoc,
      );
      maintainabilityScore = maintainability.score;
      maintainabilityLevel = maintainability.level;
    }

    List<Map<String, dynamic>>? taintFlow;
    if (taintDeclarationNode != null &&
        taintVarName != null &&
        taintVarName.trim().isNotEmpty) {
      taintFlow = _runTaintTracking(
        taintDeclarationNode,
        taintVarName,
        loc.$1,
      );
    }

    final evidence = <String, dynamic>{...hit.evidence};

    if (maintainability != null) {
      evidence['maintainabilityContext'] = {
        ...maintainability.toJson(),
        'complexity': complexity,
        'nestingDepth': nestingDepth,
        'functionLoc': functionLoc,
        'note':
            'FLUSEC-defined maintainability context; not a security-severity score.',
      };
    }

    // Correlate an AWS secret access key with a nearby access-key identifier,
    // but never copy the identifier or secret value into the finding.
    if (hit.secretType == 'AWS_SECRET_ACCESS_KEY') {
      final scopeSource = executable?.toSource() ?? raw;
      final hasNearbyAccessKeyId = RegExp(
        r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b',
      ).hasMatch(scopeSource);
      evidence['nearbyAwsAccessKeyId'] = hasNearbyAccessKeyId;
    }

    if (taintFlow != null && taintFlow.isNotEmpty) {
      evidence['taintSinkTypes'] = taintFlow
          .map((step) => step['type']?.toString() ?? '')
          .where((type) => type.isNotEmpty)
          .toSet()
          .toList();
    }

    final message = functionName == null
        ? hit.message
        : '${hit.message} in function $functionName';

    issues.add(
      Issue(
        filePath,
        hit.ruleId,
        message,
        'warning',
        loc.$1,
        loc.$2,
        securitySeverity: hit.securitySeverity,
        confidence: hit.confidence,
        category: hit.category,
        remediation: hit.remediation,
        cwe: hit.cwe,
        evidence: evidence,
        functionName: functionName,
        complexity: complexity,
        nestingDepth: nestingDepth,
        functionLoc: functionLoc,
        maintainabilityScore: maintainabilityScore,
        maintainabilityLevel: maintainabilityLevel,
        secretType: hit.secretType,
        taintFlow: taintFlow,
        component: 'hsd',
      ),
    );
  }

  (int, int) _nodeLocation(AstNode node) {
    final unit = node.root as CompilationUnit;
    final location = unit.lineInfo.getLocation(node.offset);
    return (location.lineNumber, location.columnNumber);
  }

  /// Evaluate only simple deterministic compile-time string expressions.
  /// Arbitrary Dart execution is intentionally not attempted.
  String? _constantStringFromExpression(Expression? expression) {
    if (expression == null) return null;

    if (expression is StringLiteral) {
      return expression.stringValue;
    }

    if (expression is ParenthesizedExpression) {
      return _constantStringFromExpression(expression.expression);
    }

    if (expression is BinaryExpression && expression.operator.lexeme == '+') {
      final left = _constantStringFromExpression(expression.leftOperand);
      final right = _constantStringFromExpression(expression.rightOperand);
      if (left != null && right != null) {
        return '$left$right';
      }
    }

    if (expression is AdjacentStrings) {
      final buffer = StringBuffer();
      for (final string in expression.strings) {
        final value = _constantStringFromExpression(string);
        if (value == null) return null;
        buffer.write(value);
      }
      return buffer.toString();
    }

    return null;
  }

  String _nameFrom(Object? value) {
    if (value == null) return '';
    if (value is SimpleIdentifier) return value.name;
    if (value is PrefixedIdentifier) return value.identifier.name;
    if (value is Token) return value.lexeme;
    if (value is AstNode) return value.toSource();
    return value.toString();
  }

  String _lhsName(Expression lhs) {
    if (lhs is SimpleIdentifier) return lhs.name;
    if (lhs is PrefixedIdentifier) return lhs.identifier.name;
    if (lhs is PropertyAccess) return lhs.propertyName.name;

    // Keep the index/key source because config['password'] is much more useful
    // context than only "config".
    if (lhs is IndexExpression) return lhs.toSource();

    return lhs.toSource();
  }

  /// Returns true when [node] is part of the key expression of a map entry.
  ///
  /// Map keys such as:
  ///   {'Authorization': authHeader}
  ///   {'access_token': token}
  ///
  /// are semantic labels, not credential values. They may provide context for
  /// the corresponding map value, but must never be sent to the HSD rules
  /// engine as candidate secret material.
  bool _isInsideMapKey(AstNode node) {
    AstNode? current = node;

    while (current != null) {
      final parent = current.parent;

      if (parent is MapLiteralEntry) {
        final key = parent.key;

        final nodeStart = node.offset;
        final nodeEnd = node.end;
        final keyStart = key.offset;
        final keyEnd = key.end;

        return nodeStart >= keyStart && nodeEnd <= keyEnd;
      }

      current = parent;
    }

    return false;
  }

  String _contextFromAncestors(AstNode node) {
    AstNode? current = node.parent;

    while (current != null) {
      if (current is VariableDeclaration) {
        return _nameFrom(current.name);
      }

      if (current is AssignmentExpression) {
        return _lhsName(current.leftHandSide);
      }

      if (current is MapLiteralEntry) {
        return _constantStringFromExpression(current.key) ??
            current.key.toSource();
      }

      if (current is NamedExpression) {
        return current.name.label.name;
      }

      if (current is ReturnStatement || current is ExpressionFunctionBody) {
        final executable = FunctionUtils.enclosingExecutable(current);
        if (executable != null) {
          final name = FunctionUtils.executableName(executable);
          if (name != '<anonymous>') return name;
        }
      }

      current = current.parent;
    }

    return '';
  }

  // Catch strong/semantic secrets that appear in source locations not covered
  // by the targeted declaration/map/argument visitors, for example direct
  // return literals, expression-bodied getters, conditional branches, and set
  // literals. Context-rich parent visitors execute first where available; the
  // location/rule dedup key prevents duplicate findings.
  @override
  void visitSimpleStringLiteral(SimpleStringLiteral node) {
    // Map keys are labels/context, not secret values. The corresponding
    // MapLiteralEntry visitor analyzes only the value and uses this key as
    // semantic context.
    if (!_isInsideMapKey(node)) {
      _maybeReport(
        node,
        node.stringValue,
        _contextFromAncestors(node),
      );
    }

    super.visitSimpleStringLiteral(node);
  }

  @override
  void visitAdjacentStrings(AdjacentStrings node) {
    if (!_isInsideMapKey(node)) {
      _maybeReport(
        node,
        _constantStringFromExpression(node),
        _contextFromAncestors(node),
      );
    }

    super.visitAdjacentStrings(node);
  }

  @override
  void visitBinaryExpression(BinaryExpression node) {
    if (node.operator.lexeme == '+' && !_isInsideMapKey(node)) {
      _maybeReport(
        node,
        _constantStringFromExpression(node),
        _contextFromAncestors(node),
      );
    }

    super.visitBinaryExpression(node);
  }

  @override
  void visitVariableDeclaration(VariableDeclaration node) {
    final name = _nameFrom(node.name);
    final initializer = node.initializer;
    final value = _constantStringFromExpression(initializer);

    if (initializer != null) {
      _maybeReport(
        initializer,
        value,
        name,
        taintDeclarationNode: node,
        taintVarName: name,
      );
    }

    super.visitVariableDeclaration(node);
  }

  @override
  void visitAssignmentExpression(AssignmentExpression node) {
    final leftName = _lhsName(node.leftHandSide);
    final value = _constantStringFromExpression(node.rightHandSide);

    _maybeReport(
      node.rightHandSide,
      value,
      leftName,
      taintDeclarationNode: node,
      taintVarName: leftName,
    );

    super.visitAssignmentExpression(node);
  }

  @override
  void visitMapLiteralEntry(MapLiteralEntry node) {
    final context = _constantStringFromExpression(node.key) ?? node.key.toSource();
    final value = _constantStringFromExpression(node.value);

    _maybeReport(node.value, value, context);
    super.visitMapLiteralEntry(node);
  }

  String _contextForArgument(ArgumentList node, int index) {
    final arg = node.arguments[index];

    if (arg is NamedExpression) {
      final label = arg.name.label.name;

      // key/value APIs such as:
      //   secureStorage.write(key: 'access_token', value: 'hardcoded...')
      // A hardcoded secret is still HSD even if the destination storage itself
      // is secure. Use the sibling key as semantic context for the value.
      if (label == 'value' || label == 'data') {
        for (final sibling in node.arguments) {
          if (sibling is! NamedExpression) continue;
          if (sibling.name.label.name != 'key') continue;

          final key = _constantStringFromExpression(sibling.expression);
          if (key != null && key.trim().isNotEmpty) return key;
        }
      }

      return label;
    }

    final parent = node.parent;
    if (parent is MethodInvocation && index >= 1) {
      const keyValueMethods = <String>{
        'setString',
        'setBool',
        'setInt',
        'setDouble',
        'setStringList',
      };

      if (keyValueMethods.contains(parent.methodName.name)) {
        final firstArg = node.arguments.first;
        final firstExpression = firstArg is NamedExpression
            ? firstArg.expression
            : firstArg;
        final key = _constantStringFromExpression(firstExpression);
        if (key != null && key.trim().isNotEmpty) return key;
      }
    }

    return '';
  }

  @override
  void visitArgumentList(ArgumentList node) {
    for (var index = 0; index < node.arguments.length; index++) {
      final arg = node.arguments[index];
      final expression = arg is NamedExpression ? arg.expression : arg;
      final context = _contextForArgument(node, index);
      final value = _constantStringFromExpression(expression);
      _maybeReport(expression, value, context);
    }

    super.visitArgumentList(node);
  }

  @override
  void visitListLiteral(ListLiteral node) {
    for (var index = 0; index < node.elements.length; index++) {
      final element = node.elements[index];
      if (element is! Expression) continue;

      final value = _constantStringFromExpression(element);
      _maybeReport(element, value, 'list[$index]');
    }

    super.visitListLiteral(node);
  }

  @override
  void visitMethodInvocation(MethodInvocation node) {
    // String.fromEnvironment('DB_PASSWORD', defaultValue: 'hardcoded-value')
    // is not safe merely because the main value comes from the environment.
    if (node.methodName.name == 'fromEnvironment' &&
        node.target?.toSource() == 'String') {
      String environmentName = '';

      if (node.argumentList.arguments.isNotEmpty) {
        final first = node.argumentList.arguments.first;
        if (first is Expression) {
          environmentName = _constantStringFromExpression(first) ?? '';
        }
      }

      for (final arg in node.argumentList.arguments) {
        if (arg is! NamedExpression) continue;
        if (arg.name.label.name != 'defaultValue') continue;

        final value = _constantStringFromExpression(arg.expression);
        _maybeReport(
          arg.expression,
          value,
          environmentName.isEmpty ? 'defaultValue' : environmentName,
        );
      }
    }

    super.visitMethodInvocation(node);
  }
}
