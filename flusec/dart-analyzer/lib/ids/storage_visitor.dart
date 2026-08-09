// lib/ids/storage_visitor.dart
//
// IDS detects a storage event only when all of the following are present:
//   1. sensitive-data evidence,
//   2. an insecure persistence sink, and
//   3. no recognized protection before the sink.
//
// IDS does not detect hardcoded secrets by itself. HSD owns vendor secret
// patterns, entropy checks, and hardcoded-value classification.

import 'dart:io';

import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';

import '../core/code_context.dart';
import '../core/issue.dart';
import 'heuristic_analyzer.dart';
import 'ids_rules.dart';

class StorageVisitor extends RecursiveAstVisitor<void> {
  final CompilationUnit unit;
  final String sourceCode;
  final String filePath;
  final IdsRulesEngine rules;
  final List<Issue> issues = [];

  final SensitiveVariableAnalyzer variableAnalyzer =
      SensitiveVariableAnalyzer();
  final IdsSeverityClassifier severityClassifier = IdsSeverityClassifier();

  final Set<String> imports = {};
  final Map<int, Map<String, Expression>> _initializersByScope = {};
  final Map<int, Map<String, String>> _sensitiveTypesByScope = {};
  final Map<int, Set<String>> _protectedVariablesByScope = {};
  final Map<int, Map<String, String>> _directoryContextsByScope = {};
  final Map<int, Map<String, String>> _fileContextsByScope = {};
  final Set<String> _emitted = {};

  int _methods = 0;
  int _variables = 0;
  int _instances = 0;

  StorageVisitor(this.unit, this.sourceCode, this.filePath, this.rules);

  // -------------------------------------------------------------------------
  // Scope helpers
  // -------------------------------------------------------------------------

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

  Map<String, String> _scopeSensitiveTypes(AstNode node) {
    return _sensitiveTypesByScope.putIfAbsent(_scopeKey(node), () => {});
  }

  Set<String> _scopeProtectedVariables(AstNode node) {
    return _protectedVariablesByScope.putIfAbsent(_scopeKey(node), () => {});
  }

  Map<String, String> _scopeDirectoryContexts(AstNode node) {
    return _directoryContextsByScope.putIfAbsent(_scopeKey(node), () => {});
  }

  Map<String, String> _scopeFileContexts(AstNode node) {
    return _fileContextsByScope.putIfAbsent(_scopeKey(node), () => {});
  }


  // -------------------------------------------------------------------------
  // Imports and local state tracking
  // -------------------------------------------------------------------------

  @override
  void visitImportDirective(ImportDirective node) {
    final uri = node.uri.stringValue;
    if (uri != null) imports.add(uri);
    super.visitImportDirective(node);
  }

  @override
  void visitVariableDeclaration(VariableDeclaration node) {
    _variables++;
    final name = node.name.lexeme;
    final initializer = node.initializer;

    if (initializer != null) {
      _trackAssignment(name, initializer, node);
    } else {
      final result = variableAnalyzer.analyze(name);
      if (result.isSensitive) {
        _scopeSensitiveTypes(node)[name] = result.dataType;
      }
    }

    super.visitVariableDeclaration(node);
  }

  @override
  void visitAssignmentExpression(AssignmentExpression node) {
    final left = node.leftHandSide;
    if (left is SimpleIdentifier) {
      _trackAssignment(left.name, node.rightHandSide, node);
    }
    super.visitAssignmentExpression(node);
  }

  void _trackAssignment(String name, Expression expression, AstNode context) {
    _scopeInitializers(context)[name] = expression;

    final nameResult = variableAnalyzer.analyze(name);
    final expressionEvidence = _sensitivityOfExpression(expression, context);

    if (nameResult.isSensitive) {
      _scopeSensitiveTypes(context)[name] = nameResult.dataType;
    } else if (expressionEvidence.isSensitive) {
      _scopeSensitiveTypes(context)[name] = expressionEvidence.dataType;
    }

    if (_isProtectedExpression(expression, context)) {
      _scopeProtectedVariables(context).add(name);
    } else {
      _scopeProtectedVariables(context).remove(name);
    }

    final directoryContext = _directoryContextFromExpression(expression, context);
    if (directoryContext != null) {
      _scopeDirectoryContexts(context)[name] = directoryContext;
    }

    final fileContext = _fileContextFromExpression(expression, context);
    if (fileContext != null) {
      _scopeFileContexts(context)[name] = fileContext;
    }
  }

  // -------------------------------------------------------------------------
  // Method and constructor detection
  // -------------------------------------------------------------------------

  @override
  void visitMethodInvocation(MethodInvocation node) {
    _methods++;
    final methodName = node.methodName.name;

    if (_isSharedPreferencesWrite(node)) {
      _checkSharedPreferences(node);
    } else if (_isFileWrite(methodName)) {
      _checkFileWrite(node);
    } else if (_isSqliteWrite(node)) {
      _checkSqliteWrite(node);
    } else if (_isWebViewJavaScript(methodName)) {
      _checkWebViewStorage(node);
    }

    super.visitMethodInvocation(node);
  }

  @override
  void visitInstanceCreationExpression(InstanceCreationExpression node) {
    _instances++;
    // Constructing File or Directory objects alone is not an IDS finding.
    super.visitInstanceCreationExpression(node);
  }

  // -------------------------------------------------------------------------
  // SharedPreferences
  // -------------------------------------------------------------------------

  bool _isSharedPreferencesWrite(MethodInvocation node) {
    const writeMethods = {
      'setString',
      'setInt',
      'setDouble',
      'setBool',
      'setStringList',
    };

    if (!writeMethods.contains(node.methodName.name)) return false;

    final target = node.target?.toSource().toLowerCase() ?? '';
    final likelyTarget = target.contains('prefs') ||
        target.contains('preference') ||
        imports.contains('package:shared_preferences/shared_preferences.dart');

    return likelyTarget;
  }

  void _checkSharedPreferences(MethodInvocation node) {
    final rule = rules.ruleFor('shared_prefs');
    if (rule == null) return;

    final positional = _positionalArguments(node.argumentList);
    if (positional.length < 2) return;

    final keyExpression = positional[0];
    final valueExpression = positional[1];
    final evidence = _storageValueEvidence(
      valueExpression,
      node,
      keyExpression: keyExpression,
    );

    if (!evidence.isSensitive || evidence.isProtected) return;

    _emit(
      node,
      rule,
      dataType: evidence.dataType,
      confidence: evidence.confidence,
      storageContext: 'shared_prefs',
      evidence: {
        'sink': 'SharedPreferences.${node.methodName.name}',
        'storageKey': _safeStorageKey(keyExpression),
        'valueKind': _nodeKindName(valueExpression),
        'valueRedacted': true,
        'sensitiveEvidence': evidence.reason,
        'protectionDetected': false,
        'analysisScope': 'same-function',
      },
    );
  }

  // -------------------------------------------------------------------------
  // File, external-storage and cache writes
  // -------------------------------------------------------------------------

  bool _isFileWrite(String methodName) {
    return const {
      'writeAsString',
      'writeAsStringSync',
      'writeAsBytes',
      'writeAsBytesSync',
    }.contains(methodName);
  }

  void _checkFileWrite(MethodInvocation node) {
    final positional = _positionalArguments(node.argumentList);
    if (positional.isEmpty) return;

    final valueExpression = positional.first;
    final valueEvidence = _storageValueEvidence(valueExpression, node);
    if (!valueEvidence.isSensitive || valueEvidence.isProtected) return;

    final storageContext = _storageContextForFileTarget(node.target, node);
    final checkKey = switch (storageContext) {
      'external_storage' => 'external_storage',
      'cache' => 'cache_storage',
      _ => 'file_storage',
    };

    final rule = rules.ruleFor(checkKey);
    if (rule == null) return;

    _emit(
      node,
      rule,
      dataType: valueEvidence.dataType,
      confidence: valueEvidence.confidence,
      storageContext: storageContext,
      evidence: {
        'sink': 'File.${node.methodName.name}',
        'targetKind': node.target == null
            ? 'unknown'
            : _nodeKindName(node.target!),
        'valueKind': _nodeKindName(valueExpression),
        'valueRedacted': true,
        'sensitiveEvidence': valueEvidence.reason,
        'protectionDetected': false,
        'analysisScope': 'same-function',
      },
    );
  }

  String _storageContextForFileTarget(Expression? target, AstNode context) {
    if (target == null) return 'file';

    if (target is SimpleIdentifier) {
      return _scopeFileContexts(context)[target.name] ?? 'file';
    }

    return _fileContextFromSource(target.toSource(), context) ?? 'file';
  }

  // -------------------------------------------------------------------------
  // SQLite
  // -------------------------------------------------------------------------

  bool _isSqliteWrite(MethodInvocation node) {
    const writeMethods = {'insert', 'update', 'rawInsert', 'rawUpdate'};
    if (!writeMethods.contains(node.methodName.name)) return false;

    final target = node.target?.toSource().toLowerCase() ?? '';
    return target.contains('db') ||
        target.contains('database') ||
        imports.contains('package:sqflite/sqflite.dart');
  }

  void _checkSqliteWrite(MethodInvocation node) {
    final rule = rules.ruleFor('sqlite_storage');
    if (rule == null) return;

    final positional = _positionalArguments(node.argumentList);
    if (positional.isEmpty) return;

    final candidateExpressions = node.methodName.name.startsWith('raw')
        ? positional.skip(1)
        : positional.skip(1);

    for (final expression in candidateExpressions) {
      final valueEvidence = _storageValueEvidence(expression, node);
      if (!valueEvidence.isSensitive || valueEvidence.isProtected) continue;

      _emit(
        node,
        rule,
        dataType: valueEvidence.dataType,
        confidence: valueEvidence.confidence,
        storageContext: 'sqlite',
        evidence: {
          'sink': 'SQLite.${node.methodName.name}',
          'valueKind': _nodeKindName(expression),
          'valueRedacted': true,
          'sensitiveEvidence': valueEvidence.reason,
          'protectionDetected': false,
          'analysisScope': 'same-function',
        },
      );
      return;
    }
  }

  // -------------------------------------------------------------------------
  // WebView browser storage
  // -------------------------------------------------------------------------

  bool _isWebViewJavaScript(String methodName) {
    return const {
      'runJavascript',
      'runJavaScript',
      'evaluateJavascript',
      'evaluateJavaScript',
    }.contains(methodName);
  }

  void _checkWebViewStorage(MethodInvocation node) {
    final rule = rules.ruleFor('webview_storage');
    if (rule == null) return;

    final positional = _positionalArguments(node.argumentList);
    if (positional.isEmpty) return;

    final script = positional.first;
    final source = script.toSource();
    final lower = source.toLowerCase();

    final usesBrowserStorage = lower.contains('localstorage.setitem') ||
        lower.contains('sessionstorage.setitem') ||
        lower.contains('document.cookie');
    if (!usesBrowserStorage) return;

    final valueEvidence = _storageValueEvidence(script, node);
    if (!valueEvidence.isSensitive || valueEvidence.isProtected) return;

    _emit(
      node,
      rule,
      dataType: valueEvidence.dataType,
      confidence: valueEvidence.confidence,
      storageContext: 'webview',
      evidence: {
        'sink': 'WebView.${node.methodName.name}',
        'browserStorage': lower.contains('document.cookie')
            ? 'document.cookie'
            : lower.contains('sessionstorage')
                ? 'sessionStorage'
                : 'localStorage',
        'sensitiveEvidence': valueEvidence.reason,
        'protectionDetected': false,
        'analysisScope': 'same-function',
      },
    );
  }

  // -------------------------------------------------------------------------
  // Sensitive-value and protection analysis
  // -------------------------------------------------------------------------

  List<Expression> _positionalArguments(ArgumentList argumentList) {
    return argumentList.arguments
        .where((argument) => argument is! NamedExpression)
        .cast<Expression>()
        .toList(growable: false);
  }

  _StorageValueEvidence _storageValueEvidence(
    Expression expression,
    AstNode context, {
    Expression? keyExpression,
  }) {
    final protected = _isProtectedExpression(expression, context);
    final expressionResult = _sensitivityOfExpression(expression, context);

    if (expressionResult.isSensitive) {
      return _StorageValueEvidence(
        isSensitive: true,
        isProtected: protected,
        dataType: expressionResult.dataType,
        confidence: _confidenceLabel(expressionResult.confidenceScore),
        reason: expressionResult.matchedKeywords.isEmpty
            ? 'sensitive expression'
            : 'identifier: ${expressionResult.matchedKeywords.join(', ')}',
      );
    }

    if (keyExpression != null) {
      final keyResult = variableAnalyzer.analyze(keyExpression.toSource());
      if (keyResult.isSensitive && !_isClearlyNonSensitiveLiteral(expression)) {
        return _StorageValueEvidence(
          isSensitive: true,
          isProtected: protected,
          dataType: keyResult.dataType,
          confidence: 'medium',
          reason: 'sensitive storage key: ${keyResult.matchedKeywords.join(', ')}',
        );
      }
    }

    return const _StorageValueEvidence.notSensitive();
  }

  SensitivityResult _sensitivityOfExpression(
    Expression expression,
    AstNode context, [
    Set<String>? visited,
  ]) {
    final seen = visited ?? <String>{};
    final sourceResult = variableAnalyzer.analyze(expression.toSource());
    if (sourceResult.isSensitive) return sourceResult;

    if (expression is SimpleIdentifier) {
      if (!seen.add(expression.name)) {
        return const SensitivityResult(
          isSensitive: false,
          dataType: 'GENERIC_SENSITIVE',
          confidenceScore: 0,
          matchedKeywords: [],
        );
      }

      final trackedType = _scopeSensitiveTypes(context)[expression.name];
      if (trackedType != null) {
        return SensitivityResult(
          isSensitive: true,
          dataType: trackedType,
          confidenceScore: 0.9,
          matchedKeywords: [expression.name],
        );
      }

      final initializer = _scopeInitializers(context)[expression.name];
      if (initializer != null) {
        return _sensitivityOfExpression(initializer, context, seen);
      }
    }

    return const SensitivityResult(
      isSensitive: false,
      dataType: 'GENERIC_SENSITIVE',
      confidenceScore: 0,
      matchedKeywords: [],
    );
  }

  bool _isProtectedExpression(
    Expression expression,
    AstNode context, [
    Set<String>? visited,
  ]) {
    final seen = visited ?? <String>{};
    final lower = expression.toSource().toLowerCase();

    const protectionIndicators = [
      'encrypt(',
      '.encrypt(',
      'encryptdata(',
      'aesencrypt(',
      'cipher.encrypt(',
      'seal(',
      'sealedbox',
      'ciphertext',
      'encryptedvalue',
      'encrypted_value',
    ];

    if (protectionIndicators.any(lower.contains)) return true;

    if (expression is SimpleIdentifier) {
      if (_scopeProtectedVariables(context).contains(expression.name)) {
        return true;
      }

      if (!seen.add(expression.name)) return false;
      final initializer = _scopeInitializers(context)[expression.name];
      if (initializer != null) {
        return _isProtectedExpression(initializer, context, seen);
      }
    }

    return false;
  }

  bool _isClearlyNonSensitiveLiteral(Expression expression) {
    if (expression is BooleanLiteral ||
        expression is IntegerLiteral ||
        expression is DoubleLiteral ||
        expression is NullLiteral) {
      return true;
    }

    if (expression is SimpleStringLiteral) {
      final value = expression.value.toLowerCase();
      const safeValues = {
        '',
        'true',
        'false',
        'enabled',
        'disabled',
        'light',
        'dark',
        'system',
      };
      return safeValues.contains(value);
    }

    return false;
  }

  String _confidenceLabel(double score) {
    if (score >= 0.9) return 'high';
    if (score >= 0.7) return 'medium';
    return 'low';
  }

  // -------------------------------------------------------------------------
  // File/directory context tracking
  // -------------------------------------------------------------------------

  String? _directoryContextFromExpression(
    Expression expression,
    AstNode context,
  ) {
    final source = expression.toSource().toLowerCase();
    if (source.contains('getexternalstoragedirectory') ||
        source.contains('getexternalstoragedirectories')) {
      return 'external_storage';
    }

    if (source.contains('gettemporarydirectory') ||
        source.contains('getapplicationcachedirectory') ||
        source.contains('directory.systemtemp')) {
      return 'cache';
    }

    if (expression is SimpleIdentifier) {
      return _scopeDirectoryContexts(context)[expression.name];
    }

    return null;
  }

  String? _fileContextFromExpression(Expression expression, AstNode context) {
    if (expression is InstanceCreationExpression) {
      final typeName = expression.constructorName.type.name.lexeme;
      if (typeName != 'File') return null;

      final positional = _positionalArguments(expression.argumentList);
      if (positional.isEmpty) return 'file';
      return _fileContextFromSource(positional.first.toSource(), context) ??
          'file';
    }

    if (expression is SimpleIdentifier) {
      return _scopeFileContexts(context)[expression.name];
    }

    return _fileContextFromSource(expression.toSource(), context);
  }

  String? _fileContextFromSource(String source, AstNode context) {
    final lower = source.toLowerCase();
    if (lower.contains('getexternalstoragedirectory') ||
        lower.contains('getexternalstoragedirectories')) {
      return 'external_storage';
    }

    if (lower.contains('gettemporarydirectory') ||
        lower.contains('getapplicationcachedirectory') ||
        lower.contains('directory.systemtemp')) {
      return 'cache';
    }

    for (final entry in _scopeDirectoryContexts(context).entries) {
      final pattern = RegExp('\\b${RegExp.escape(entry.key)}\\b');
      if (pattern.hasMatch(source)) return entry.value;
    }

    return null;
  }

  String _nodeKindName(AstNode node) {
    final rawName = node.runtimeType.toString();
    return rawName.endsWith('Impl')
        ? rawName.substring(0, rawName.length - 4)
        : rawName;
  }

  String _safeStorageKey(Expression expression) {
    if (expression is SimpleStringLiteral) {
      final value = expression.value;
      return value.length <= 80 ? value : '${value.substring(0, 77)}...';
    }

    if (expression is SimpleIdentifier) {
      return expression.name;
    }

    return '[${_nodeKindName(expression)}]';
  }

  // -------------------------------------------------------------------------
  // Finding emission
  // -------------------------------------------------------------------------

  void _emit(
    AstNode node,
    IdsRule rule, {
    required String dataType,
    required String confidence,
    required String storageContext,
    required Map<String, dynamic> evidence,
  }) {
    final dedupeKey = '${rule.id}:${node.offset}';
    if (!_emitted.add(dedupeKey)) return;

    final location = unit.lineInfo.getLocation(node.offset);
    final securitySeverity = severityClassifier.classify(
      baseSeverity: rule.securitySeverity,
      dataType: dataType,
      storageContext: storageContext,
    );
    final codeContext = CodeContextAnalyzer.fromNode(node);

    final findingEvidence = <String, dynamic>{
      'checkKey': rule.checkKey,
      'dataType': dataType,
      'storageContext': storageContext,
      ...evidence,
    };

    if (codeContext != null) {
      findingEvidence['maintainabilityContext'] =
          codeContext.maintainabilityEvidence();
    }

    issues.add(
      Issue(
        filePath,
        rule.id,
        rule.description,
        flusecSecurityDiagnosticSeverity,
        location.lineNumber,
        location.columnNumber,
        securitySeverity: securitySeverity,
        confidence: confidence,
        category: rule.category,
        remediation: rule.remediation,
        cwe: rule.cwe,
        evidence: findingEvidence,
        functionName: codeContext?.functionName,
        complexity: codeContext?.complexity,
        nestingDepth: codeContext?.nestingDepth,
        functionLoc: codeContext?.functionLoc,
        maintainabilityScore: codeContext?.maintainabilityScore,
        maintainabilityLevel: codeContext?.maintainabilityLevel,
        component: 'ids',
        dataType: dataType,
        storageContext: storageContext,
      ),
    );

    stderr.writeln(
      '[IDS] ${rule.id} at ${location.lineNumber}:${location.columnNumber}',
    );
  }

  void debugCounters() {
    stderr.writeln(
      '[IDS] counters: methods=$_methods variables=$_variables '
      'instances=$_instances findings=${issues.length}',
    );
  }
}

class _StorageValueEvidence {
  final bool isSensitive;
  final bool isProtected;
  final String dataType;
  final String confidence;
  final String reason;

  const _StorageValueEvidence({
    required this.isSensitive,
    required this.isProtected,
    required this.dataType,
    required this.confidence,
    required this.reason,
  });

  const _StorageValueEvidence.notSensitive()
      : isSensitive = false,
        isProtected = false,
        dataType = 'GENERIC_SENSITIVE',
        confidence = 'low',
        reason = '';
}
