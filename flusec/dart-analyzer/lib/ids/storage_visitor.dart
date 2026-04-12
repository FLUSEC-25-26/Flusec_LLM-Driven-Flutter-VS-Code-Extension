// lib/ids/storage_visitor.dart
//
// AST visitor for detecting insecure data storage patterns.
//
// REFACTORED to use IdsRulesEngine (loaded from JSON via rule repo)
// and emit shared Issue objects with component: 'ids'.

import 'dart:io';
import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';

import '../core/issue.dart';
import 'ids_rules.dart';
import 'heuristic_analyzer.dart';

class StorageVisitor extends RecursiveAstVisitor<void> {
  final CompilationUnit unit;
  final String filePath;
  final String sourceCode;
  final IdsRulesEngine rules;
  final List<Issue> issues = [];

  // Heuristic helpers
  final SensitiveVariableAnalyzer variableAnalyzer = SensitiveVariableAnalyzer();
  final SeverityClassifier severityClassifier = SeverityClassifier();

  // Track imports
  final Set<String> imports = {};

  // Track sensitive variables
  final Map<String, String> sensitiveVariables = {};

  // DEBUG counters
  int _methods = 0, _strings = 0, _instances = 0, _variables = 0;

  StorageVisitor(this.unit, this.sourceCode, this.filePath, this.rules);

  @override
  void visitImportDirective(ImportDirective node) {
    super.visitImportDirective(node);
    final uri = node.uri.stringValue;
    if (uri != null) imports.add(uri);
  }

  @override
  void visitVariableDeclaration(VariableDeclaration node) {
    super.visitVariableDeclaration(node);
    _variables++;

    final varName = node.name.toString();
    final analysis = variableAnalyzer.analyze(varName);
    if (analysis.isSensitive && analysis.confidenceScore > 0.5) {
      sensitiveVariables[varName] = analysis.dataType;
    }
  }

  @override
  void visitMethodInvocation(MethodInvocation node) {
    _methods++;
    final methodName = node.methodName.name;
    final targetType = node.target?.toString() ?? '';
    final fullInvocation = '$targetType.$methodName';

    // Check each rule
    for (final rule in rules.allRules) {
      // Check required imports
      if (rule.requiresImport.isNotEmpty) {
        final hasImport = rule.requiresImport.any((req) => imports.contains(req));
        if (!hasImport) continue;
      }

      // Check if method matches any pattern
      for (final pattern in rule.patterns) {
        if (methodName.contains(pattern) || fullInvocation.contains(pattern)) {
          if (_isSensitiveStorageOperation(node, rule)) {
            _emit(node, rule.checkKey);
            break;
          }
        }
      }
    }

    super.visitMethodInvocation(node);
  }

  @override
  void visitInstanceCreationExpression(InstanceCreationExpression node) {
    _instances++;
    final typeName = node.constructorName.type.toString();

    if (typeName.contains('File')) {
      final rule = rules.ruleFor('file_storage');
      if (rule != null && _hasSensitiveArguments(node.argumentList)) {
        _emit(node, 'file_storage');
      }
    }

    super.visitInstanceCreationExpression(node);
  }

  @override
  void visitSimpleStringLiteral(SimpleStringLiteral node) {
    _strings++;
    final value = node.value.toLowerCase();

    final sensitiveKeywords = ['password', 'token', 'api_key', 'secret', 'auth', 'credential'];
    if (sensitiveKeywords.any((kw) => value.contains(kw))) {
      if (_isStorageContext(node.parent)) {
        _emit(node, 'hardcoded_storage_keys');
      }
    }

    super.visitSimpleStringLiteral(node);
  }

  // ---- Detection helpers ----

  bool _isSensitiveStorageOperation(MethodInvocation node, IdsRule rule) {
    final checkKey = rule.checkKey;

    if (checkKey == 'shared_prefs') {
      final target = node.target?.toString() ?? '';
      if (target.contains('prefs') || target.contains('SharedPreferences')) {
        return _hasSensitiveArguments(node.argumentList);
      }
    }

    if (checkKey == 'file_storage') {
      if (node.methodName.name.contains('write')) {
        return _hasSensitiveArguments(node.argumentList);
      }
    }

    if (checkKey == 'sqlite_storage') {
      final m = node.methodName.name;
      if (m == 'insert' || m == 'rawInsert') {
        return _hasSensitiveArguments(node.argumentList);
      }
    }

    if (checkKey == 'external_storage') {
      if (node.methodName.name.contains('getExternalStorage')) return true;
    }

    if (checkKey == 'cache_storage') {
      final m = node.methodName.name;
      if (m.contains('getTemporaryDirectory') || m.contains('getApplicationSupportDirectory')) {
        return _hasSensitiveArguments(node.argumentList);
      }
    }

    if (checkKey == 'webview_storage') {
      final m = node.methodName.name;
      if (m == 'runJavascript' || m == 'evaluateJavascript') {
        return _hasWebStorageInJavaScript(node.argumentList);
      }
    }

    if (checkKey == 'insecure_serialization') {
      final m = node.methodName.name;
      if (m == 'jsonEncode' || m == 'toJson') {
        return _hasSensitiveArguments(node.argumentList);
      }
    }

    if (checkKey == 'logging_secrets') {
      final m = node.methodName.name;
      if (m == 'print' || m == 'debugPrint' || m == 'log') {
        return _hasSensitiveArguments(node.argumentList);
      }
    }

    if (checkKey == 'unprotected_backup') {
      final m = node.methodName.name;
      if (m.contains('backup') || m.contains('export') ||
          m.contains('share') || m.contains('copy')) {
        return _hasSensitiveArguments(node.argumentList);
      }
    }

    return false;
  }

  bool _hasWebStorageInJavaScript(ArgumentList? args) {
    if (args == null) return false;
    for (final arg in args.arguments) {
      final s = arg.toString();
      if (s.contains('localStorage') || s.contains('sessionStorage') || s.contains('document.cookie')) {
        return true;
      }
    }
    return false;
  }

  bool _hasSensitiveArguments(ArgumentList? args) {
    if (args == null) return false;
    final keywords = ['password', 'token', 'api', 'secret', 'auth', 'key', 'credential'];
    for (final arg in args.arguments) {
      final s = arg.toString().toLowerCase();
      if (keywords.any((kw) => s.contains(kw))) return true;
    }
    return false;
  }

  bool _isStorageContext(AstNode? node) {
    if (node == null) return false;
    AstNode? current = node;
    while (current != null) {
      if (current is MethodInvocation) {
        final m = current.methodName.name;
        final storageKeywords = [
          'setString', 'setInt', 'setBool', 'set',
          'write', 'save', 'store', 'put', 'insert', 'update'
        ];
        if (storageKeywords.any((kw) => m.contains(kw))) return true;
      }
      current = current.parent;
    }
    return false;
  }

  String _getStorageContext(String checkKey) {
    const map = {
      'shared_prefs': 'shared_prefs',
      'file_storage': 'file',
      'sqlite_storage': 'sqlite',
      'external_storage': 'external_storage',
      'cache_storage': 'cache',
      'webview_storage': 'webview',
      'insecure_serialization': 'serialization',
      'logging_secrets': 'log',
      'unprotected_backup': 'backup',
      'hardcoded_storage_keys': 'shared_prefs',
    };
    return map[checkKey] ?? 'unknown';
  }

  /// Emit an issue using the rules engine.
  void _emit(AstNode node, String checkKey) {
    final rule = rules.ruleFor(checkKey);
    if (rule == null) return;

    final loc = unit.lineInfo.getLocation(node.offset);

    // Determine data type via heuristic on the snippet
    final snippetEnd = (node.offset + node.length).clamp(0, sourceCode.length);
    final snippet = sourceCode.substring(node.offset, snippetEnd).substring(0, 80.clamp(0, snippetEnd - node.offset));
    final heuristic = variableAnalyzer.analyze(snippet.toLowerCase());

    String dataType = rule.dataTypes.isNotEmpty ? rule.dataTypes.first : 'GENERIC_SENSITIVE';
    if (heuristic.isSensitive && heuristic.confidenceScore > 0.6) {
      dataType = heuristic.dataType;
    }

    final storageCtx = _getStorageContext(checkKey);
    final riskLevel = severityClassifier.classify(
      dataType: dataType,
      storageType: storageCtx,
      isEncrypted: false,
      isPublicStorage: checkKey == 'external_storage',
    );

    final issue = Issue(
      filePath,
      rules.ruleId(checkKey),
      rules.message(checkKey),
      rules.severity(checkKey),
      loc.lineNumber,
      loc.columnNumber,
      functionName: null,
      complexity: null,
      nestingDepth: null,
      functionLoc: null,
      component: 'ids',
      riskLevel: riskLevel,
      dataType: dataType,
      storageContext: storageCtx,
    );
    issues.add(issue);
    stderr.writeln('[IDS] ${issue.ruleId} at ${issue.line}:${issue.column}');
  }

  void debugCounters() {
    stderr.writeln(
      '[IDS] counters: methods=$_methods strings=$_strings '
      'instances=$_instances variables=$_variables'
    );
  }
}