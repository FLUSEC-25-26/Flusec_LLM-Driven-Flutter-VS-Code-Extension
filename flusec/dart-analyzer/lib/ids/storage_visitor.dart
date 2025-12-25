// lib/ids/storage_visitor.dart
//
// AST visitor for detecting insecure data storage patterns

import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';

import '../core/issue.dart';
import 'insecure_storage_rules.dart';
import 'heuristic_analyzer.dart';

class StorageVisitor extends RecursiveAstVisitor<void> {
  final InsecureStorageRulesEngine engine;
  final String sourceCode;
  final String filePath;
  final List<Issue> issues = [];
  
  // Heuristic analysis
  final SensitiveVariableAnalyzer variableAnalyzer = SensitiveVariableAnalyzer();
  final SeverityClassifier severityClassifier = SeverityClassifier();
  
  // Track imports
  final Set<String> imports = {};
  
  // Track sensitive variables
  final Map<String, String> sensitiveVariables = {}; // variable name -> data type

  StorageVisitor(this.engine, this.sourceCode, this.filePath);
  
  @override
  void visitImportDirective(ImportDirective node) {
    super.visitImportDirective(node);
    final uri = node.uri.stringValue;
    if (uri != null) {
      imports.add(uri);
    }
  }
  
  @override
  void visitVariableDeclaration(VariableDeclaration node) {
    super.visitVariableDeclaration(node);
    
    // Analyze variable name for sensitivity
    final varName = node.name.toString();
    final analysis = variableAnalyzer.analyze(varName);
    
    if (analysis.isSensitive && analysis.confidenceScore > 0.5) {
      sensitiveVariables[varName] = analysis.dataType;
    }
  }

  @override
  void visitMethodInvocation(MethodInvocation node) {
    super.visitMethodInvocation(node);

    final methodName = node.methodName.name;
    final targetType = node.target?.toString() ?? '';
    final fullInvocation = '$targetType.$methodName';

    // Check for insecure storage patterns
    for (final rule in engine.rules) {
      // Check if required imports are present
      if (rule.requiresImport.isNotEmpty) {
        final hasRequiredImport = rule.requiresImport.any((req) => imports.contains(req));
        if (!hasRequiredImport) {
          continue; // Skip this rule if required import is missing
        }
      }
      
      for (final pattern in rule.patterns) {
        if (methodName.contains(pattern) || fullInvocation.contains(pattern)) {
          // Check if this is a sensitive operation
          if (_isSensitiveStorageOperation(node, rule)) {
            _reportIssue(node, rule);
            break;
          }
        }
      }
    }
  }

  @override
  void visitInstanceCreationExpression(InstanceCreationExpression node) {
    super.visitInstanceCreationExpression(node);

    final typeName = node.constructorName.type.toString();

    // Check for File creation with sensitive data
    if (typeName.contains('File')) {
      for (final rule in engine.rules) {
        if (rule.id == 'IDS-002') {
          // Check if arguments suggest sensitive data
          if (_hasSensitiveArguments(node.argumentList)) {
            _reportIssue(node, rule);
          }
        }
      }
    }
  }

  @override
  void visitSimpleStringLiteral(SimpleStringLiteral node) {
    super.visitSimpleStringLiteral(node);

    final value = node.value.toLowerCase();
    
    // Check for sensitive keys in storage operations
    final sensitiveKeywords = ['password', 'token', 'api_key', 'secret', 'auth', 'credential'];
    
    if (sensitiveKeywords.any((keyword) => value.contains(keyword))) {
      // Check if this is within a storage context
      final parent = node.parent;
      if (_isStorageContext(parent)) {
        final rule = engine.getRuleById('IDS-004');
        if (rule != null) {
          _reportIssue(node, rule);
        }
      }
    }
  }

  bool _isSensitiveStorageOperation(MethodInvocation node, InsecureStorageRule rule) {
    // For SharedPreferences
    if (rule.id == 'IDS-001') {
      final target = node.target?.toString() ?? '';
      if (target.contains('prefs') || target.contains('SharedPreferences')) {
        // Check if storing sensitive data
        return _hasSensitiveArguments(node.argumentList);
      }
    }

    // For File operations
    if (rule.id == 'IDS-002') {
      if (node.methodName.name.contains('write')) {
        return _hasSensitiveArguments(node.argumentList);
      }
    }

    // For SQLite operations
    if (rule.id == 'IDS-003') {
      final methodName = node.methodName.name;
      if (methodName == 'insert' || methodName == 'rawInsert') {
        return _hasSensitiveArguments(node.argumentList);
      }
    }

    // Rule 4: External Public Storage
    if (rule.id == 'IDS-004') {
      final methodName = node.methodName.name;
      if (methodName.contains('getExternalStorage')) {
        return true; // Always flag external storage usage
      }
    }

    // Rule 5: Cache/Temp Storage
    if (rule.id == 'IDS-005') {
      final methodName = node.methodName.name;
      if (methodName.contains('getTemporaryDirectory') || 
          methodName.contains('getApplicationSupportDirectory')) {
        return _hasSensitiveArguments(node.argumentList);
      }
    }

    // Rule 6: WebView LocalStorage
    if (rule.id == 'IDS-006') {
      final methodName = node.methodName.name;
      if (methodName == 'runJavascript' || methodName == 'evaluateJavascript') {
        // Check if JavaScript contains localStorage/sessionStorage
        return _hasWebStorageInJavaScript(node.argumentList);
      }
    }

    // Rule 7: Insecure Serialization
    if (rule.id == 'IDS-007') {
      final methodName = node.methodName.name;
      if (methodName == 'jsonEncode' || methodName == 'toJson') {
        return _hasSensitiveArguments(node.argumentList);
      }
    }

    // Rule 8: Logging Secrets
    if (rule.id == 'IDS-008') {
      final methodName = node.methodName.name;
      if (methodName == 'print' || methodName == 'debugPrint' || methodName == 'log') {
        return _hasSensitiveArguments(node.argumentList);
      }
    }

    // Rule 9: Unprotected Backup
    if (rule.id == 'IDS-009') {
      final methodName = node.methodName.name;
      if (methodName.contains('backup') || methodName.contains('export') || 
          methodName.contains('share') || methodName.contains('copy')) {
        return _hasSensitiveArguments(node.argumentList);
      }
    }

    return false;
  }
  
  bool _hasWebStorageInJavaScript(ArgumentList? args) {
    if (args == null) return false;
    
    for (final arg in args.arguments) {
      final argString = arg.toString();
      if (argString.contains('localStorage') || 
          argString.contains('sessionStorage') ||
          argString.contains('document.cookie')) {
        return true;
      }
    }
    return false;
  }

  bool _hasSensitiveArguments(ArgumentList? args) {
    if (args == null) return false;

    final sensitiveKeywords = ['password', 'token', 'api', 'secret', 'auth', 'key', 'credential'];
    
    for (final arg in args.arguments) {
      final argString = arg.toString().toLowerCase();
      if (sensitiveKeywords.any((keyword) => argString.contains(keyword))) {
        return true;
      }
    }

    return false;
  }

  bool _isStorageContext(AstNode? node) {
    if (node == null) return false;

    // Check if we're in a storage-related method call
    AstNode? current = node;
    while (current != null) {
      if (current is MethodInvocation) {
        final methodName = current.methodName.name;
        final storageMethodsKeywords = [
          'setString', 'setInt', 'setBool', 'set',
          'write', 'save', 'store', 'put',
          'insert', 'update'
        ];
        
        if (storageMethodsKeywords.any((keyword) => methodName.contains(keyword))) {
          return true;
        }
      }
      current = current.parent;
    }

    return false;
  }

  void _reportIssue(AstNode node, InsecureStorageRule rule) {
    final offset = node.offset;
    final length = node.length;
    final snippet = sourceCode.substring(offset, offset + length.clamp(0, 80));

    // Get line and column info
    final lines = sourceCode.substring(0, offset).split('\n');
    final line = lines.length;
    final column = lines.last.length + 1;
    
    // Determine storage context
    String storageContext = _getStorageContext(rule.id);
    
    // Determine data type from rule or heuristic analysis
    String? dataType;
    if (rule.dataTypes.isNotEmpty) {
      dataType = rule.dataTypes.first;
    }
    
    // Try to refine data type using heuristic analysis
    final snippetLower = snippet.toLowerCase();
    final heuristicResult = variableAnalyzer.analyze(snippetLower);
    if (heuristicResult.isSensitive && heuristicResult.confidenceScore > 0.6) {
      dataType = heuristicResult.dataType;
    }
    
    // Classify severity based on context
    final riskLevel = severityClassifier.classify(
      dataType: dataType ?? 'GENERIC_SENSITIVE',
      storageType: storageContext,
      isEncrypted: false, // We're detecting unencrypted storage
      isPublicStorage: rule.id == 'IDS-004', // External storage
    );

    issues.add(Issue(
      filePath,
      rule.id,
      rule.description,
      rule.severity.toLowerCase(),
      line,
      column,
      dataType: dataType,
      riskLevel: riskLevel,
      storageContext: storageContext,
      recommendation: rule.remediation,
    ));
  }
  
  String _getStorageContext(String ruleId) {
    switch (ruleId) {
      case 'IDS-001':
        return 'shared_prefs';
      case 'IDS-002':
        return 'file';
      case 'IDS-003':
        return 'sqlite';
      case 'IDS-004':
        return 'external_storage';
      case 'IDS-005':
        return 'cache';
      case 'IDS-006':
        return 'webview';
      case 'IDS-007':
        return 'serialization';
      case 'IDS-008':
        return 'log';
      case 'IDS-009':
        return 'backup';
      default:
        return 'unknown';
    }
  }
}
