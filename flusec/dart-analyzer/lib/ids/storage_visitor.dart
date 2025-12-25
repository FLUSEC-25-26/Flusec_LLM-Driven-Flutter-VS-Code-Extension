// lib/ids/storage_visitor.dart
//
// AST visitor for detecting insecure data storage patterns

import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';

import '../core/issue.dart';
import 'insecure_storage_rules.dart';

class StorageVisitor extends RecursiveAstVisitor<void> {
  final InsecureStorageRulesEngine engine;
  final String sourceCode;
  final String filePath;
  final List<Issue> issues = [];

  StorageVisitor(this.engine, this.sourceCode, this.filePath);

  @override
  void visitMethodInvocation(MethodInvocation node) {
    super.visitMethodInvocation(node);

    final methodName = node.methodName.name;
    final targetType = node.target?.toString() ?? '';
    final fullInvocation = '$targetType.$methodName';

    // Check for insecure storage patterns
    for (final rule in engine.rules) {
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

    issues.add(Issue(
      filePath,
      rule.id,
      rule.description,
      rule.severity.toLowerCase(),
      line,
      column,
    ));
  }
}
