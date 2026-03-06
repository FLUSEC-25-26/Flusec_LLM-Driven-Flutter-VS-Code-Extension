// flusec/dart-analyzer/lib/ivd/ivd_visitor.dart

import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';
import '../core/issue.dart';

class IvdVisitor extends RecursiveAstVisitor<void> {
  final String filePath;
  final List<Map<String, dynamic>> rules;
  final List<Issue> issues = [];

  IvdVisitor(this.filePath, this.rules);

  Map<String, dynamic>? _getRuleForFunction(String functionName) {
    for (var rule in rules) {
      final targets = rule['targetFunctions'] as List?;
      if (targets != null && targets.contains(functionName)) {
        return rule;
      }
    }
    return null;
  }

  void _addIssue(AstNode node, Map<String, dynamic> rule, String customMsg) {
    final unit = node.root as CompilationUnit;
    final loc = unit.lineInfo.getLocation(node.offset);

    issues.add(
      Issue(
        filePath,
        rule['id'] ?? 'FLUSEC.IVD.GENERIC',
        customMsg,
        rule['severity'] ?? 'medium',
        loc.lineNumber,
        loc.columnNumber,
        functionName: _getEnclosingFunctionName(node),
      ),
    );
  }

  String? _getEnclosingFunctionName(AstNode node) {
    AstNode? current = node;
    while (current != null) {
      if (current is FunctionDeclaration) return current.name.lexeme;
      if (current is MethodDeclaration) return current.name.lexeme;
      current = current.parent;
    }
    return null;
  }

  @override
  void visitMethodInvocation(MethodInvocation node) {
    final methodName = node.methodName.name;
    final rule = _getRuleForFunction(methodName);

    if (rule != null) {
      final String ruleId = rule['id'] ?? '';
      final targetStr = node.target?.toString();

      // --- SQL Injection ---
      if (ruleId == 'FLUSEC.IVD.SQLI') {
        if (node.argumentList.arguments.isNotEmpty) {
          final arg = node.argumentList.arguments.first;
          if (arg is StringInterpolation) {
            _addIssue(
              node,
              rule,
              "Potential SQL Injection: Avoid string interpolation in $methodName.",
            );
          }
        }
      }
      // --- Command Injection (Robust Target Check) ---
      else if (ruleId == 'FLUSEC.IVD.CMD') {
        if (targetStr == 'Process' || targetStr == 'Platform') {
          _addIssue(
            node,
            rule,
            "Potential Command Injection: User input passed to $targetStr.$methodName.",
          );
        }
      }
      // --- Unsafe File Upload ---
      else if (ruleId == 'FLUSEC.IVD.FILE') {
        bool hasFilter = node.argumentList.arguments.any(
          (arg) =>
              arg is NamedExpression &&
              arg.name.label.name == 'allowedExtensions',
        );
        if (!hasFilter) {
          _addIssue(
            node,
            rule,
            "Unsafe File Upload: $methodName missing 'allowedExtensions' filter.",
          );
        }
      }
      // --- Deep Link Poisoning ---
      else if (ruleId == 'FLUSEC.IVD.DEEP') {
        _addIssue(
          node,
          rule,
          "Deep Link Poisoning: Ensure URI from $methodName is validated.",
        );
      }
    }
    super.visitMethodInvocation(node);
  }

  @override
  void visitInstanceCreationExpression(InstanceCreationExpression node) {
    final typeName = node.constructorName.type.name.lexeme;
    final rule = _getRuleForFunction(typeName);

    if (rule != null && rule['id'] == 'FLUSEC.IVD.FORM') {
      bool hasValidator = node.argumentList.arguments.any(
        (arg) => arg is NamedExpression && arg.name.label.name == 'validator',
      );
      if (!hasValidator) {
        _addIssue(
          node,
          rule,
          "Missing Form Validation: $typeName requires a 'validator' function.",
        );
      }
    }
    super.visitInstanceCreationExpression(node);
  }
}
