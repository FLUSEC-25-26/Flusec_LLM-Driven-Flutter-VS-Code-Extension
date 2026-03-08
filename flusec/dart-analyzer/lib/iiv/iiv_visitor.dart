// lib/iiv/iiv_visitor.dart
//
// AST visitor for detecting insufficient input validation patterns.
//
// Refactored from the original IvdVisitor to:
// - Use IivRulesEngine (loaded from JSON via rule repo)
// - Emit shared Issue objects with component: 'iiv'
// - Integrate into the unified analyzer pipeline
//
// Detects:
// - SQL injection via string interpolation in rawQuery/rawInsert/rawDelete/rawUpdate
// - Command injection via Process.run / Process.start
// - Unsafe file uploads missing allowedExtensions filter
// - Deep link poisoning via getInitialLink / onLink / getInitialUri
// - Missing form validation (TextFormField without validator)

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

  IivVisitor(this.unit, this.filePath, this.rules);

  // ---- Helpers ----

  String? _getEnclosingFunctionName(AstNode node) {
    AstNode? current = node;
    while (current != null) {
      if (current is FunctionDeclaration) return current.name.lexeme;
      if (current is MethodDeclaration) return current.name.lexeme;
      current = current.parent;
    }
    return null;
  }

  // FIXED: Removed customMessage, now uses rule.description directly from JSON
  void _emit(AstNode node, IivRule rule) {
    final loc = unit.lineInfo.getLocation(node.offset);

    issues.add(
      Issue(
        filePath,
        rule.id,
        rule.description, // <-- Now strictly using the JSON rule description
        rule.severity,    // <-- Now strictly using the JSON rule severity
        loc.lineNumber,
        loc.columnNumber,
        functionName: _getEnclosingFunctionName(node),
        component: 'iiv',
      ),
    );

    stderr.writeln('[IIV] ${rule.id} at ${loc.lineNumber}:${loc.columnNumber}');
  }

  // ---- Visitors ----

  @override
  void visitMethodInvocation(MethodInvocation node) {
    final methodName = node.methodName.name;
    final rule = rules.ruleForFunction(methodName);

    if (rule != null) {
      final targetStr = node.target?.toString();

      // --- SQL Injection ---
      if (rule.checkKey == 'sql_injection') {
        if (node.argumentList.arguments.isNotEmpty) {
          final arg = node.argumentList.arguments.first;
          if (arg is StringInterpolation) {
            _emit(node, rule); // Hardcoded string removed!
          }
        }
      }

      // --- Command Injection ---
      else if (rule.checkKey == 'command_injection') {
        if (targetStr == 'Process' || targetStr == 'Platform') {
          _emit(node, rule); // Hardcoded string removed!
        }
      }

      // --- Unsafe File Upload ---
      else if (rule.checkKey == 'unsafe_file_upload') {
        bool hasFilter = node.argumentList.arguments.any(
          (arg) =>
              arg is NamedExpression &&
              arg.name.label.name == 'allowedExtensions',
        );
        if (!hasFilter) {
          _emit(node, rule); // Hardcoded string removed!
        }
      }

      // --- Deep Link Poisoning ---
      else if (rule.checkKey == 'deep_link_poisoning') {
        _emit(node, rule); // Hardcoded string removed!
      }
    }

    super.visitMethodInvocation(node);
  }

  @override
  void visitInstanceCreationExpression(InstanceCreationExpression node) {
    final typeName = node.constructorName.type.name2.lexeme;
    final rule = rules.ruleForFunction(typeName);

    // --- Missing Form Validation ---
    if (rule != null && rule.checkKey == 'missing_form_validation') {
      bool hasValidator = node.argumentList.arguments.any(
        (arg) => arg is NamedExpression && arg.name.label.name == 'validator',
      );
      if (!hasValidator) {
        _emit(node, rule); // Hardcoded string removed!
      }
    }

    super.visitInstanceCreationExpression(node);
  }

  void debugCounters() {
    stderr.writeln('[IIV] Found ${issues.length} input validation issue(s).');
  }
}