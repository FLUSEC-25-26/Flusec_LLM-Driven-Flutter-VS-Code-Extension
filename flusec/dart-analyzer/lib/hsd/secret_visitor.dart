// lib/hsd/secret_visitor.dart
//
// AST visitor for your HSD module.
// It searches places where hardcoded string literals appear and asks RulesEngine
// if that literal looks like a secret.
//
// IMPORTANT: Your original behavior is preserved, including:
// - ignoring insecure storage sinks by returning early in _maybeReport
// - scanning VariableDeclaration, AssignmentExpression, MapLiteralEntry,
//   ArgumentList, and ListLiteral

import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/token.dart';
import 'package:analyzer/dart/ast/visitor.dart';

import '../core/issue.dart';
import 'hardcoded_secrets_rules.dart';
import 'function_utils.dart';
import 'complexity.dart';

class SecretVisitor extends RecursiveAstVisitor<void> {
  final RulesEngine engine;
  final String raw;
  final String filePath;

  final List<Issue> issues = [];
  final Set<String> _seen = {};

  SecretVisitor(this.engine, this.raw, this.filePath);

  /// Produce a stable node "kind name" without "Impl" suffix.
  String _nodeKindName(AstNode node) {
    final rawName = node.runtimeType.toString();
    return rawName.endsWith('Impl')
        ? rawName.substring(0, rawName.length - 4)
        : rawName;
  }

  /// Walk up AST tree to detect if inside insecure storage sinks.
  /// NOTE: Your current logic uses this as a FILTER (skip reporting inside these sinks).
  ///
  /// Other components idea (future):
  /// - insecure_storage module might REPORT these sinks instead of skipping.
  bool _isInsideInsecureStorageCall(AstNode node) {
    AstNode? current = node;

    String methodName(MethodInvocation mi) => mi.methodName.name;

    // Flexible typeName extractor (handles Identifier | Token)
    String typeName(dynamic id) {
      if (id is SimpleIdentifier) return id.name;
      if (id is PrefixedIdentifier) return id.identifier.name;
      if (id is Token) return id.lexeme;
      return id.toString();
    }

    while (current != null) {
      if (current is MethodInvocation) {
        final name = methodName(current);

        const sp = {'setString', 'setBool', 'setInt', 'setDouble', 'setStringList'};
        if (sp.contains(name)) return true;

        const fileWrites = {'writeAsString', 'writeAsBytes', 'openWrite'};
        if (fileWrites.contains(name)) return true;

        const sqlWrites = {'insert', 'rawInsert', 'execute', 'rawQuery'};
        if (sqlWrites.contains(name)) return true;

        const webview = {'runJavaScript', 'evaluateJavascript'};
        if (webview.contains(name)) return true;

        const externalDirs = {
          'getExternalStorageDirectory',
          'getExternalStorageDirectories',
        };
        if (externalDirs.contains(name)) return true;
      }

      if (current is InstanceCreationExpression) {
        final nameNode = current.constructorName.type.name;
        final tName = typeName(nameNode);
        if (tName == 'File' || tName == 'RandomAccessFile') return true;
      }

      final src = current.toSource();
      if (src.contains('/sdcard') || src.contains('/storage/')) return true;

      current = current.parent;
    }

    return false;
  }

  /// Decide if a node/value should become an Issue.
  void _maybeReport(AstNode node, String? value, String contextName) {
    if (value == null || value.isEmpty) return;

    // Preserving your original behavior exactly:
    if (_isInsideInsecureStorageCall(node)) return;

    final nodeKind = _nodeKindName(node);
    final hit = engine.detect(value, contextName, nodeKind);
    if (hit == null) return;

    final loc = _nodeLocation(node);
    final key = '$filePath:${loc.$1}:${loc.$2}:${hit.ruleId}';

    if (_seen.add(key)) {
      // Your feature: compute enclosing function name & complexity
      String? fnName;
      int? complexity;
      String? complexityLevel;

      final exec = FunctionUtils.enclosingExecutable(node);
      if (exec != null) {
        fnName = FunctionUtils.executableName(exec);

        // numeric complexity score
        final score = Complexity.computeCyclomaticComplexity(exec);
        complexity = score;

        // human-readable level (low / medium / high)
        complexityLevel = Complexity.levelFor(score);
      }

      // Optionally enrich the message with complexity level for better context.
      final baseMessage = hit.message;
      final annotatedMessage = complexityLevel == null
          ? baseMessage
          : '$baseMessage (Function complexity: $complexityLevel)';

      issues.add(Issue(
        filePath,
        hit.ruleId,
        annotatedMessage,
        hit.severity,
        loc.$1,
        loc.$2,
        functionName: fnName,
        complexity: complexity,
      ));
    }
  }

  /// Convert AST node offset into (line, column).
  (int, int) _nodeLocation(AstNode node) {
    final unit = node.root as CompilationUnit;
    final loc = unit.lineInfo.getLocation(node.offset);
    return (loc.lineNumber, loc.columnNumber);
  }

  /// Extract string value only if expression is a literal string.
  String? _stringFromExpression(Expression? e) =>
      e is StringLiteral ? e.stringValue : null;

  /// Generic name extractor for identifiers/tokens.
  String _nameFrom(Object? any) {
    if (any == null) return '';
    if (any is SimpleIdentifier) return any.name;
    if (any is PrefixedIdentifier) return any.identifier.name;
    if (any is Token) return any.lexeme;
    if (any is AstNode) return any.toSource();
    return any.toString();
  }

  /// Find a readable left-hand-side name for assignments.
  String _lhsName(Expression lhs) {
    if (lhs is SimpleIdentifier) return lhs.name;
    if (lhs is PrefixedIdentifier) return lhs.identifier.name;
    if (lhs is PropertyAccess) return lhs.propertyName.name;
    if (lhs is IndexExpression) {
      return lhs.target?.toSource() ?? lhs.toSource();
    }
    return lhs.toSource();
  }

  // ---------------------------
  // Visit points (your original scan coverage)
  // ---------------------------

  @override
  void visitVariableDeclaration(VariableDeclaration node) {
    final name = _nameFrom(node.name);
    final v = _stringFromExpression(node.initializer);
    _maybeReport(node, v, name);
    super.visitVariableDeclaration(node);
  }

  @override
  void visitAssignmentExpression(AssignmentExpression node) {
    final leftName = _lhsName(node.leftHandSide);
    final v = _stringFromExpression(node.rightHandSide);
    _maybeReport(node, v, leftName);
    super.visitAssignmentExpression(node);
  }

  @override
  void visitMapLiteralEntry(MapLiteralEntry node) {
    final keyName = node.key.toSource();
    final v = _stringFromExpression(node.value);
    _maybeReport(node, v, keyName);
    super.visitMapLiteralEntry(node);
  }

  @override
  void visitArgumentList(ArgumentList node) {
    for (final arg in node.arguments) {
      String context = '';
      String? value;

      if (arg is NamedExpression) {
        context = arg.name.label.name;
        value = _stringFromExpression(arg.expression);
      } else if (arg is Expression) {
        value = _stringFromExpression(arg);
      }

      _maybeReport(arg, value, context);
    }
    super.visitArgumentList(node);
  }

  @override
  void visitListLiteral(ListLiteral node) {
    var i = 0;
    for (final elem in node.elements) {
      if (elem is Expression) {
        final v = _stringFromExpression(elem);
        _maybeReport(elem, v, 'list[$i]');
      }
      i++;
    }
    super.visitListLiteral(node);
  }
}
