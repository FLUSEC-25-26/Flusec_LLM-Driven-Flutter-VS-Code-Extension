// lib/hsd/secret_visitor.dart
//
// AST visitor for the HSD module.
// It searches places where hardcoded string literals appear and asks RulesEngine
// if that literal looks like a secret.
//
// IMPORTANT: Original behavior is preserved, including:
// - ignoring insecure storage sinks by returning early in _maybeReport
// - scanning VariableDeclaration, AssignmentExpression, MapLiteralEntry,
//   ArgumentList, and ListLiteral
//
// NEW: After detecting a secret in a VariableDeclaration or AssignmentExpression,
// runs simplified taint analysis to track where the secret flows.

import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/token.dart';
import 'package:analyzer/dart/ast/visitor.dart';

import '../core/issue.dart';
import 'hardcoded_secrets_rules.dart';
import 'function_utils.dart';
import 'complexity.dart';
import 'taint_tracker.dart';

class SecretVisitor extends RecursiveAstVisitor<void> {
  final RulesEngine engine;
  final String raw;
  final String filePath;

  final List<Issue> issues = [];
  final Set<String> _seen = {};

  /// The parsed CompilationUnit — needed for taint tracking line resolution.
  CompilationUnit? _unit;

  SecretVisitor(this.engine, this.raw, this.filePath);

  /// Set the CompilationUnit after parsing. Must be called before visiting.
  void setUnit(CompilationUnit unit) {
    _unit = unit;
  }

  /// Produce a stable node "kind name" without "Impl" suffix.
  String _nodeKindName(AstNode node) {
    final rawName = node.runtimeType.toString();
    return rawName.endsWith('Impl')
        ? rawName.substring(0, rawName.length - 4)
        : rawName;
  }

  /// Walk up AST tree to detect if inside insecure storage sinks.
  /// NOTE: Current logic uses this as a FILTER (skip reporting inside these sinks).
  /// The IDS component handles reporting these sinks.
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

        const sp = {
          'setString',
          'setBool',
          'setInt',
          'setDouble',
          'setStringList',
        };
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

  /// Run taint tracking for a variable with the given name.
  /// Returns the flow steps as JSON-serializable maps, or null if no flows.
  List<Map<String, dynamic>>? _runTaintTracking(
    AstNode declarationNode,
    String variableName,
    int sourceLine,
  ) {
    if (_unit == null) return null;
    if (variableName.isEmpty) return null;

    try {
      final steps = trackTaintFlow(
        taintedVarName: variableName,
        declarationNode: declarationNode,
        unit: _unit!,
        sourceLine: sourceLine,
      );

      if (steps.isEmpty) return null;

      return steps.map((s) => s.toJson()).toList();
    } catch (e) {
      // Taint tracking is best-effort; don't fail the entire scan
      return null;
    }
  }

  /// Decide if a node/value should become an Issue.
  /// [taintVarName] is the variable name for taint tracking (only set for
  /// VariableDeclaration and AssignmentExpression).
  void _maybeReport(
    AstNode node,
    String? value,
    String contextName, {
    String? taintVarName,
  }) {
    if (value == null || value.isEmpty) return;

    // Preserving original behavior exactly:
    if (_isInsideInsecureStorageCall(node)) return;

    final nodeKind = _nodeKindName(node);
    final hit = engine.detect(value, contextName, nodeKind);
    if (hit == null) return;

    final loc = _nodeLocation(node);
    final key = '$filePath:${loc.$1}:${loc.$2}:${hit.ruleId}';

    if (_seen.add(key)) {
      // Compute enclosing function name & metrics
      String? fnName;
      int? complexity;
      String? complexityLevel;

      // Numeric metrics
      int? nestingDepth;
      int? functionLoc;

      // Human-readable levels
      String? nestingLevel;
      String? sizeLevel;

      final exec = FunctionUtils.enclosingExecutable(node);
      if (exec != null) {
        fnName = FunctionUtils.executableName(exec);

        // Treat "<anonymous>" as "no name" for the user-facing message
        if (fnName == '<anonymous>') {
          fnName = null;
        }

        // Numeric complexity score
        final score = Complexity.computeCyclomaticComplexity(exec);
        complexity = score;

        // Human-readable level (low / medium / high)
        complexityLevel = Complexity.levelFor(score);

        // Numeric nesting depth + size
        nestingDepth = Complexity.computeMaxNestingDepth(exec);
        functionLoc = Complexity.computeFunctionLoc(exec);

        // Human-readable levels
        if (nestingDepth != null) {
          nestingLevel = Complexity.nestingLevelFor(nestingDepth);
        }
        if (functionLoc != null) {
          sizeLevel = Complexity.sizeLevelFor(functionLoc);
        }
      }

      // Run taint tracking if we have a variable name
      List<Map<String, dynamic>>? taintFlow;
      if (taintVarName != null && taintVarName.isNotEmpty) {
        taintFlow = _runTaintTracking(node, taintVarName, loc.$1);
      }

      // Build a nice human-readable message
      final baseMessage = hit.message;
      final buffer = StringBuffer(baseMessage);

      // Add function name if we know it
      if (fnName != null && fnName.trim().isNotEmpty) {
        buffer.write(' in function ${fnName.trim()}');
      }

      // Collect labels
      final details = <String>[];
      if (complexityLevel != null) {
        details.add('complexity: $complexityLevel');
      }
      if (nestingLevel != null) {
        details.add('nesting: $nestingLevel');
      }
      if (sizeLevel != null) {
        details.add('size: $sizeLevel');
      }

      if (details.isNotEmpty) {
        buffer.write(' (Function ${details.join(', ')})');
      }

      // Add taint flow summary to message if flows were found
      if (taintFlow != null && taintFlow.isNotEmpty) {
        final flowCount = taintFlow.length;
        // Collect unique sink types
        final sinkTypes = taintFlow
            .map((s) => s['type'] as String)
            .toSet()
            .toList();
        buffer.write(' [Flows to $flowCount sink(s): ${sinkTypes.join(", ")}]');
      }

      final annotatedMessage = buffer.toString();

      issues.add(
        Issue(
          filePath,
          hit.ruleId,
          annotatedMessage,
          hit.severity,
          loc.$1,
          loc.$2,
          functionName: fnName,
          complexity: complexity,
          nestingDepth: nestingDepth,
          functionLoc: functionLoc,
          secretType: hit.secretType,
          taintFlow: taintFlow,
        ),
      );
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
  // Visit points (scan coverage)
  // ---------------------------

  @override
  void visitVariableDeclaration(VariableDeclaration node) {
    final name = _nameFrom(node.name);
    final v = _stringFromExpression(node.initializer);
    // Pass variable name for taint tracking
    _maybeReport(node, v, name, taintVarName: name);
    super.visitVariableDeclaration(node);
  }

  @override
  void visitAssignmentExpression(AssignmentExpression node) {
    final leftName = _lhsName(node.leftHandSide);
    final v = _stringFromExpression(node.rightHandSide);
    // Pass LHS name for taint tracking
    _maybeReport(node, v, leftName, taintVarName: leftName);
    super.visitAssignmentExpression(node);
  }

  @override
  void visitMapLiteralEntry(MapLiteralEntry node) {
    final keyName = node.key.toSource();
    final v = _stringFromExpression(node.value);
    // No taint tracking for map entries (value is inline, not a named variable)
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

      // No taint tracking for inline arguments (not assigned to a variable)
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
