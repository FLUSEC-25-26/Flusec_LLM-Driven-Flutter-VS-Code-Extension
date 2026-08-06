// lib/net/network_visitor.dart
//
// AST visitor for Insecure Network Communication component.
//
// REFACTORED: All detection ALGORITHMS are preserved exactly from the original.
// Added new detection logic for network fallbacks (Try/Catch downgrades,
// kDebugMode leaks, Weak TLS fallbacks, and WebView Mixed Content).
//
// Rule IDs, messages, and severities come from NetworkRulesEngine
// (loaded from insecure_network_rules.json or defaults).

import 'dart:io';
import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';
import '../core/issue.dart';
import 'network_rules.dart';
import 'url_utils.dart';

class NetworkVisitor extends RecursiveAstVisitor<void> {
  final CompilationUnit unit;
  final String filePath;
  final NetworkRulesEngine rules;
  final List<Issue> issues = [];

  // DEBUG counters (kept from original)
  int _methodInvocations = 0, _stringLiterals = 0, _interpolations = 0;
  int _identifiers = 0,
      _assignments = 0,
      _prefixed = 0,
      _propAccess = 0,
      _news = 0;

  NetworkVisitor(this.unit, this.filePath, this.rules);

  @override
  void visitMethodInvocation(MethodInvocation node) {
    _methodInvocations++;
    final method = node.methodName.name.toLowerCase();
    final src = node.toSource();

    // --- HTTP method calls ---
    const httpOps = {
      'get',
      'post',
      'put',
      'delete',
      'head',
      'patch',
      'geturl',
      'openurl',
      'connect',
    };
    if (httpOps.contains(method)) {
      for (final arg in node.argumentList.arguments) {
        final url = _extractUrl(arg);
        if (_isInsecureHttpUrl(url)) {
          _emit(
            node,
            'http_url',
            context:
                'Insecure network call: "$url" uses HTTP. Prefer HTTPS endpoints.',
          );
          break;
        }
      }
    }

    // --- Uri.parse('http://...') / 'ws://...' ---
    if (src.contains('Uri.parse(')) {
      final parsed = UrlUtils.extractFirstStringArg(
        node.argumentList.arguments,
      );
      if (_isInsecureHttpUrl(parsed)) {
        _emit(node, 'http_url', context: 'Uri.parse uses HTTP. Prefer HTTPS.');
      }
      if (parsed != null && parsed.toLowerCase().startsWith('ws://')) {
        _emit(
          node,
          'websocket_insecure',
          context: 'WebSocket uses ws://. Prefer wss:// for TLS.',
        );
      }
    }

    // --- WebSocket.connect('ws://...') ---
    if (src.contains('WebSocket.connect(')) {
      final url = UrlUtils.extractFirstStringArg(node.argumentList.arguments);
      if (url != null && url.toLowerCase().startsWith('ws://')) {
        _emit(
          node,
          'websocket_insecure',
          context: 'Insecure WebSocket (ws://). Use wss://',
        );
      }
    }

    // --- gRPC ChannelCredentials.insecure() ---
    if (src.contains('ChannelCredentials.insecure(')) {
      _emit(
        node,
        'grpc_insecure',
        context:
            'Insecure gRPC channel credentials. Prefer secure credentials.',
      );
    }

    // --- WebView Mixed Content Fallback ---
    if (src.contains('MixedContentMode.alwaysAllow')) {
      _emit(
        node,
        'webview_mixed_content',
        context:
            'WebView fallback: MixedContentMode.alwaysAllow permits insecure HTTP content inside HTTPS pages.',
      );
    }

    super.visitMethodInvocation(node);
  }

  @override
  void visitSimpleStringLiteral(SimpleStringLiteral node) {
    _stringLiterals++;
    final v = node.value.toLowerCase();
    if (v.startsWith('http://') && _isInsecureHttpUrl(node.value)) {
      _emit(
        node,
        'http_url',
        context: 'String literal contains insecure HTTP URL.',
      );
    } else if (v.startsWith('ws://')) {
      _emit(
        node,
        'websocket_insecure',
        context: 'String literal contains insecure WebSocket URL (ws://).',
      );
    }
    super.visitSimpleStringLiteral(node);
  }

  @override
  void visitStringInterpolation(StringInterpolation node) {
    _interpolations++;
    for (final el in node.elements) {
      if (el is InterpolationString) {
        final v = el.value.trim().toLowerCase();
        if (v.startsWith('http://')) {
          _emit(
            node,
            'http_url',
            context: 'String interpolation contains insecure HTTP URL.',
          );
          break;
        } else if (v.startsWith('ws://')) {
          _emit(
            node,
            'websocket_insecure',
            context:
                'String interpolation contains insecure WebSocket URL (ws://).',
          );
          break;
        }
      }
    }
    super.visitStringInterpolation(node);
  }

  @override
  void visitSimpleIdentifier(SimpleIdentifier node) {
    _identifiers++;
    final name = node.name.toLowerCase();

    if (name == 'md5') {
      _emit(node, 'weak_hash_md5');
    }
    if (name == 'sha1') {
      _emit(node, 'weak_hash_sha1');
    }

    // Dio onHttpClientCreate
    if (name == 'onhttpclientcreate') {
      final namedExpr = _nearestNamed(node);
      if (namedExpr != null) {
        _emit(
          namedExpr,
          'dio_onhttpclientcreate',
          context: 'onHttpClientCreate callback may bypass TLS checks in Dio.',
        );
      } else if (_isInAssignmentLhs(node)) {
        _emit(
          node.parent ?? node,
          'dio_onhttpclientcreate',
          context: 'onHttpClientCreate assigned; may bypass TLS checks in Dio.',
        );
      }
    }

    super.visitSimpleIdentifier(node);
  }

  @override
  void visitPrefixedIdentifier(PrefixedIdentifier node) {
    _prefixed++;
    final prefix = node.prefix.name;
    final ident = node.identifier.name;

    if (prefix == 'HttpOverrides' && ident == 'global') {
      _emit(node, 'http_overrides_global');
    }
    if (prefix == 'ChannelCredentials' && ident == 'insecure') {
      _emit(node, 'grpc_insecure');
    }
    if (ident == 'badCertificateCallback') {
      _emit(node, 'insecure_tls_callback');
    }
    // WebView Mixed Content Fallback
    if (prefix == 'MixedContentMode' && ident == 'alwaysAllow') {
      _emit(
        node,
        'webview_mixed_content',
        context:
            'WebView fallback: MixedContentMode.alwaysAllow permits insecure HTTP content inside HTTPS pages.',
      );
    }

    super.visitPrefixedIdentifier(node);
  }

  @override
  void visitPropertyAccess(PropertyAccess node) {
    _propAccess++;
    if (node.propertyName.name == 'badCertificateCallback') {
      _emit(node, 'insecure_tls_callback');
    }
    // WebView Mixed Content Fallback
    if (node.toSource().contains('MixedContentMode.alwaysAllow')) {
      _emit(
        node,
        'webview_mixed_content',
        context:
            'WebView fallback: MixedContentMode.alwaysAllow permits insecure HTTP content inside HTTPS pages.',
      );
    }
    super.visitPropertyAccess(node);
  }

  @override
  void visitAssignmentExpression(AssignmentExpression node) {
    _assignments++;
    final lhs = node.leftHandSide;
    final rhs = node.rightHandSide;

    String? lhsName;
    if (lhs is SimpleIdentifier) lhsName = lhs.name;
    if (lhs is PropertyAccess) lhsName = lhs.propertyName.name;
    if (lhs is PrefixedIdentifier) lhsName = lhs.identifier.name;

    if ((lhsName ?? '').toLowerCase() == 'validatecertificate' &&
        rhs is BooleanLiteral &&
        rhs.value == false) {
      _emit(node, 'disabled_cert_validation');
    }
    if ((lhsName ?? '').toLowerCase() == 'badcertificatecallback') {
      _emit(
        node,
        'insecure_tls_callback',
        context:
            'badCertificateCallback assigned: disables TLS certificate validation.',
      );
    }

    // --- TLS Protocol Downgrade Fallback ---
    final lhsSource = node.leftHandSide.toSource();
    if (lhsSource.contains('minimumTlsProtocol')) {
      final rhsSource = node.rightHandSide.toSource().toLowerCase();
      if (rhsSource.contains('tls1_0') || rhsSource.contains('tls1_1')) {
        _emit(
          node,
          'weak_tls_fallback',
          context:
              'SecurityContext allows fallback to weak TLS protocol (TLS 1.0/1.1). Require TLS 1.2+.',
        );
      }
    }

    super.visitAssignmentExpression(node);
  }

  @override
  void visitInstanceCreationExpression(InstanceCreationExpression node) {
    _news++;
    final typeName = node.constructorName.type.toString();
    if (typeName == 'HttpClient') {
      _emit(node, 'http_client_usage');
    }
    super.visitInstanceCreationExpression(node);
  }

  // --- Logic-Based Downgrades (Try/Catch) Fallback ---
  @override
  void visitTryStatement(TryStatement node) {
    final tryBody = node.body.toSource().toLowerCase();

    // Check if the 'try' block attempts a secure HTTPS connection
    if (tryBody.contains('https://')) {
      for (final catchClause in node.catchClauses) {
        final catchBody = catchClause.toSource().toLowerCase();

        // If the 'catch' block falls back to HTTP, it's a downgrade!
        if (catchBody.contains('http://') && _isInsecureHttpUrl('http://')) {
          _emit(
            node,
            'try_catch_downgrade',
            context:
                'Protocol downgrade: try block uses HTTPS, but catch block falls back to insecure HTTP.',
          );
        }
      }
    }
    super.visitTryStatement(node);
  }

  // --- Environment Toggles (kDebugMode) Fallback ---
  @override
  void visitConditionalExpression(ConditionalExpression node) {
    final condition = node.condition.toSource();

    // Check if the condition relies on Flutter's kDebugMode
    if (condition.contains('kDebugMode')) {
      final thenExpr = node.thenExpression.toSource().toLowerCase();
      final elseExpr = node.elseExpression.toSource().toLowerCase();

      // If either branch results in an http:// string, flag it
      if (thenExpr.contains('http://') || elseExpr.contains('http://')) {
        _emit(
          node,
          'debug_mode_fallback',
          context:
              'Environment toggle (kDebugMode) allows fallback to plain HTTP.',
        );
      }
    }
    super.visitConditionalExpression(node);
  }

  // ---- helpers ----

  bool _isInsecureHttpUrl(String? url) {
    if (url == null) return false;
    final u = url.toLowerCase();
    if (!u.startsWith('http://')) return false;
    if (u.startsWith('http://localhost') || u.startsWith('http://127.0.0.1'))
      return false;
    return true;
  }

  String? _extractUrl(Expression expr) {
    if (expr is SimpleStringLiteral) return expr.value;
    if (expr is StringInterpolation) {
      for (final el in expr.elements) {
        if (el is InterpolationString) {
          final v = el.value.trim();
          if (v.isNotEmpty) return v;
        }
      }
    }
    if (expr is MethodInvocation && expr.toSource().contains('Uri.parse(')) {
      return UrlUtils.extractFirstStringArg(expr.argumentList.arguments);
    }
    if (expr is Identifier) return _resolveStringFromIdentifier(expr);
    return null;
  }

  String? _resolveStringFromIdentifier(Identifier id) {
    final name = id.name;
    AstNode? scope = id;

    while (scope != null) {
      if (scope is Block) {
        for (final stmt in scope.statements) {
          if (stmt is VariableDeclarationStatement) {
            for (final v in stmt.variables.variables) {
              if (v.name.lexeme == name && v.initializer != null) {
                final val = _extractUrl(v.initializer!);
                if (val != null) return val;
              }
            }
          }
        }
      }
      scope = scope.parent;
    }

    final cu = unit;
    for (final decl in cu.declarations) {
      if (decl is TopLevelVariableDeclaration) {
        for (final v in decl.variables.variables) {
          if (v.name.lexeme == name && v.initializer != null) {
            final val = _extractUrl(v.initializer!);
            if (val != null) return val;
          }
        }
      }
    }
    return null;
  }

  bool _isInAssignmentLhs(SimpleIdentifier id) {
    final p = id.parent;
    if (p is AssignmentExpression) {
      final lhs = p.leftHandSide;
      if (lhs is SimpleIdentifier)
        return lhs.name.toLowerCase() == id.name.toLowerCase();
      if (lhs is PropertyAccess)
        return lhs.propertyName.name.toLowerCase() == id.name.toLowerCase();
      if (lhs is PrefixedIdentifier)
        return lhs.identifier.name.toLowerCase() == id.name.toLowerCase();
    }
    if (p is PropertyAccess && p.parent is AssignmentExpression) {
      final lhs = (p.parent as AssignmentExpression).leftHandSide;
      if (lhs is PropertyAccess) {
        return lhs.propertyName.name.toLowerCase() == id.name.toLowerCase();
      }
    }
    return false;
  }

  NamedExpression? _nearestNamed(SimpleIdentifier id) {
    AstNode? cur = id.parent;
    while (cur != null) {
      if (cur is NamedExpression) return cur;
      cur = cur.parent;
    }
    return null;
  }

  /// Emit an issue using the rules engine.
  /// [checkKey] maps to a rule in NetworkRulesEngine.
  /// [context] is an optional specific message override for this detection site.
  void _emit(AstNode node, String checkKey, {String? context}) {
    final rule = rules.ruleFor(checkKey);
    if (rule == null) return; // rule disabled or not found → skip

    final loc = unit.lineInfo.getLocation(node.offset);
    final msg = context ?? rules.message(checkKey);

    final issue = Issue(
      filePath,
      rules.ruleId(checkKey),
      msg,
      rules.severity(checkKey),
      loc.lineNumber,
      loc.columnNumber,
      functionName: null,
      complexity: null,
      nestingDepth: null,
      functionLoc: null,
      component: 'net',
    );
    issues.add(issue);
    stderr.writeln('[NET] ${issue.ruleId} at ${issue.line}:${issue.column}');
  }

  void debugCounters() {
    stderr.writeln(
      '[NET] counters: methods=$_methodInvocations strings=$_stringLiterals '
      'interps=$_interpolations idents=$_identifiers assigns=$_assignments '
      'prefixed=$_prefixed props=$_propAccess news=$_news',
    );
  }
}
