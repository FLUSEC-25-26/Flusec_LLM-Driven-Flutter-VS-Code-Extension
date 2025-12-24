
// lib/net/network_visitor.dart
import 'dart:io';
import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart'; // REQUIRED
import 'package:dart_analyzer/core/issue.dart';
import 'url_utils.dart';

class NetworkVisitor extends RecursiveAstVisitor<void> {
  final CompilationUnit unit;
  final String filePath;
  final List<Issue> issues = [];

  // DEBUG counters
  int _methodInvocations = 0, _stringLiterals = 0, _interpolations = 0;
  int _identifiers = 0, _assignments = 0, _prefixed = 0, _propAccess = 0, _news = 0;

  NetworkVisitor(this.unit, this.filePath);

  @override
  void visitMethodInvocation(MethodInvocation node) {
    _methodInvocations++;
    final method = node.methodName.name.toLowerCase();
    final src = node.toSource(); // robust across analyzer versions

    const httpOps = {'get','post','put','delete','head','patch','geturl','openurl','connect'};
    if (httpOps.contains(method)) {
      for (final arg in node.argumentList.arguments) {
        final url = _extractUrl(arg);
        if (_isInsecureHttpUrl(url)) {
          _emit(node, 'FLUSEC.NETWORK.HTTP_URL',
                'Insecure network call: "$url" uses HTTP. Prefer HTTPS endpoints.');
          break;
        }
      }
    }

    // Uri.parse('http://...') / 'ws://...'
    if (src.contains('Uri.parse(')) {
      final parsed = UrlUtils.extractFirstStringArg(node.argumentList.arguments);
      if (_isInsecureHttpUrl(parsed)) {
        _emit(node, 'FLUSEC.NETWORK.HTTP_URL', 'Uri.parse uses HTTP. Prefer HTTPS.');
      }
      if (parsed != null && parsed.toLowerCase().startsWith('ws://')) {
        _emit(node, 'FLUSEC.NETWORK.WEBSOCKET_INSECURE',
              'WebSocket uses ws://. Prefer wss:// for TLS.');
      }
    }

    // WebSocket.connect('ws://...')
    if (src.contains('WebSocket.connect(')) {
      final url = UrlUtils.extractFirstStringArg(node.argumentList.arguments);
      if (url != null && url.toLowerCase().startsWith('ws://')) {
        _emit(node, 'FLUSEC.NETWORK.WEBSOCKET_INSECURE',
              'Insecure WebSocket (ws://). Use wss://');
      }
    }

    // gRPC ChannelCredentials.insecure()
    if (src.contains('ChannelCredentials.insecure(')) {
      _emit(node, 'FLUSEC.NETWORK.GRPC_INSECURE_CREDENTIALS',
            'Insecure gRPC channel credentials. Prefer secure credentials.');
    }

    super.visitMethodInvocation(node);
  }

  @override
  void visitSimpleStringLiteral(SimpleStringLiteral node) {
    _stringLiterals++;
    final v = node.value.toLowerCase();
    if (v.startsWith('http://')) {
      _emit(node, 'FLUSEC.NETWORK.HTTP_URL', 'String literal contains insecure HTTP URL.');
    } else if (v.startsWith('ws://')) {
      _emit(node, 'FLUSEC.NETWORK.WEBSOCKET_INSECURE',
            'String literal contains insecure WebSocket URL (ws://).');
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
          _emit(node, 'FLUSEC.NETWORK.HTTP_URL',
                'String interpolation contains insecure HTTP URL.');
          break;
        } else if (v.startsWith('ws://')) {
          _emit(node, 'FLUSEC.NETWORK.WEBSOCKET_INSECURE',
                'String interpolation contains insecure WebSocket URL (ws://).');
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
      _emit(node, 'FLUSEC.NETWORK.WEAK_HASH_MD5', 'Use of MD5 hash detected.');
    }
    if (name == 'sha1') {
      _emit(node, 'FLUSEC.NETWORK.WEAK_HASH_SHA1', 'Use of SHA-1 hash detected.');
    }

    // Dio onHttpClientCreate (named parameter or assignment)
    if (name == 'onhttpclientcreate') {
      final namedExpr = _nearestNamed(node);
      if (namedExpr != null) {
        _emit(namedExpr, 'FLUSEC.NETWORK.DIO_ONHTTPCLIENTCREATE',
              'onHttpClientCreate callback may bypass TLS checks in Dio.');
      } else if (_isInAssignmentLhs(node)) {
        _emit(node.parent ?? node, 'FLUSEC.NETWORK.DIO_ONHTTPCLIENTCREATE',
              'onHttpClientCreate assigned; may bypass TLS checks in Dio.');
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
      _emit(node, 'FLUSEC.NETWORK.HTTP_OVERRIDES_GLOBAL',
            'HttpOverrides.global used: overrides network behavior globally.');
    }
    if (prefix == 'ChannelCredentials' && ident == 'insecure') {
      _emit(node, 'FLUSEC.NETWORK.GRPC_INSECURE_CREDENTIALS',
            'gRPC channel uses insecure credentials (no TLS).');
    }
    if (ident == 'badCertificateCallback') {
      _emit(node, 'FLUSEC.NETWORK.INSECURE_TLS_CALLBACK',
            'badCertificateCallback used. This disables certificate validation.');
    }

    super.visitPrefixedIdentifier(node);
  }

  @override
  void visitPropertyAccess(PropertyAccess node) {
    _propAccess++;
    if (node.propertyName.name == 'badCertificateCallback') {
      _emit(node, 'FLUSEC.NETWORK.INSECURE_TLS_CALLBACK',
            'badCertificateCallback used. This disables certificate validation.');
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
        rhs is BooleanLiteral && rhs.value == false) {
      _emit(node, 'FLUSEC.NETWORK.DISABLED_CERT_VALIDATION',
            'validateCertificate set to false: TLS certificate validation disabled.');
    }
    if ((lhsName ?? '').toLowerCase() == 'badcertificatecallback') {
      _emit(node, 'FLUSEC.NETWORK.INSECURE_TLS_CALLBACK',
            'badCertificateCallback assigned: disables TLS certificate validation.');
    }

    super.visitAssignmentExpression(node);
  }

  @override
  void visitInstanceCreationExpression(InstanceCreationExpression node) {
    _news++;
    final typeName = node.constructorName.type.toString();
    if (typeName == 'HttpClient') {
      _emit(node, 'FLUSEC.NETWORK.HTTP_URL',
            'HttpClient detected. Ensure secure TLS configuration and checks.');
    }
    super.visitInstanceCreationExpression(node);
  }

  // ---- helpers ----
  bool _isInsecureHttpUrl(String? url) {
    if (url == null) return false;
    final u = url.toLowerCase();
    if (!u.startsWith('http://')) return false;
    if (u.startsWith('http://localhost') || u.startsWith('http://127.0.0.1')) return false;
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
      if (lhs is SimpleIdentifier) return lhs.name.toLowerCase() == id.name.toLowerCase();
      if (lhs is PropertyAccess) return lhs.propertyName.name.toLowerCase() == id.name.toLowerCase();
      if (lhs is PrefixedIdentifier) return lhs.identifier.name.toLowerCase() == id.name.toLowerCase();
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

  void _emit(AstNode node, String ruleId, String message) {
    final loc = unit.lineInfo.getLocation(node.offset);
    final issue = Issue(
      ruleId,
      message,
      'warning', // force severity
      loc.lineNumber,
      loc.columnNumber,
      functionName: null,
      complexity: null,
    );
    issues.add(issue);
    stderr.writeln('[NET] $ruleId at ${issue.line}:${issue.column}'); // DEBUG
  }

  void debugCounters() {
    stderr.writeln(
      '[NET] counters: methods=$_methodInvocations strings=$_stringLiterals '
      'interps=$_interpolations idents=$_identifiers assigns=$_assignments '
      'prefixed=$_prefixed props=$_propAccess news=$_news'
    );
  }
}
