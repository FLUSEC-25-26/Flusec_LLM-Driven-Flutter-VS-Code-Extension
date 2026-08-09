// lib/net/network_visitor.dart
//
// Context-aware AST visitor for FLUSEC Insecure Network Communication (NET).
//
// Refinement goals:
// - report actual insecure network behavior instead of API presence alone
// - avoid duplicate findings for the same HTTP/WebSocket endpoint
// - distinguish badCertificateCallback => true from => false
// - do not report HttpClient(), HttpOverrides.global, onHttpClientCreate,
//   MD5, or SHA-1 merely because they exist
// - keep coupling analysis separate from vulnerability detection

import 'dart:io';

import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';

import '../core/code_context.dart';
import '../core/issue.dart';
import 'network_rules.dart';

class NetworkVisitor extends RecursiveAstVisitor<void> {
  final CompilationUnit unit;
  final String filePath;
  final NetworkRulesEngine rules;
  final List<Issue> issues = [];

  final Set<String> _emitted = <String>{};

  // Debug counters retained because the analyzer already prints them.
  int _methodInvocations = 0;
  int _stringLiterals = 0;
  int _interpolations = 0;
  int _identifiers = 0;
  int _assignments = 0;
  int _prefixed = 0;
  int _propAccess = 0;
  int _news = 0;

  NetworkVisitor(this.unit, this.filePath, this.rules);

  // ---------------------------------------------------------------------------
  // Endpoint detection
  // ---------------------------------------------------------------------------

  @override
  void visitSimpleStringLiteral(SimpleStringLiteral node) {
    _stringLiterals++;

    final value = node.value.trim();

    if (_isInsecureHttpUrl(value)) {
      // A HTTPS -> HTTP fallback is reported by the stronger downgrade rule,
      // so do not emit a second generic HTTP finding for the same catch block.
      if (!_isInsideHttpsToHttpDowngradeCatch(node)) {
        _emit(
          node,
          'http_url',
          context:
              'Insecure HTTP endpoint: ${_redactedEndpoint(value)}. Use HTTPS for network communication.',
          evidence: {
            'type': 'cleartext_http',
            'url': _redactedEndpoint(value),
            'credentialsRedacted': _endpointContainedCredentials(value),
            'scheme': 'http',
          },
        );
      }
    } else if (_isInsecureWebSocketUrl(value)) {
      _emit(
        node,
        'websocket_insecure',
        context:
            'Insecure WebSocket endpoint: ${_redactedEndpoint(value)}. Use wss:// instead of ws://.',
        evidence: {
          'type': 'cleartext_websocket',
          'url': _redactedEndpoint(value),
          'credentialsRedacted': _endpointContainedCredentials(value),
          'scheme': 'ws',
        },
      );
    }

    super.visitSimpleStringLiteral(node);
  }

  @override
  void visitStringInterpolation(StringInterpolation node) {
    _interpolations++;

    final source = node.toSource();
    final lower = source.toLowerCase();

    if (_containsInterpolatedScheme(lower, 'http://') &&
        !_looksLikeLocalInterpolatedEndpoint(lower) &&
        !_isInsideHttpsToHttpDowngradeCatch(node)) {
      _emit(
        node,
        'http_url',
        context: 'String interpolation constructs an insecure HTTP endpoint. Use HTTPS.',
        confidenceOverride: 'medium',
        evidence: {
          'type': 'cleartext_http',
          'expressionKind': 'StringInterpolation',
          'scheme': 'http',
        },
      );
    } else if (_containsInterpolatedScheme(lower, 'ws://') &&
        !_looksLikeLocalInterpolatedEndpoint(lower)) {
      _emit(
        node,
        'websocket_insecure',
        context: 'String interpolation constructs an insecure WebSocket endpoint. Use wss://.',
        confidenceOverride: 'medium',
        evidence: {
          'type': 'cleartext_websocket',
          'expressionKind': 'StringInterpolation',
          'scheme': 'ws',
        },
      );
    }

    super.visitStringInterpolation(node);
  }

  // ---------------------------------------------------------------------------
  // Explicit insecure network APIs/configuration
  // ---------------------------------------------------------------------------

  @override
  void visitMethodInvocation(MethodInvocation node) {
    _methodInvocations++;
    final source = node.toSource();

    // gRPC explicitly requests a plaintext channel.
    if (source.contains('ChannelCredentials.insecure(')) {
      _emit(
        node,
        'grpc_insecure',
        context: 'gRPC channel uses ChannelCredentials.insecure(), so transport TLS is disabled.',
        evidence: {
          'type': 'insecure_grpc_credentials',
          'api': 'ChannelCredentials.insecure',
        },
      );
    }

    super.visitMethodInvocation(node);
  }

  @override
  void visitAssignmentExpression(AssignmentExpression node) {
    _assignments++;

    final lhsName = _assignmentTargetName(node.leftHandSide).toLowerCase();
    final rhs = node.rightHandSide;

    // badCertificateCallback is only a vulnerability when the callback is
    // clearly configured to accept every bad certificate.
    if (lhsName == 'badcertificatecallback' &&
        _callbackAlwaysAcceptsBadCertificate(rhs)) {
      _emit(
        node,
        'certificate_validation_bypass',
        context: 'badCertificateCallback unconditionally accepts invalid TLS certificates.',
        evidence: {
          'type': 'certificate_validation_bypass',
          'api': 'badCertificateCallback',
          'behavior': 'always_accept',
        },
      );
    }

    // Some libraries expose a direct validateCertificate switch.
    if (lhsName == 'validatecertificate' &&
        rhs is BooleanLiteral &&
        rhs.value == false) {
      _emit(
        node,
        'certificate_validation_bypass',
        context: 'validateCertificate is explicitly set to false, disabling certificate validation.',
        evidence: {
          'type': 'certificate_validation_bypass',
          'api': 'validateCertificate',
          'behavior': 'disabled',
        },
      );
    }

    // Explicit minimum TLS 1.0/1.1 configuration.
    final lhsSource = node.leftHandSide.toSource().toLowerCase();
    final rhsSource = rhs.toSource().toLowerCase();
    if (lhsSource.contains('minimumtlsprotocol') &&
        (rhsSource.contains('tls1_0') || rhsSource.contains('tls1_1'))) {
      _emit(
        node,
        'weak_tls_protocol',
        context: 'The minimum TLS protocol allows TLS 1.0/1.1. Require TLS 1.2 or newer.',
        evidence: {
          'type': 'weak_tls_protocol',
          'configuration': node.toSource(),
        },
      );
    }

    super.visitAssignmentExpression(node);
  }

  @override
  void visitPrefixedIdentifier(PrefixedIdentifier node) {
    _prefixed++;

    final prefix = node.prefix.name;
    final identifier = node.identifier.name;

    // Only the explicit mixed-content-enabling enum value is a finding.
    if (prefix == 'MixedContentMode' && identifier == 'alwaysAllow') {
      _emit(
        node,
        'webview_mixed_content',
        context: 'WebView mixed content is set to alwaysAllow, permitting HTTP resources inside HTTPS content.',
        evidence: {
          'type': 'webview_mixed_content',
          'configuration': 'MixedContentMode.alwaysAllow',
        },
      );
    }

    super.visitPrefixedIdentifier(node);
  }

  @override
  void visitPropertyAccess(PropertyAccess node) {
    _propAccess++;
    super.visitPropertyAccess(node);
  }

  @override
  void visitSimpleIdentifier(SimpleIdentifier node) {
    _identifiers++;

    // Intentionally no vulnerability detection here.
    // Generic identifier matches such as md5, sha1, onHttpClientCreate,
    // badCertificateCallback, or HttpOverrides.global created false positives.

    super.visitSimpleIdentifier(node);
  }

  @override
  void visitInstanceCreationExpression(InstanceCreationExpression node) {
    _news++;

    // HttpClient() creation by itself is not insecure. Security findings are
    // emitted only when the client is configured or used insecurely.

    super.visitInstanceCreationExpression(node);
  }

  // ---------------------------------------------------------------------------
  // Logic-based downgrade detection
  // ---------------------------------------------------------------------------

  @override
  void visitTryStatement(TryStatement node) {
    final trySource = node.body.toSource();

    if (_containsHttps(trySource)) {
      for (final catchClause in node.catchClauses) {
        final catchSource = catchClause.toSource();
        final insecureUrl = _firstExternalHttpUrl(catchSource);

        if (insecureUrl != null) {
          _emit(
            node,
            'https_http_downgrade',
            context:
              'HTTPS failure falls back to insecure HTTP endpoint ${_redactedEndpoint(insecureUrl)}.',
            evidence: {
              'type': 'protocol_downgrade',
              'secureScheme': 'https',
              'fallbackScheme': 'http',
              'fallbackUrl': _redactedEndpoint(insecureUrl),
              'credentialsRedacted': _endpointContainedCredentials(insecureUrl),
            },
          );
          break;
        }
      }
    }

    super.visitTryStatement(node);
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  bool _isSensitiveQueryName(String name) {
    final normalized = name.toLowerCase().replaceAll(RegExp(r'[^a-z0-9]+'), '_');
    const indicators = {
      'token',
      'access_token',
      'refresh_token',
      'api_key',
      'apikey',
      'key',
      'secret',
      'client_secret',
      'password',
      'passwd',
      'auth',
      'authorization',
      'credential',
      'credentials',
      'signature',
      'sig',
      'session',
      'jwt',
    };

    if (indicators.contains(normalized)) return true;
    return normalized.endsWith('_token') ||
        normalized.endsWith('_secret') ||
        normalized.endsWith('_password') ||
        normalized.endsWith('_key');
  }

  bool _endpointContainedCredentials(String raw) {
    final uri = Uri.tryParse(raw.trim());
    if (uri == null) return false;
    if (uri.userInfo.isNotEmpty) return true;
    return uri.queryParametersAll.keys.any(_isSensitiveQueryName);
  }

  String _redactedEndpoint(String raw) {
    final trimmed = raw.trim();
    final uri = Uri.tryParse(trimmed);
    if (uri == null || uri.scheme.isEmpty) return '[REDACTED_ENDPOINT]';

    final queryParameters = <String, dynamic>{};
    for (final entry in uri.queryParametersAll.entries) {
      if (_isSensitiveQueryName(entry.key)) {
        queryParameters[entry.key] = '[REDACTED]';
      } else if (entry.value.length == 1) {
        queryParameters[entry.key] = entry.value.single;
      } else {
        queryParameters[entry.key] = entry.value;
      }
    }

    try {
      final safe = Uri(
        scheme: uri.scheme,
        host: uri.host,
        port: uri.hasPort ? uri.port : null,
        path: uri.path,
        queryParameters: uri.hasQuery ? queryParameters : null,
        fragment: uri.fragment.isEmpty ? null : uri.fragment,
      );
      return safe.toString();
    } catch (_) {
      return '${uri.scheme}://${uri.host}${uri.path}';
    }
  }

  String _assignmentTargetName(Expression lhs) {
    if (lhs is SimpleIdentifier) return lhs.name;
    if (lhs is PropertyAccess) return lhs.propertyName.name;
    if (lhs is PrefixedIdentifier) return lhs.identifier.name;
    return lhs.toSource();
  }

  bool _callbackAlwaysAcceptsBadCertificate(Expression rhs) {
    if (rhs is! FunctionExpression) return false;

    final body = rhs.body;

    if (body is ExpressionFunctionBody) {
      final expression = body.expression;
      return expression is BooleanLiteral && expression.value == true;
    }

    if (body is BlockFunctionBody) {
      // Only accept a direct, unconditional `return true;` in the callback
      // body. A conditional return true may represent host/certificate pinning
      // or another deliberate validation policy, so FLUSEC does not label it
      // an automatic bypass.
      final directReturns = body.block.statements.whereType<ReturnStatement>().toList();
      if (directReturns.length != 1) return false;

      final expression = directReturns.single.expression;
      return expression is BooleanLiteral && expression.value == true;
    }

    return false;
  }

  bool _isInsecureHttpUrl(String? url) {
    if (url == null) return false;
    final trimmed = url.trim();
    if (!trimmed.toLowerCase().startsWith('http://')) return false;

    final uri = Uri.tryParse(trimmed);
    final host = uri?.host.toLowerCase() ?? '';

    // If parsing cannot determine a host, keep the finding because the source
    // still explicitly requests cleartext HTTP.
    if (host.isEmpty) return true;
    return !_isLocalDevelopmentHost(host);
  }

  bool _isInsecureWebSocketUrl(String? url) {
    if (url == null) return false;
    final trimmed = url.trim();
    if (!trimmed.toLowerCase().startsWith('ws://')) return false;

    final uri = Uri.tryParse(trimmed);
    final host = uri?.host.toLowerCase() ?? '';
    if (host.isEmpty) return true;
    return !_isLocalDevelopmentHost(host);
  }

  bool _isLocalDevelopmentHost(String host) {
    final normalized = host.toLowerCase();
    return normalized == 'localhost' ||
        normalized.endsWith('.localhost') ||
        normalized == '127.0.0.1' ||
        normalized == '::1' ||
        normalized == '0.0.0.0' ||
        normalized == '10.0.2.2';
  }

  bool _containsInterpolatedScheme(String source, String scheme) {
    return source.contains(scheme);
  }

  bool _looksLikeLocalInterpolatedEndpoint(String source) {
    final lower = source.toLowerCase();
    return lower.contains('://localhost') ||
        lower.contains('://127.0.0.1') ||
        lower.contains('://10.0.2.2') ||
        lower.contains('://0.0.0.0') ||
        lower.contains('://[::1]');
  }

  bool _containsHttps(String source) => source.toLowerCase().contains('https://');

  String? _firstExternalHttpUrl(String source) {
    final matches = RegExp(
      r'''http://[^\s'"\)\]\},;]+''',
      caseSensitive: false,
    ).allMatches(source);

    for (final match in matches) {
      final value = match.group(0);
      if (_isInsecureHttpUrl(value)) return value;
    }
    return null;
  }

  bool _isInsideHttpsToHttpDowngradeCatch(AstNode node) {
    AstNode? current = node.parent;
    CatchClause? catchClause;

    while (current != null) {
      if (current is CatchClause) {
        catchClause = current;
        break;
      }
      if (current is TryStatement) return false;
      current = current.parent;
    }

    if (catchClause == null) return false;

    current = catchClause.parent;
    while (current != null && current is! TryStatement) {
      current = current.parent;
    }

    if (current is! TryStatement) return false;

    return _containsHttps(current.body.toSource()) &&
        _firstExternalHttpUrl(catchClause.toSource()) != null;
  }

  void _emit(
    AstNode node,
    String checkKey, {
    String? context,
    String? confidenceOverride,
    Map<String, dynamic>? evidence,
  }) {
    final rule = rules.ruleFor(checkKey);
    if (rule == null) return;

    final location = unit.lineInfo.getLocation(node.offset);

    // Multiple AST visitors/nodes may describe the same source-line issue.
    // Keep one finding per rule per source line.
    final dedupKey = '$checkKey:${location.lineNumber}';
    if (!_emitted.add(dedupKey)) return;

    final codeContext = CodeContextAnalyzer.fromNode(node);
    Map<String, dynamic>? findingEvidence =
        evidence == null ? null : <String, dynamic>{...evidence};

    if (codeContext != null) {
      findingEvidence ??= <String, dynamic>{};
      findingEvidence['maintainabilityContext'] =
          codeContext.maintainabilityEvidence();
    }

    final issue = Issue(
      filePath,
      rule.id,
      context ?? rule.messageTemplate,
      flusecSecurityDiagnosticSeverity,
      location.lineNumber,
      location.columnNumber,
      securitySeverity: rule.securitySeverity,
      confidence: confidenceOverride ?? rule.defaultConfidence,
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
