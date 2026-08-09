// lib/hsd/hardcoded_secrets_rules.dart
//
// Provider-aware and context-aware rule engine for FLUSEC Hardcoded Secrets
// Detection (HSD).
//
// Design goals:
// - Detect actual confidential credential material embedded in Dart source.
// - Do not report intentionally public client identifiers such as Firebase
//   client API keys, Stripe publishable keys, OAuth client IDs, Supabase
//   publishable/anon keys, or AWS access-key IDs by themselves.
// - Keep provider/structural signatures separate from contextual heuristics.
// - Treat entropy as supporting evidence, not as the definition of a secret.
// - Never place the full detected secret in finding metadata.

import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:crypto/crypto.dart';

class DynamicRule {
  final String id;
  final String name;
  final String pattern;
  final String description;
  final bool enabled;
  final String? messageTemplate;
  final RegExp regex;

  /// Logical secret type. Custom policy rules may use additional values.
  final String secretType;

  /// Optional provider name, for example Stripe or GitHub.
  final String? provider;

  /// Security impact. This is intentionally separate from VS Code diagnostic
  /// severity, which remains `warning` for current FLUSEC security findings.
  final String securitySeverity;

  /// Detection confidence: high | medium | low.
  final String confidence;

  final String category;
  final String remediation;
  final String cwe;

  DynamicRule({
    required this.id,
    required this.name,
    required this.pattern,
    required this.description,
    required this.enabled,
    required this.messageTemplate,
    required this.regex,
    required this.secretType,
    required this.provider,
    required this.securitySeverity,
    required this.confidence,
    required this.category,
    required this.remediation,
    required this.cwe,
  });

  static DynamicRule? tryFromJson(Map<String, dynamic> raw) {
    try {
      final enabled = (raw['enabled'] as bool?) ?? true;
      final pattern = (raw['pattern'] as String?)?.trim() ?? '';
      if (!enabled || pattern.isEmpty) return null;

      final id = (raw['id'] ?? '').toString().trim();
      final name = (raw['name'] ?? id).toString().trim();
      if (id.isEmpty) return null;

      final secretType =
          (raw['secretType'] ?? 'GENERIC_SECRET').toString().trim().toUpperCase();

      final providerText = raw['provider']?.toString().trim();
      final provider =
          providerText == null || providerText.isEmpty ? null : providerText;

      final securitySeverity =
          _normalizeSecuritySeverity(raw['securitySeverity']?.toString());
      final confidence = _normalizeConfidence(raw['confidence']?.toString());
      final category = (raw['category'] ?? 'vulnerability').toString().trim();
      final remediation = (raw['remediation'] ??
              'Remove the hardcoded credential from source code, rotate the exposed credential, and load it from an appropriate secret-management mechanism.')
          .toString()
          .trim();
      final cwe = (raw['cwe'] ?? _defaultCweForType(secretType))
          .toString()
          .trim();

      stderr.writeln(
        'HSD: compiled rule "$id" [type=$secretType, provider=${provider ?? "generic"}]',
      );

      return DynamicRule(
        id: id,
        name: name.isEmpty ? id : name,
        pattern: pattern,
        description: (raw['description'] ?? '').toString(),
        enabled: enabled,
        messageTemplate: raw['messageTemplate'] as String?,
        regex: RegExp(
          pattern,
          caseSensitive: true,
          dotAll: true,
          multiLine: true,
        ),
        secretType: secretType,
        provider: provider,
        securitySeverity: securitySeverity,
        confidence: confidence,
        category: category.isEmpty ? 'vulnerability' : category,
        remediation: remediation,
        cwe: cwe,
      );
    } catch (error) {
      stderr.writeln('HSD: ignored invalid dynamic rule: $error');
      return null;
    }
  }

  static String _normalizeSecuritySeverity(String? value) {
    switch (value?.trim().toLowerCase()) {
      case 'critical':
      case 'high':
      case 'medium':
      case 'low':
        return value!.trim().toLowerCase();
      default:
        return 'high';
    }
  }

  static String _normalizeConfidence(String? value) {
    switch (value?.trim().toLowerCase()) {
      case 'high':
      case 'medium':
      case 'low':
        return value!.trim().toLowerCase();
      default:
        return 'high';
    }
  }

  static String _defaultCweForType(String secretType) {
    final upper = secretType.toUpperCase();
    if (upper.contains('PRIVATE_KEY') ||
        upper.contains('CRYPTO') ||
        upper.contains('ENCRYPTION') ||
        upper.contains('SIGNING')) {
      return 'CWE-321';
    }
    return 'CWE-798';
  }
}

enum MatchSource { rule, heuristic, semantic }

class MatchHit {
  final MatchSource source;
  final String ruleId;
  final String message;

  /// Current FLUSEC diagnostics are presented as warnings in VS Code.
  final String severity;

  final String secretType;
  final String securitySeverity;
  final String confidence;
  final String category;
  final String remediation;
  final String cwe;
  final Map<String, dynamic> evidence;

  MatchHit({
    required this.source,
    required this.ruleId,
    required this.message,
    this.severity = 'warning',
    required this.secretType,
    required this.securitySeverity,
    required this.confidence,
    this.category = 'vulnerability',
    required this.remediation,
    required this.cwe,
    required this.evidence,
  });
}

class HeuristicsCfg {
  final bool enabled;
  final int minLength;
  final int minContextLength;
  final double minEntropy;

  /// Kept for backwards compatibility with existing web-policy JSON. The
  /// refined detector no longer performs unsafe raw substring matching such as
  /// `context.contains("auth")` or `context.contains("key")`.
  final List<String> sensitiveKeywords;

  /// Markers are applied to candidate VALUES, not to variable/file names.
  final List<String> placeholderMarkers;

  const HeuristicsCfg({
    required this.enabled,
    required this.minLength,
    required this.minContextLength,
    required this.minEntropy,
    required this.sensitiveKeywords,
    required this.placeholderMarkers,
  });

  factory HeuristicsCfg.disabled() => const HeuristicsCfg(
        enabled: false,
        minLength: 1 << 30,
        minContextLength: 1 << 30,
        minEntropy: double.infinity,
        sensitiveKeywords: <String>[],
        placeholderMarkers: <String>[],
      );

  factory HeuristicsCfg.fromJsonStrict(Map<String, dynamic> json) {
    final minLength = json['minLength'];
    final minEntropy = json['minEntropy'];

    if (minLength is! int) {
      throw const FormatException('heuristics.minLength must be an int');
    }
    if (minEntropy is! num) {
      throw const FormatException('heuristics.minEntropy must be a number');
    }

    final minContextLengthRaw = json['minContextLength'];
    final minContextLength =
        minContextLengthRaw is int ? minContextLengthRaw : 6;

    final sensitiveRaw = json['sensitiveKeywords'];
    final sensitive = sensitiveRaw is List
        ? sensitiveRaw.map((e) => e.toString()).toList()
        : <String>[];

    final placeholdersRaw =
        json['placeholderMarkers'] ?? json['benignMarkers'];
    final placeholders = placeholdersRaw is List
        ? placeholdersRaw.map((e) => e.toString()).toList()
        : <String>[];

    return HeuristicsCfg(
      enabled: true,
      minLength: minLength,
      minContextLength: minContextLength,
      minEntropy: minEntropy.toDouble(),
      sensitiveKeywords: sensitive,
      placeholderMarkers: placeholders,
    );
  }
}

class RulesEngine {
  final List<DynamicRule> _rules = [];
  HeuristicsCfg _cfg = HeuristicsCfg.disabled();

  static final RegExp _googleFirebaseClientKey =
      RegExp(r'^AIza[0-9A-Za-z\-_]{35}$');
  static final RegExp _awsAccessKeyId =
      RegExp(r'^(?:AKIA|ASIA)[0-9A-Z]{16}$');
  static final RegExp _stripePublishableKey =
      RegExp(r'^pk_(?:live|test)_[0-9A-Za-z]{12,}$');
  static final RegExp _supabasePublishableKey =
      RegExp(r'^sb_publishable_[A-Za-z0-9._-]{10,}$');
  static final RegExp _jwtLike = RegExp(
    r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
  );
  static final RegExp _awsSecretShape =
      RegExp(r'^[A-Za-z0-9/+=]{40}$');

  void loadDynamicRules(List<Map<String, dynamic>> raw) {
    _rules
      ..clear()
      ..addAll(raw.map(DynamicRule.tryFromJson).whereType<DynamicRule>());

    stderr.writeln('HSD: loaded ${_rules.length} active rule(s).');
  }

  void loadHeuristics(Map<String, dynamic> json) {
    if (json.isEmpty) {
      _cfg = HeuristicsCfg.disabled();
      stderr.writeln('HSD: heuristics config missing/empty; heuristics disabled.');
      return;
    }

    try {
      _cfg = HeuristicsCfg.fromJsonStrict(json);
      stderr.writeln('HSD: loaded refined heuristics configuration.');
    } catch (error) {
      _cfg = HeuristicsCfg.disabled();
      stderr.writeln('HSD: invalid heuristics config; heuristics disabled: $error');
    }
  }

  MatchHit? detect(String value, String contextName, String nodeKind) {
    final trimmed = value.trim();
    if (trimmed.isEmpty || trimmed.length < 3) return null;

    // 1) Suppress clear placeholders based on the VALUE only. Variable names
    // containing "test", "sample", etc. never suppress a real credential.
    if (_isPlaceholderValue(trimmed)) return null;

    // 2) Suppress explicit public/client-side identifiers before legacy or
    // remotely cached rules can misclassify them as secrets.
    if (_isExplicitPublicCredentialValue(trimmed)) return null;

    // 3) Inspect HTTP/HTTPS URLs for embedded credentials. Ordinary URLs are
    // explicitly ignored after this check.
    if (_looksHttpUrl(trimmed)) {
      final urlHit = _detectCredentialInHttpUrl(trimmed, contextName, nodeKind);
      if (urlHit != null) return urlHit;
      return null;
    }

    // 4) JWTs need semantic/contextual handling. A JWT shape by itself is not
    // enough to prove that the value is confidential.
    final jwtMatch = _jwtLike.firstMatch(trimmed);
    if (jwtMatch != null) {
      final jwtValue = jwtMatch.group(0)!;
      final claims = _decodeJwtPayload(jwtValue);
      final role = claims?['role']?.toString().toLowerCase();
      final issuer = claims?['iss']?.toString().toLowerCase() ?? '';
      final tokens = _contextTokens(contextName);

      final supabaseContext =
          tokens.contains('supabase') || tokens.contains('anon') ||
          (tokens.contains('service') && tokens.contains('role'));
      final looksSupabase = issuer.contains('supabase') || supabaseContext;

      if (looksSupabase && role == 'anon') {
        return null;
      }

      if (looksSupabase && role == 'service_role') {
        return _buildHit(
          source: MatchSource.semantic,
          ruleId: 'FLUSEC.HSD.011',
          message: _message(
            'Supabase service-role credential',
            nodeKind,
            contextName,
          ),
          secretType: 'SUPABASE_SERVICE_ROLE_KEY',
          provider: 'Supabase',
          securitySeverity: 'critical',
          confidence: 'high',
          remediation:
              'Remove the Supabase service-role credential from client/source code, rotate it, and keep privileged Supabase credentials only in a trusted backend or secret manager.',
          cwe: 'CWE-798',
          detectedSecret: jwtValue,
          contextName: contextName,
          detectionMethod: 'jwt_claim_classification',
          extraEvidence: {
            'jwtRole': 'service_role',
          },
        );
      }

      // Explicit public contexts such as OAuth clientId and Supabase anon key
      // are never upgraded to a secret simply because the value is JWT-shaped.
      if (_isPublicContext(contextName)) return null;

      if (_looksLikeAuthTokenContext(tokens)) {
        return _buildHit(
          source: MatchSource.semantic,
          ruleId: 'FLUSEC.HSD.015',
          message: _message(
            'Hardcoded authentication/session token',
            nodeKind,
            contextName,
          ),
          secretType: 'AUTH_TOKEN',
          securitySeverity: 'high',
          confidence: 'high',
          remediation:
              'Remove the hardcoded token, rotate/revoke it if it may be valid, and obtain tokens at runtime through the intended authentication flow or secure backend.',
          cwe: 'CWE-798',
          detectedSecret: jwtValue,
          contextName: contextName,
          detectionMethod: 'jwt_context',
        );
      }

      // A generic JWT-looking literal without sensitive context is not enough
      // for an HSD finding. This also neutralizes old broad JWT rule packs.
      return null;
    }

    // 5) Strong provider/structural rules. These are high-signal signatures
    // such as Stripe secret keys, GitHub PATs, private-key headers, etc.
    for (final rule in _rules) {
      final match = rule.regex.firstMatch(trimmed);
      if (match == null) continue;

      final matchedSecret = _secretMaterialForRule(
        rule: rule,
        fullValue: trimmed,
        match: match,
      );

      return _buildHit(
        source: MatchSource.rule,
        ruleId: rule.id,
        message: rule.messageTemplate ??
            _message(rule.name, nodeKind, contextName),
        secretType: rule.secretType,
        provider: rule.provider,
        securitySeverity: rule.securitySeverity,
        confidence: rule.confidence,
        category: rule.category,
        remediation: rule.remediation,
        cwe: rule.cwe,
        detectedSecret: matchedSecret,
        contextName: contextName,
        detectionMethod: 'provider_or_structural_pattern',
        extraEvidence: {
          if (rule.provider != null) 'provider': rule.provider,
          'ruleName': rule.name,
        },
      );
    }

    // 6) Context-only public identifiers should not fall into the generic
    // heuristic layer.
    if (_isPublicContext(contextName)) return null;

    // 7) Contextual heuristics. Disabled if policy heuristics are missing.
    if (!_cfg.enabled) return null;

    return _detectContextualSecret(trimmed, contextName, nodeKind);
  }

  MatchHit? _detectContextualSecret(
    String value,
    String contextName,
    String nodeKind,
  ) {
    final tokens = _contextTokens(contextName);
    final entropy = _entropy(value);

    // Passwords: a weak/low-entropy password is still a hardcoded credential.
    if (_looksLikePasswordContext(tokens) && value.length >= 4) {
      return _buildHit(
        source: MatchSource.heuristic,
        ruleId: 'FLUSEC.HSD.014',
        message: _message('Hardcoded password', nodeKind, contextName),
        secretType: 'PASSWORD',
        securitySeverity: 'high',
        confidence: 'high',
        remediation:
            'Remove the password from source code, rotate it if it may be valid, and retrieve it at runtime from an appropriate secret-management mechanism.',
        cwe: 'CWE-798',
        detectedSecret: value,
        contextName: contextName,
        detectionMethod: 'exact_password_context',
      );
    }

    if (_looksLikeAwsSecretContext(tokens) &&
        value.length >= _cfg.minContextLength) {
      final strongShape = _awsSecretShape.hasMatch(value);
      return _buildHit(
        source: MatchSource.heuristic,
        ruleId: 'FLUSEC.HSD.012',
        message: _message('AWS secret access credential', nodeKind, contextName),
        secretType: 'AWS_SECRET_ACCESS_KEY',
        provider: 'AWS',
        securitySeverity: 'high',
        confidence: strongShape ? 'high' : 'medium',
        remediation:
            'Remove the AWS secret access key from source code, deactivate/rotate the credential, and use workload identity, environment injection, or a secrets manager instead.',
        cwe: 'CWE-798',
        detectedSecret: value,
        contextName: contextName,
        detectionMethod: strongShape
            ? 'aws_context_plus_shape'
            : 'aws_secret_context',
        extraEvidence: {
          'awsSecretShape': strongShape,
        },
      );
    }

    if (_looksLikeOAuthClientSecretContext(tokens) &&
        value.length >= _cfg.minContextLength) {
      return _buildHit(
        source: MatchSource.heuristic,
        ruleId: 'FLUSEC.HSD.013',
        message: _message('OAuth client secret', nodeKind, contextName),
        secretType: 'OAUTH_CLIENT_SECRET',
        provider: 'OAuth',
        securitySeverity: 'high',
        confidence: 'high',
        remediation:
            'Remove the OAuth client secret from client/source code, rotate it if exposed, and keep confidential-client credentials in a trusted backend.',
        cwe: 'CWE-798',
        detectedSecret: value,
        contextName: contextName,
        detectionMethod: 'exact_client_secret_context',
      );
    }

    if (_looksLikeSupabaseServiceRoleContext(tokens) &&
        value.length >= _cfg.minContextLength) {
      return _buildHit(
        source: MatchSource.heuristic,
        ruleId: 'FLUSEC.HSD.011',
        message: _message(
          'Supabase service-role credential',
          nodeKind,
          contextName,
        ),
        secretType: 'SUPABASE_SERVICE_ROLE_KEY',
        provider: 'Supabase',
        securitySeverity: 'critical',
        confidence: 'high',
        remediation:
            'Remove the Supabase service-role credential from client/source code, rotate it, and keep privileged Supabase credentials only in a trusted backend or secret manager.',
        cwe: 'CWE-798',
        detectedSecret: value,
        contextName: contextName,
        detectionMethod: 'service_role_context',
      );
    }

    if (_looksLikeCryptoKeyContext(tokens) &&
        value.length >= _cfg.minContextLength) {
      final confidence = entropy >= _cfg.minEntropy ? 'high' : 'medium';
      return _buildHit(
        source: MatchSource.heuristic,
        ruleId: 'FLUSEC.HSD.016',
        message: _message('Hardcoded cryptographic key', nodeKind, contextName),
        secretType: 'CRYPTOGRAPHIC_KEY',
        securitySeverity: 'high',
        confidence: confidence,
        remediation:
            'Remove the cryptographic key from source code, rotate it if it has been used, and obtain key material from platform-backed or server-side key management.',
        cwe: 'CWE-321',
        detectedSecret: value,
        contextName: contextName,
        detectionMethod: 'cryptographic_key_context',
      );
    }

    if (_looksLikeAuthTokenContext(tokens) &&
        value.length >= _cfg.minContextLength) {
      final confidence = entropy >= _cfg.minEntropy ? 'high' : 'medium';
      return _buildHit(
        source: MatchSource.heuristic,
        ruleId: 'FLUSEC.HSD.015',
        message: _message(
          'Hardcoded authentication/session token',
          nodeKind,
          contextName,
        ),
        secretType: 'AUTH_TOKEN',
        securitySeverity: 'high',
        confidence: confidence,
        remediation:
            'Remove the token from source code, revoke/rotate it if necessary, and obtain session/access tokens dynamically through the intended authentication flow.',
        cwe: 'CWE-798',
        detectedSecret: value,
        contextName: contextName,
        detectionMethod: 'token_context',
      );
    }

    // Generic API keys/secrets require both precise context and value evidence.
    // This avoids broad false positives such as authorName -> "auth" or
    // keyboardShortcut -> "key".
    if (_looksLikeGenericSecretContext(tokens) &&
        value.length >= _cfg.minLength &&
        entropy >= _cfg.minEntropy) {
      return _buildHit(
        source: MatchSource.heuristic,
        ruleId: 'FLUSEC.HSD.018',
        message: _message(
          'Possible hardcoded credential',
          nodeKind,
          contextName,
        ),
        secretType: 'GENERIC_SECRET',
        securitySeverity: 'high',
        confidence: 'medium',
        remediation:
            'Verify whether this value is confidential. If it is a credential, remove it from source code, rotate it, and use an appropriate secret-management mechanism.',
        cwe: 'CWE-798',
        detectedSecret: value,
        contextName: contextName,
        detectionMethod: 'context_plus_entropy',
      );
    }

    return null;
  }

  MatchHit? _detectCredentialInHttpUrl(
    String value,
    String contextName,
    String nodeKind,
  ) {
    final uri = Uri.tryParse(value);
    if (uri == null) return null;

    // Basic/user-info credentials: https://user:password@example.com
    if (uri.userInfo.contains(':')) {
      final pieces = uri.userInfo.split(':');
      if (pieces.length >= 2) {
        final password = pieces.sublist(1).join(':');
        if (password.isNotEmpty && !_isPlaceholderValue(password)) {
          return _buildHit(
            source: MatchSource.semantic,
            ruleId: 'FLUSEC.HSD.017',
            message: _message(
              'Credential embedded in URL user-info',
              nodeKind,
              contextName,
            ),
            secretType: 'URL_CREDENTIAL',
            securitySeverity: 'high',
            confidence: 'high',
            remediation:
                'Remove credentials from the URL, rotate the credential, and pass authentication material through an appropriate runtime authentication mechanism.',
            cwe: 'CWE-798',
            detectedSecret: password,
            contextName: contextName,
            detectionMethod: 'url_userinfo',
          );
        }
      }
    }

    for (final entry in uri.queryParameters.entries) {
      final queryTokens = _contextTokens(entry.key);
      if (!_looksLikeSensitiveQueryParameter(queryTokens)) continue;

      final candidate = entry.value.trim();
      const minimumUrlCredentialLength = 6;
      if (candidate.length < minimumUrlCredentialLength ||
          _isPlaceholderValue(candidate) ||
          _isExplicitPublicCredentialValue(candidate) ||
          _isSupabaseAnonJwt(candidate, entry.key)) {
        continue;
      }

      final isGenericApiKey = queryTokens.contains('api') &&
          queryTokens.contains('key') &&
          !_looksLikePasswordContext(queryTokens) &&
          !_looksLikeOAuthClientSecretContext(queryTokens) &&
          !_looksLikeAuthTokenContext(queryTokens) &&
          !queryTokens.contains('secret') &&
          !queryTokens.contains('signature');

      // Generic api_key parameters can also be intentionally publishable.
      // Require value evidence and lower confidence rather than treating every
      // api_key query parameter as a definite confidential credential.
      final urlEntropyThreshold = _cfg.enabled ? _cfg.minEntropy : 3.3;
      if (isGenericApiKey && _entropy(candidate) < urlEntropyThreshold) {
        continue;
      }

      return _buildHit(
        source: MatchSource.semantic,
        ruleId: 'FLUSEC.HSD.017',
        message: _message(
          'Credential embedded in URL query parameter',
          nodeKind,
          contextName,
        ),
        secretType: 'URL_CREDENTIAL',
        securitySeverity: 'high',
        confidence: isGenericApiKey ? 'medium' : 'high',
        remediation:
            'Remove the credential from the URL, rotate it if it may be valid, and transmit authentication material using a secure runtime mechanism such as an authorization header.',
        cwe: 'CWE-798',
        detectedSecret: candidate,
        contextName: contextName,
        detectionMethod: 'url_query_parameter',
        extraEvidence: {
          'queryParameter': entry.key,
        },
      );
    }

    return null;
  }

  MatchHit _buildHit({
    required MatchSource source,
    required String ruleId,
    required String message,
    required String secretType,
    String? provider,
    required String securitySeverity,
    required String confidence,
    String category = 'vulnerability',
    required String remediation,
    required String cwe,
    required String detectedSecret,
    required String contextName,
    required String detectionMethod,
    Map<String, dynamic>? extraEvidence,
  }) {
    final entropy = _entropy(detectedSecret);

    return MatchHit(
      source: source,
      ruleId: ruleId,
      message: message,
      severity: 'warning',
      secretType: secretType,
      securitySeverity: securitySeverity,
      confidence: confidence,
      category: category,
      remediation: remediation,
      cwe: cwe,
      evidence: {
        'detectionMethod': detectionMethod,
        if (provider != null && provider.trim().isNotEmpty)
          'provider': provider.trim(),
        if (contextName.trim().isNotEmpty) 'context': contextName.trim(),
        'maskedValue': _maskSecret(detectedSecret),
        'secretFingerprint': _secretFingerprint(detectedSecret),
        'entropy': double.parse(entropy.toStringAsFixed(3)),
        'valueLength': detectedSecret.length,
        ...?extraEvidence,
      },
    );
  }

  String _message(String label, String nodeKind, String contextName) {
    final context = contextName.trim();
    return '$label hardcoded in $nodeKind${context.isNotEmpty ? ' in "$context"' : ''}';
  }

  bool _isExplicitPublicCredentialValue(String value) {
    final trimmed = value.trim();
    return _googleFirebaseClientKey.hasMatch(trimmed) ||
        _awsAccessKeyId.hasMatch(trimmed) ||
        _stripePublishableKey.hasMatch(trimmed) ||
        _supabasePublishableKey.hasMatch(trimmed);
  }

  bool _isPublicContext(String contextName) {
    final tokens = _contextTokens(contextName);

    if (tokens.contains('client') &&
        tokens.contains('id') &&
        !tokens.contains('secret')) {
      return true;
    }

    if (tokens.contains('publishable') && tokens.contains('key')) {
      return true;
    }

    if (tokens.contains('firebase') &&
        tokens.contains('api') &&
        tokens.contains('key')) {
      return true;
    }

    if (tokens.contains('google') &&
        tokens.contains('api') &&
        tokens.contains('key')) {
      return true;
    }

    if (tokens.contains('supabase') &&
        tokens.contains('anon') &&
        tokens.contains('key')) {
      return true;
    }

    if (tokens.contains('anon') && tokens.contains('key')) {
      return true;
    }

    if (tokens.contains('stripe') &&
        tokens.contains('publishable') &&
        tokens.contains('key')) {
      return true;
    }

    return false;
  }

  bool _isPlaceholderValue(String value) {
    final lower = value.trim().toLowerCase();
    if (lower.isEmpty) return true;

    if (lower.startsWith('flusec_marker_') ||
        lower.startsWith('flusec_rp_marker_')) {
      return true;
    }

    final normalized = lower.replaceAll(RegExp(r'[^a-z0-9]+'), '_');

    for (final marker in _cfg.placeholderMarkers) {
      final m = marker.toLowerCase().trim();
      if (m.isEmpty) continue;
      final markerNormalized = m.replaceAll(RegExp(r'[^a-z0-9]+'), '_');
      if (normalized.contains(markerNormalized)) return true;
    }

    const builtInMarkers = <String>[
      'changeme',
      'change_me',
      'replace_me',
      'placeholder',
      'your_api_key',
      'your_secret',
      'your_token',
      'your_password',
      'your_service_role_key',
      'service_role_key_here',
      'insert_secret_here',
      'not_a_real',
      'not_real',
      'example_key',
      'example_token',
      'example_secret',
      'dummy_key',
      'dummy_token',
      'dummy_secret',
      'fake_key',
      'fake_token',
      'fake_secret',
    ];

    if (builtInMarkers.any(normalized.contains)) return true;

    if (RegExp(r'^[xX0*_-]{6,}$').hasMatch(value.trim())) return true;
    if (RegExp(r'^<[^>]{2,}>$').hasMatch(value.trim())) return true;

    return false;
  }

  Set<String> _contextTokens(String contextName) {
    var text = contextName.trim();
    if (text.isEmpty) return <String>{};

    // camelCase / PascalCase -> words, then punctuation/underscores -> spaces.
    text = text.replaceAllMapped(
      RegExp(r'([a-z0-9])([A-Z])'),
      (m) => '${m.group(1)} ${m.group(2)}',
    );
    text = text.replaceAll(RegExp(r'[^A-Za-z0-9]+'), ' ');

    return text
        .toLowerCase()
        .split(RegExp(r'\s+'))
        .where((part) => part.isNotEmpty)
        .toSet();
  }

  bool _looksLikePasswordContext(Set<String> tokens) {
    return tokens.contains('password') ||
        tokens.contains('passwd') ||
        tokens.contains('pwd');
  }

  bool _looksLikeAwsSecretContext(Set<String> tokens) {
    final secretAccessKey = tokens.contains('secret') &&
        tokens.contains('access') &&
        tokens.contains('key');
    final awsSecretKey = tokens.contains('aws') &&
        tokens.contains('secret') &&
        tokens.contains('key');
    return secretAccessKey || awsSecretKey;
  }

  bool _looksLikeOAuthClientSecretContext(Set<String> tokens) {
    return tokens.contains('client') && tokens.contains('secret');
  }

  bool _looksLikeSupabaseServiceRoleContext(Set<String> tokens) {
    final explicitSupabaseRole = tokens.contains('supabase') &&
        tokens.contains('service') &&
        tokens.contains('role');
    final serviceRoleKey = tokens.contains('service') &&
        tokens.contains('role') &&
        tokens.contains('key');
    return explicitSupabaseRole || serviceRoleKey;
  }

  bool _looksLikeCryptoKeyContext(Set<String> tokens) {
    final key = tokens.contains('key');
    if (!key) return false;

    return tokens.contains('private') ||
        tokens.contains('encryption') ||
        tokens.contains('signing') ||
        tokens.contains('hmac') ||
        tokens.contains('aes');
  }

  bool _looksLikeAuthTokenContext(Set<String> tokens) {
    if (tokens.contains('authorization') || tokens.contains('bearer')) {
      return true;
    }

    if (!tokens.contains('token')) return false;

    if (tokens.length == 1) return true;

    return tokens.contains('access') ||
        tokens.contains('refresh') ||
        tokens.contains('session') ||
        tokens.contains('auth') ||
        tokens.contains('authentication') ||
        tokens.contains('bearer') ||
        tokens.contains('id') ||
        tokens.contains('api');
  }

  bool _looksLikeGenericSecretContext(Set<String> tokens) {
    if (tokens.contains('credential') || tokens.contains('credentials')) {
      return true;
    }

    if (tokens.contains('api') && tokens.contains('key')) return true;

    if (tokens.contains('secret')) {
      // Avoid common non-credential concepts such as secretQuestion.
      if (tokens.contains('question') ||
          tokens.contains('message') ||
          tokens.contains('label') ||
          tokens.contains('name') ||
          tokens.contains('text')) {
        return false;
      }
      return true;
    }

    return false;
  }

  bool _looksLikeSensitiveQueryParameter(Set<String> tokens) {
    if (_looksLikePasswordContext(tokens)) return true;
    if (_looksLikeOAuthClientSecretContext(tokens)) return true;
    if (_looksLikeAuthTokenContext(tokens)) return true;
    if (tokens.contains('secret')) return true;
    if (tokens.contains('signature')) return true;
    if (tokens.contains('api') && tokens.contains('key')) return true;
    return false;
  }

  bool _looksHttpUrl(String value) {
    final lower = value.toLowerCase();
    return lower.startsWith('http://') || lower.startsWith('https://');
  }

  bool _isSupabaseAnonJwt(String value, String contextName) {
    final match = _jwtLike.firstMatch(value.trim());
    if (match == null) return false;

    final claims = _decodeJwtPayload(match.group(0)!);
    final role = claims?['role']?.toString().toLowerCase();
    if (role != 'anon') return false;

    final issuer = claims?['iss']?.toString().toLowerCase() ?? '';
    final tokens = _contextTokens(contextName);
    final supabaseContext = tokens.contains('supabase') ||
        (tokens.contains('anon') && tokens.contains('key'));

    return issuer.contains('supabase') || supabaseContext;
  }

  Map<String, dynamic>? _decodeJwtPayload(String jwt) {
    try {
      final parts = jwt.split('.');
      if (parts.length != 3) return null;

      var payload = parts[1];
      final remainder = payload.length % 4;
      if (remainder != 0) {
        payload = payload.padRight(payload.length + (4 - remainder), '=');
      }

      final decoded = utf8.decode(base64Url.decode(payload));
      final parsed = jsonDecode(decoded);
      if (parsed is Map) {
        return parsed.map((key, value) => MapEntry(key.toString(), value));
      }
    } catch (_) {
      // A malformed JWT-looking value simply loses semantic classification.
    }
    return null;
  }

  String _secretMaterialForRule({
    required DynamicRule rule,
    required String fullValue,
    required RegExpMatch match,
  }) {
    if (rule.secretType == 'DATABASE_CREDENTIAL') {
      final uri = Uri.tryParse(fullValue);
      if (uri != null && uri.userInfo.contains(':')) {
        final pieces = uri.userInfo.split(':');
        if (pieces.length >= 2) {
          final password = pieces.sublist(1).join(':');
          if (password.isNotEmpty) return password;
        }
      }
    }

    return match.group(0) ?? fullValue;
  }

  String _maskSecret(String secret) {
    final value = secret.trim();
    if (value.isEmpty) return '••••';

    const visiblePrefixes = <String>[
      'sk_live_',
      'sk_test_',
      'rk_live_',
      'rk_test_',
      'ghp_',
      'gho_',
      'ghu_',
      'ghs_',
      'ghr_',
      'github_pat_',
      'glpat-',
      'gldt-',
      'glcbt-',
      'gloas-',
      'xoxb-',
      'xoxp-',
      'xapp-',
      'sb_secret_',
    ];

    for (final prefix in visiblePrefixes) {
      if (value.startsWith(prefix)) {
        final suffix = value.length >= 4
            ? value.substring(value.length - 4)
            : '';
        return '$prefix••••$suffix';
      }
    }

    return '••••';
  }

  String _secretFingerprint(String secret) {
    return sha256.convert(utf8.encode(secret)).toString();
  }

  double _entropy(String input) {
    if (input.isEmpty) return 0;

    final frequencies = <int, int>{};
    for (final code in input.codeUnits) {
      frequencies[code] = (frequencies[code] ?? 0) + 1;
    }

    final length = input.length.toDouble();
    var entropy = 0.0;

    frequencies.forEach((_, count) {
      final p = count / length;
      entropy -= p * (log(p) / ln2);
    });

    return entropy;
  }
}
