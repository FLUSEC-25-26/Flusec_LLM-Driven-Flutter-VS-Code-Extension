// lib/rules.dart
import 'dart:io';
import 'dart:math';
import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/token.dart';
import 'package:analyzer/dart/ast/visitor.dart';

/// ------------------------------
/// Models & engine
/// ------------------------------

class DynamicRule {
  final String id;
  final String name;
  final String pattern;
  final String severity;
  final String description;
  final bool enabled;
  final String? messageTemplate;
  final RegExp regex;

  DynamicRule({
    required this.id,
    required this.name,
    required this.pattern,
    required this.severity,
    required this.description,
    required this.enabled,
    required this.messageTemplate,
    required this.regex,
  });
}

enum MatchSource { dynamicRule, builtinRule, heuristic }

class MatchHit {
  final MatchSource source;
  final String ruleId;
  final String message;
  final String severity;
  MatchHit(this.source, this.ruleId, this.message, this.severity);
}

class Issue {
  final String ruleId;
  final String message;
  final String severity;
  final int line;
  final int column;

  // NEW: where and how complex the secret’s context is
  final String? functionName; // enclosing function/method name, if any
  final int? complexity;      // cyclomatic complexity of that executable

  Issue(
    this.ruleId,
    this.message,
    this.severity,
    this.line,
    this.column, {
    this.functionName,
    this.complexity,
  });
}


class RulesEngine {
  final List<DynamicRule> _dynamic = [];
  final Set<String> _dynamicPatternSet = {};

  final RegExp _googleKey = RegExp(r'^AIza[0-9A-Za-z\-_]{35}$');
  final RegExp _awsAccessKey = RegExp(r'^AKIA[0-9A-Z]{16}$');
  final RegExp _stripeLive = RegExp(r'^sk_live_[0-9A-Za-z]{16,}$');
  final RegExp _jwt =
      RegExp(r'eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+');

  final List<String> _sensitiveKeywords = const [
    'password',
    'passwd',
    'pwd',
    'secret',
    'token',
    'apikey',
    'api_key',
    'auth',
    'authorization',
    'bearer',
    'private',
    'key',
  ];

  final List<String> _benignMarkers = const [
    'test',
    'dummy',
    'sample',
    'example',
    'fake',
    'placeholder',
    'changeme',
  ];

  final int _globalMinLen = 10;
  final double _globalMinEntropy = 3.3;

  void loadDynamicRules(List<Map<String, dynamic>> raw) {
    _dynamic
      ..clear()
      ..addAll(raw.map((r) {
        final enabled = (r['enabled'] as bool?) ?? true;
        final pat = (r['pattern'] as String).trim();
        stderr.writeln('🧠 Compiled pattern for rule "${r['id']}": $pat');
        return DynamicRule(
          id: r['id'] as String,
          name: (r['name'] as String?) ?? (r['id'] as String),
          pattern: pat,
          severity: (r['severity'] as String?) ?? 'warning',
          description: (r['description'] as String?) ?? '',
          enabled: enabled,
          messageTemplate: r['messageTemplate'] as String?,
          regex: RegExp(pat,
              caseSensitive: false, dotAll: true, multiLine: true),
        );
      }).where((r) => r.enabled));

    _dynamicPatternSet
      ..clear()
      ..addAll(_dynamic.map((r) => r.pattern));

    stderr.writeln('✅ Loaded ${_dynamic.length} dynamic rules.');
  }

  MatchHit? detect(String value, String contextName, String nodeKind) {
    final trimmed = value.trim();
    if (trimmed.isEmpty || trimmed.length < 3) return null;

    final lc = trimmed.toLowerCase();
    if (lc.contains('dummy') || lc.contains('example') || lc.contains('sample')) {
      return null;
    }

    final bool isHttp =
        trimmed.startsWith('http://') || trimmed.startsWith('https://');

    // 1️⃣ dynamic
    for (final r in _dynamic) {
      if (r.regex.hasMatch(trimmed)) {
        final msg =
            '${r.name} hardcoded in $nodeKind${contextName.isNotEmpty ? ' in "$contextName"' : ''}';
        return MatchHit(MatchSource.dynamicRule, r.id, msg, r.severity);
      }
    }

    // 2️⃣ built-in
    MatchHit? builtIn;
    if (!_dynamicPatternSet.contains(_googleKey.pattern) &&
        _googleKey.hasMatch(trimmed)) {
      builtIn = MatchHit(MatchSource.builtinRule, 'FLUSEC.GOOGLE_API_KEY',
          'Google API Key hardcoded in $nodeKind', 'warning');
    } else if (!_dynamicPatternSet.contains(_awsAccessKey.pattern) &&
        _awsAccessKey.hasMatch(trimmed)) {
      builtIn = MatchHit(MatchSource.builtinRule, 'FLUSEC.AWS_ACCESS_KEY',
          'AWS Access Key hardcoded in $nodeKind', 'warning');
    } else if (!_dynamicPatternSet.contains(_stripeLive.pattern) &&
        _stripeLive.hasMatch(trimmed)) {
      builtIn = MatchHit(MatchSource.builtinRule, 'FLUSEC.STRIPE_LIVE_KEY',
          'Stripe Live Secret Key hardcoded in $nodeKind', 'warning');
    } else if (!_dynamicPatternSet.contains(_jwt.pattern) &&
        _jwt.hasMatch(trimmed)) {
      builtIn = MatchHit(MatchSource.builtinRule, 'FLUSEC.JWT',
          'JWT Token hardcoded in $nodeKind', 'warning');
    }
    if (builtIn != null) return builtIn;

    // 3️⃣ heuristics
    final e = _entropy(trimmed);
    final ctxLower = contextName.toLowerCase();
    final hasKeyword = _sensitiveKeywords.any((kw) => ctxLower.contains(kw));

    final hasBenignValueMarker = _benignMarkers.any((m) => lc.contains(m));
    final hasBenignContextMarker =
        _benignMarkers.any((m) => ctxLower.contains(m));
    if (hasBenignValueMarker || hasBenignContextMarker) return null;

    if (isHttp && !_isSensitiveUrl(trimmed)) return null;

    if (!isHttp &&
        trimmed.length >= max(_globalMinLen, 17) &&
        e > max(_globalMinEntropy, 3.6)) {
      return MatchHit(MatchSource.heuristic, 'FLUSEC.SEC_HEUR',
          'Possible hardcoded secret in $nodeKind', 'warning');
    }

    if (hasKeyword && trimmed.length >= _globalMinLen && e > _globalMinEntropy) {
      return MatchHit(MatchSource.heuristic, 'FLUSEC.SEC_HEUR',
          'Possible hardcoded secret in $nodeKind', 'warning');
    }

    return null;
  }

  bool _isSensitiveUrl(String s) {
    final slack = RegExp(
        r'^https://hooks\.slack\.com/services/[A-Za-z0-9]{9,}/[A-Za-z0-9]{9,}/[A-Za-z0-9]{24,}$');
    final discord = RegExp(
        r'^https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]{30,}');
    return slack.hasMatch(s) ||
        discord.hasMatch(s) ||
        (s.contains('?') && s.toLowerCase().contains('sig='));
  }

  double _entropy(String s) {
    if (s.isEmpty) return 0;
    final freq = <int, int>{};
    for (final code in s.codeUnits) {
      freq.update(code, (v) => v + 1, ifAbsent: () => 1);
    }
    final len = s.length;
    double h = 0.0;
    freq.forEach((_, count) {
      final p = count / len;
      h -= p * (log(p) / log(2));
    });
    return h;
  }
}

/// ------------------------------
/// AST Visitor
/// ------------------------------

class SecretVisitor extends RecursiveAstVisitor<void> {
  final RulesEngine engine;
  final String raw;
  final String filePath;

  final List<Issue> issues = [];
  final Set<String> _seen = {};

  SecretVisitor(this.engine, this.raw, this.filePath);

  String _nodeKindName(AstNode node) {
    final rawName = node.runtimeType.toString();
    return rawName.endsWith('Impl')
        ? rawName.substring(0, rawName.length - 4)
        : rawName;
  }

  /// Walk up AST tree to detect if inside insecure storage sinks
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

    /// Find the enclosing function / method / constructor (if any)
  AstNode? _enclosingExecutable(AstNode node) {
    AstNode? current = node;
    while (current != null) {
      if (current is FunctionDeclaration ||
          current is MethodDeclaration ||
          current is ConstructorDeclaration ||
          current is FunctionExpression) {
        return current;
      }
      current = current.parent;
    }
    return null;
  }

  /// Human-readable name for the executable
  String _executableName(AstNode exec) {
    if (exec is FunctionDeclaration) {
      return exec.name.lexeme;
    }
    if (exec is MethodDeclaration) {
      return exec.name.lexeme;
    }
    if (exec is ConstructorDeclaration) {
      final typeName = exec.returnType?.toSource() ?? '';
      final ctorName = exec.name?.lexeme ?? '';
      return ctorName.isEmpty ? typeName : '$typeName.$ctorName';
    }
    // anonymous functions / lambdas
    return '<anonymous>';
  }

  /// Simple cyclomatic complexity:
  /// counts branches (if/for/while/switch/?:) and && / ||.
  int _computeCyclomaticComplexity(AstNode exec) {
    int complexity = 1; // default path

    void walk(AstNode n) {
      if (n is IfStatement ||
          n is ForStatement ||
          n is WhileStatement ||
          n is DoStatement ||
          n is SwitchCase ||
          n is ConditionalExpression) {
        complexity++;
      }

      if (n is CatchClause) {
        complexity++;
      }

      if (n is BinaryExpression) {
        final op = n.operator.lexeme;
        if (op == '&&' || op == '||') {
          complexity++;
        }
      }

      for (final child in n.childEntities) {
        if (child is AstNode) {
          walk(child);
        }
      }
    }

    walk(exec);
    return complexity;
  }


  void _maybeReport(AstNode node, String? value, String contextName) {
    if (value == null || value.isEmpty) return;
    if (_isInsideInsecureStorageCall(node)) return;

    final nodeKind = _nodeKindName(node);
    final hit = engine.detect(value, contextName, nodeKind);
    if (hit == null) return;

    final loc = _nodeLocation(node);
    final key = '$filePath:${loc.$1}:${loc.$2}:${hit.ruleId}';
    if (_seen.add(key)) {
      // NEW: try to find enclosing executable and compute complexity
      String? fnName;
      int? complexity;
      final exec = _enclosingExecutable(node);
      if (exec != null) {
        fnName = _executableName(exec);
        complexity = _computeCyclomaticComplexity(exec);
      }

      issues.add(Issue(
        hit.ruleId,
        hit.message,
        hit.severity,
        loc.$1,
        loc.$2,
        functionName: fnName,
        complexity: complexity,
      ));
    }
  }


  (int, int) _nodeLocation(AstNode node) {
    final unit = node.root as CompilationUnit;
    final loc = unit.lineInfo.getLocation(node.offset);
    return (loc.lineNumber, loc.columnNumber);
  }

  String? _stringFromExpression(Expression? e) =>
      e is StringLiteral ? e.stringValue : null;

  String _nameFrom(Object? any) {
    if (any == null) return '';
    if (any is SimpleIdentifier) return any.name;
    if (any is PrefixedIdentifier) return any.identifier.name;
    if (any is Token) return any.lexeme;
    if (any is AstNode) return any.toSource();
    return any.toString();
  }

  String _lhsName(Expression lhs) {
    if (lhs is SimpleIdentifier) return lhs.name;
    if (lhs is PrefixedIdentifier) return lhs.identifier.name;
    if (lhs is PropertyAccess) return lhs.propertyName.name;
    if (lhs is IndexExpression) {
      return lhs.target?.toSource() ?? lhs.toSource();
    }
    return lhs.toSource();
  }

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
