// bin/analyzer.dart
import 'dart:convert';
import 'dart:io';
import 'package:analyzer/dart/analysis/utilities.dart';
import 'package:path/path.dart' as path;
import 'package:dart_analyzer/rules/hardcoded_secrets_rules.dart';

void main(List<String> args) {
  if (args.isEmpty) {
    stderr.writeln('Usage: dart run bin/analyzer.dart <path-to-dart-file>');
    exitCode = 2;
    return;
  }

  final filePath = args.first;
  final file = File(filePath);
  if (!file.existsSync()) {
    stderr.writeln("PathNotFoundException: Cannot open file, path = '$filePath'");
    exitCode = 2;
    return;
  }

  // ✅ Dynamically locate rules.json — works in both extension & user project
  final currentDir = Directory.current.path;
  final localRules = File(path.join(currentDir, 'data', 'hardcoded_secrets_rules.json'));
  final extensionRules = File(path.join(
    path.dirname(Platform.script.toFilePath()),
    '..',
    'data',
    'hardcoded_secrets_rules.json',
  ));

  // ✅ Reload fresh every analyzer run
  List<Map<String, dynamic>> rawRules = const [];
  final rulesPath = localRules.existsSync() ? localRules : extensionRules;

  if (rulesPath.existsSync()) {
    try {
      rawRules = (jsonDecode(rulesPath.readAsStringSync()) as List)
          .cast<Map<String, dynamic>>();
      stderr.writeln('♻️ Reloaded ${rawRules.length} rule(s) from ${rulesPath.path}');
    } catch (e) {
      stderr.writeln('⚠️ Failed to parse rules.json: $e');
    }
  } else {
    stderr.writeln('⚠️ rules.json not found – continuing with built-in rules.');
  }

  final engine = RulesEngine();
  engine.loadDynamicRules(rawRules);

  final content = file.readAsStringSync();
  final result = parseString(content: content, path: filePath);
  final unit = result.unit;

  // Visit AST & collect issues
  final visitor = SecretVisitor(engine, content, filePath);
  unit.accept(visitor);

  // === Minimal stdout payload (keeps your current behavior) ===
  final out = visitor.issues
      .map((i) => {
            'ruleId': i.ruleId,
            'severity': i.severity,
            'message': i.message,
            'line': i.line,
            'column': i.column,
          })
      .toList();
  stdout.writeln(jsonEncode(out));

  // === Rich findings for VS Code dashboard/diagnostics ===
  try {
    final findings = <Map<String, dynamic>>[];
    for (final i in visitor.issues) {
      final snippet = _lineSnippet(content, i.line);
      findings.add({
        'file': filePath,
        'line': i.line,
        'column': i.column,
        'ruleId': i.ruleId,
        'ruleName': _ruleNameFromMessage(i.message) ?? i.ruleId,
        'severity': i.severity,
        'nodeKind': _nodeKindFromMessage(i.message) ?? '', 
        'context': _contextFromMessage(i.message) ?? '',
        'message': i.message,
        'snippet': snippet,
        'fingerprint': _fingerprint(filePath, i.line, i.column, i.ruleId, snippet),
      });
    }

    // ✅ Always write to ".out/findings.json" in the current project folder
    final outDir = Directory('.out');
    outDir.createSync(recursive: true);
    final outFile = File(path.join(outDir.path, 'findings.json'));
    outFile.writeAsStringSync(const JsonEncoder.withIndent('  ').convert(findings));

    stderr.writeln('📝 Wrote ${findings.length} finding(s) to ${outFile.path}');
  } catch (e, st) {
    stderr.writeln('⚠️ Failed to write .out/findings.json: $e\n$st');
  }
}

// ---------- helpers to enrich findings.json ----------

String _lineSnippet(String source, int line1) {
  final lines = const LineSplitter().convert(source);
  if (line1 <= 0 || line1 > lines.length) return "";
  return lines[line1 - 1].trim();
}

// Works with messages produced by the updated rules.dart:
//  - "{ruleName} hardcoded in {nodeKind} in \"{context}\""
//  - "Possible hardcoded secret in {nodeKind} in \"{context}\""
String? _ruleNameFromMessage(String msg) {
  final idx = msg.indexOf(' hardcoded in ');
  if (idx > 0) return msg.substring(0, idx);
  if (msg.startsWith('Possible hardcoded secret')) return 'Secret';
  return null;
}

String? _nodeKindFromMessage(String msg) {
  final needle = ' hardcoded in ';
  final idx = msg.indexOf(needle);
  if (idx >= 0) {
    final rest = msg.substring(idx + needle.length);
    final end = rest.indexOf(' in "');
    return end > 0 ? rest.substring(0, end) : rest;
  }
  if (msg.startsWith('Possible hardcoded secret in ')) {
    final rest = msg.substring('Possible hardcoded secret in '.length);
    final end = rest.indexOf(' in "');
    return end > 0 ? rest.substring(0, end) : rest;
  }
  return null;
}

String? _contextFromMessage(String msg) {
  final needle = ' in "';
  final idx = msg.lastIndexOf(needle);
  if (idx >= 0 && msg.endsWith('"')) {
    return msg.substring(idx + needle.length, msg.length - 1);
  }
  return null;
}

// Simple deterministic hash; fine for baselining and grouping
String _fingerprint(String file, int line, int col, String ruleId, String snippet) {
  final s = '$file|$line|$col|$ruleId|$snippet';
  int h = 0;
  for (int i = 0; i < s.length; i++) {
    h = 0x1fffffff & (h + s.codeUnitAt(i));
    h = 0x1fffffff & (h + ((0x0007ffff & h) << 10));
    h ^= (h >> 6);
  }
  h = 0x1fffffff & (h + ((0x03ffffff & h) << 3));
  h ^= (h >> 11);
  h = 0x1fffffff & (h + ((0x00003fff & h) << 15));
  return h.toUnsigned(32).toRadixString(16).padLeft(8, '0');
}
