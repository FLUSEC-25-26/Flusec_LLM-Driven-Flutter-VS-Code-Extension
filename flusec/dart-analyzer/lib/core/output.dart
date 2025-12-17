// lib/core/output.dart
//
// Shared output logic:
// - Minimal stdout payload (VS Code extension reads this)
// - Rich ".out/findings.json" payload for dashboards / diagnostics
//
// NOTE ABOUT OTHER COMPONENTS (future integration):
// When other modules are added (network/storage/validation), they should produce
// List<Issue> as well. Then analyzer.dart will merge all issues and call
// OutputWriter.printStdout(...) + OutputWriter.writeFindingsJson(...)
// ONE TIME. That is how you keep only ONE analyzer.exe.

import 'dart:convert';
import 'dart:io';
import 'package:path/path.dart' as path;

import 'issue.dart';

class OutputWriter {
  /// Print the minimal JSON array to stdout.
  /// This preserves your current VS Code behavior.
  static void printStdout(List<Issue> issues) {
    final out = issues
        .map((i) => {
              'ruleId': i.ruleId,
              'severity': i.severity,
              'message': i.message,
              'line': i.line,
              'column': i.column,
              // Your extra metadata:
              'functionName': i.functionName,
              'complexity': i.complexity,
            })
        .toList();

    stdout.writeln(jsonEncode(out));
  }

  /// Write the richer findings JSON to ".out/findings.json" in the current folder.
  /// Matches your original behavior exactly.
  static void writeFindingsJson({
    required String filePath,
    required String content,
    required List<Issue> issues,
  }) {
    try {
      final findings = <Map<String, dynamic>>[];

      for (final i in issues) {
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

          // Your contribution:
          'functionName': i.functionName,
          'complexity': i.complexity,

          // Deterministic grouping key:
          'fingerprint': _fingerprint(
            filePath,
            i.line,
            i.column,
            i.ruleId,
            snippet,
          ),
        });
      }

      // Always write to ".out/findings.json"
      final outDir = Directory('.out');
      outDir.createSync(recursive: true);

      final outFile = File(path.join(outDir.path, 'findings.json'));
      outFile.writeAsStringSync(
        const JsonEncoder.withIndent('  ').convert(findings),
      );

      stderr.writeln('📝 Wrote ${findings.length} finding(s) to ${outFile.path}');
    } catch (e, st) {
      stderr.writeln('⚠️ Failed to write .out/findings.json: $e\n$st');
    }
  }

  // ---------------------------
  // Helpers (copied from your original analyzer.dart)
  // ---------------------------

  static String _lineSnippet(String source, int line1) {
    final lines = const LineSplitter().convert(source);
    if (line1 <= 0 || line1 > lines.length) return "";
    return lines[line1 - 1].trim();
  }

  // Works with messages produced by your RulesEngine:
  //  - "{ruleName} hardcoded in {nodeKind} in \"{context}\""
  //  - "Possible hardcoded secret in {nodeKind}"
  static String? _ruleNameFromMessage(String msg) {
    final idx = msg.indexOf(' hardcoded in ');
    if (idx > 0) return msg.substring(0, idx);
    if (msg.startsWith('Possible hardcoded secret')) return 'Secret';
    return null;
  }

  static String? _nodeKindFromMessage(String msg) {
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

  static String? _contextFromMessage(String msg) {
    final needle = ' in "';
    final idx = msg.lastIndexOf(needle);
    if (idx >= 0 && msg.endsWith('"')) {
      return msg.substring(idx + needle.length, msg.length - 1);
    }
    return null;
  }

  // Simple deterministic hash; fine for baselining and grouping
  static String _fingerprint(
    String file,
    int line,
    int col,
    String ruleId,
    String snippet,
  ) {
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
}
