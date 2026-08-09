// lib/core/output.dart
//
// Shared output logic for every FLUSEC analyzer component.

import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as path;

import 'issue.dart';

class OutputWriter {
  static void printStdout(List<Issue> issues) {
    final out = issues.map(_toMap).toList();
    stdout.writeln(jsonEncode(out));
  }

  /// Optional richer file output.
  /// HSD source snippets are redacted so FLUSEC does not copy a discovered
  /// credential into another artifact.
  static void writeFindingsJson({
    required String filePath,
    required String content,
    required List<Issue> issues,
  }) {
    try {
      final findings = <Map<String, dynamic>>[];

      for (final issue in issues) {
        final rawSnippet = _lineSnippet(content, issue.line);
        final snippet = issue.component == 'hsd'
            ? '[REDACTED: HSD source line omitted]'
            : rawSnippet;

        final evidenceFingerprint =
            issue.evidence?['secretFingerprint']?.toString();

        findings.add({
          ..._toMap(issue),
          'file': issue.filePath.isNotEmpty ? issue.filePath : filePath,
          'ruleName': _ruleNameFromMessage(issue.message) ?? issue.ruleId,
          'nodeKind': _nodeKindFromMessage(issue.message) ?? '',
          'context': _contextFromMessage(issue.message) ?? '',
          'snippet': snippet,
          'fingerprint': _fingerprint(
            issue.filePath.isNotEmpty ? issue.filePath : filePath,
            issue.line,
            issue.column,
            issue.ruleId,
            evidenceFingerprint ?? snippet,
          ),
        });
      }

      final outDir = Directory('.out');
      outDir.createSync(recursive: true);

      final outFile = File(path.join(outDir.path, 'findings.json'));
      outFile.writeAsStringSync(
        const JsonEncoder.withIndent('  ').convert(findings),
      );

      stderr.writeln('Wrote ${findings.length} finding(s) to ${outFile.path}');
    } catch (error, stackTrace) {
      stderr.writeln(
        'Failed to write .out/findings.json: $error\n$stackTrace',
      );
    }
  }

  static Map<String, dynamic> _toMap(Issue issue) {
    return {
      'file': issue.filePath,
      'ruleId': issue.ruleId,
      'severity': issue.severity,
      'securitySeverity': issue.securitySeverity,
      'confidence': issue.confidence,
      'category': issue.category,
      'message': issue.message,
      'remediation': issue.remediation,
      'cwe': issue.cwe,
      'evidence': issue.evidence,
      'line': issue.line,
      'column': issue.column,
      'functionName': issue.functionName,
      'complexity': issue.complexity,
      'nestingDepth': issue.nestingDepth,
      'functionLoc': issue.functionLoc,
      'maintainabilityScore': issue.maintainabilityScore,
      'maintainabilityLevel': issue.maintainabilityLevel,
      'secretType': issue.secretType,
      'taintFlow': issue.taintFlow,
      'component': issue.component,
      'riskLevel': issue.riskLevel,
      'dataType': issue.dataType,
      'storageContext': issue.storageContext,
    };
  }

  static String _lineSnippet(String source, int line1) {
    final lines = const LineSplitter().convert(source);
    if (line1 <= 0 || line1 > lines.length) return '';
    return lines[line1 - 1].trim();
  }

  static String? _ruleNameFromMessage(String message) {
    final index = message.indexOf(' hardcoded in ');
    if (index > 0) return message.substring(0, index);
    if (message.startsWith('Possible hardcoded')) return 'Secret';
    return null;
  }

  static String? _nodeKindFromMessage(String message) {
    const needle = ' hardcoded in ';
    final index = message.indexOf(needle);

    if (index >= 0) {
      final rest = message.substring(index + needle.length);
      final end = rest.indexOf(' in "');
      return end > 0 ? rest.substring(0, end) : rest;
    }

    return null;
  }

  static String? _contextFromMessage(String message) {
    const needle = ' in "';
    final index = message.lastIndexOf(needle);
    if (index >= 0) {
      final rest = message.substring(index + needle.length);
      final quoteEnd = rest.indexOf('"');
      if (quoteEnd >= 0) {
        return rest.substring(0, quoteEnd);
      }
    }
    return null;
  }

  static String _fingerprint(
    String file,
    int line,
    int column,
    String ruleId,
    String stableEvidence,
  ) {
    final value = '$file|$line|$column|$ruleId|$stableEvidence';
    var hash = 0;

    for (var i = 0; i < value.length; i++) {
      hash = 0x1fffffff & (hash + value.codeUnitAt(i));
      hash = 0x1fffffff & (hash + ((0x0007ffff & hash) << 10));
      hash ^= hash >> 6;
    }

    hash = 0x1fffffff & (hash + ((0x03ffffff & hash) << 3));
    hash ^= hash >> 11;
    hash = 0x1fffffff & (hash + ((0x00003fff & hash) << 15));
    return hash.toUnsigned(32).toRadixString(16).padLeft(8, '0');
  }
}
