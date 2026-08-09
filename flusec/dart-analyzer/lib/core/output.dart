// lib/core/output.dart
//
// Shared output logic for every FLUSEC analyzer component.
// The live stdout contract is intentionally compact: optional component fields
// are omitted rather than serialized as meaningless null values.

import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:path/path.dart' as path;

import 'issue.dart';

class OutputWriter {
  static void printStdout(List<Issue> issues) {
    final out = issues.map(toMap).toList();
    stdout.writeln(jsonEncode(out));
  }

  /// Public mapping helper used by tests and optional file writers.
  ///
  /// The finding-level fingerprint never contains plaintext secret material.
  /// It identifies the finding from component/rule/location/function context.
  static Map<String, dynamic> toMap(Issue issue) {
    final out = <String, dynamic>{
      'file': issue.filePath,
      'ruleId': issue.ruleId,
      'message': issue.message,
      'severity': issue.severity,
      'line': issue.line,
      'column': issue.column,
      'component': issue.component,
      'fingerprint': _findingFingerprint(issue),
    };

    _putIfNotNull(out, 'securitySeverity', issue.securitySeverity);
    _putIfNotNull(out, 'confidence', issue.confidence);
    _putIfNotNull(out, 'category', issue.category);
    _putIfNotNull(out, 'remediation', issue.remediation);
    _putIfNotNull(out, 'cwe', issue.cwe);
    _putIfNotNull(out, 'evidence', issue.evidence);

    _putIfNotNull(out, 'functionName', issue.functionName);
    _putIfNotNull(out, 'complexity', issue.complexity);
    _putIfNotNull(out, 'nestingDepth', issue.nestingDepth);
    _putIfNotNull(out, 'functionLoc', issue.functionLoc);
    _putIfNotNull(out, 'maintainabilityScore', issue.maintainabilityScore);
    _putIfNotNull(out, 'maintainabilityLevel', issue.maintainabilityLevel);

    if (issue.component == 'hsd') {
      _putIfNotNull(out, 'secretType', issue.secretType);
      _putIfNotNull(out, 'taintFlow', issue.taintFlow);
    }

    if (issue.component == 'ids') {
      _putIfNotNull(out, 'dataType', issue.dataType);
      _putIfNotNull(out, 'storageContext', issue.storageContext);
    }

    return out;
  }

  /// Optional richer file output.
  ///
  /// Source snippets are deliberately omitted for all security components so
  /// FLUSEC cannot accidentally copy hardcoded credentials or sensitive values
  /// into a second artifact.
  static void writeFindingsJson({
    required String filePath,
    required String content,
    required List<Issue> issues,
  }) {
    try {
      final findings = <Map<String, dynamic>>[];

      for (final issue in issues) {
        findings.add({
          ...toMap(issue),
          'file': issue.filePath.isNotEmpty ? issue.filePath : filePath,
          'ruleName': _ruleNameFromMessage(issue.message) ?? issue.ruleId,
          'nodeKind': _nodeKindFromMessage(issue.message) ?? '',
          'context': _contextFromMessage(issue.message) ?? '',
          'snippet': '[REDACTED: source snippet omitted by FLUSEC]',
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

  static void _putIfNotNull(
    Map<String, dynamic> target,
    String key,
    Object? value,
  ) {
    if (value != null) {
      target[key] = value;
    }
  }

  static String _findingFingerprint(Issue issue) {
    final value = [
      issue.component.toLowerCase(),
      issue.ruleId.trim(),
      _normalizedFileIdentity(issue.filePath),
      (issue.functionName ?? '').trim(),
      issue.line.toString(),
      issue.column.toString(),
    ].join('|');

    return sha256.convert(utf8.encode(value)).toString();
  }

  static String _normalizedFileIdentity(String filePath) {
    if (filePath.trim().isEmpty) return '';

    final absolute = File(filePath).absolute.path;
    final current = Directory.current.absolute.path;

    // The VS Code extension runs analyzer.exe with <workspace>/.flusec as CWD.
    // In that mode use a workspace-relative path so fingerprints are not tied
    // to a developer's absolute machine path.
    if (path.basename(current) == '.flusec') {
      final workspaceRoot = path.dirname(current);
      if (path.equals(absolute, workspaceRoot) ||
          path.isWithin(workspaceRoot, absolute)) {
        return _slashNormalize(path.relative(absolute, from: workspaceRoot));
      }
    }

    return _slashNormalize(path.normalize(absolute));
  }

  static String _slashNormalize(String value) {
    final normalized = value.replaceAll('\\', '/');
    return Platform.isWindows ? normalized.toLowerCase() : normalized;
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
}
