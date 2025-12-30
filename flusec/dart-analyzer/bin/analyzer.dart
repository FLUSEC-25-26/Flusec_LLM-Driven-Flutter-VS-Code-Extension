// bin/analyzer.dart
//
// Insecure Data Storage (IDS) Analyzer
// This analyzer detects insecure data storage patterns in Flutter/Dart applications.
//
// Detects:
// - Unencrypted SharedPreferences
// - Unencrypted File Storage
// - Insecure SQLite Storage
// - Hardcoded Sensitive Storage Keys
// - Insecure Cache Storage

import 'dart:io';
import 'dart:convert';

import '../lib/ids/index.dart';

void main(List<String> args) {
  // ---------------------------
  // 1) Validate CLI args
  // ---------------------------
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

  // ---------------------------
  // 2) Run IDS Analysis
  // ---------------------------
  try {
    final idsAnalyzer = IDSAnalyzer();
    final issues = idsAnalyzer.analyzeFile(filePath);

    stderr.writeln('🔍 Analyzed file: $filePath');
    stderr.writeln('📊 Found ${issues.length} insecure storage issue(s)');

    // ---------------------------
    // 3) Output JSON to stdout
    // ---------------------------
    final jsonOutput = jsonEncode(issues.map((issue) => issue.toJson()).toList());
    stdout.writeln(jsonOutput);
    
  } catch (e, stackTrace) {
    stderr.writeln('❌ Error during analysis: $e');
    stderr.writeln(stackTrace);
    exitCode = 1;
  }
}
