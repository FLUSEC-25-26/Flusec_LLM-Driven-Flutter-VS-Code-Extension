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

import 'package:analyzer/dart/analysis/utilities.dart';

import '../lib/core/output.dart';
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
  // 2) Parse Dart file -> AST
  // ---------------------------
  final content = file.readAsStringSync();
  final result = parseString(content: content, path: filePath);
  final unit = result.unit;

  // ---------------------------
  // 3) Run IDS module (Insecure Data Storage)
  // ---------------------------
  final storageEngine = InsecureStorageRulesEngine();
  final storageVisitor = StorageVisitor(storageEngine, content, filePath);
  unit.accept(storageVisitor);

  stderr.writeln('🔍 Analyzed file: $filePath');
  stderr.writeln('📊 Found ${storageVisitor.issues.length} insecure storage issue(s)');

  // ---------------------------
  // 4) Output
  // ---------------------------
  
  // Minimal stdout payload for VS Code extension
  OutputWriter.printStdout(storageVisitor.issues);

/*
  // Rich findings.json for dashboard/diagnostics
  OutputWriter.writeFindingsJson(
    filePath: filePath,
    content: content,
    issues: storageVisitor.issues,
  );
  */
}

