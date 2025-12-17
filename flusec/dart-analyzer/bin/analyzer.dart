// bin/analyzer.dart
//
// This is the ONLY entry point -> build ONE analyzer.exe from this.
// It runs your HSD scanner today, and is designed so that later
// other components can be plugged in and merged into one output.
//
// Future integration idea (teammates):
// - Add lib/network/..., lib/storage/..., lib/validation/...
// - Each will return List<Issue>
// - Merge all lists into one `allIssues` and output once.

import 'dart:convert';
import 'dart:io';

import 'package:analyzer/dart/analysis/utilities.dart';

import '../lib/core/output.dart';
import '../lib/core/paths.dart';
import '../lib/hsd/index.dart';

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
  // 2) Load dynamic rules JSON
  // ---------------------------
  final rulesFile = RulesPathResolver.resolveRulesFile('hardcoded_secrets_rules.json');

  // Reload fresh every analyzer run (same as your original behavior)
  List<Map<String, dynamic>> rawRules = const [];

  if (rulesFile.existsSync()) {
    try {
      rawRules = (jsonDecode(rulesFile.readAsStringSync()) as List)
          .cast<Map<String, dynamic>>();

      stderr.writeln('♻️ Reloaded ${rawRules.length} rule(s) from ${rulesFile.path}');
    } catch (e) {
      stderr.writeln('⚠️ Failed to parse rules.json: $e');
    }
  } else {
    stderr.writeln('⚠️ rules.json not found – continuing with built-in rules.');
  }

  final engine = RulesEngine();
  engine.loadDynamicRules(rawRules);

  // ---------------------------
  // 3) Parse Dart file -> AST
  // ---------------------------
  final content = file.readAsStringSync();
  final result = parseString(content: content, path: filePath);
  final unit = result.unit;

  // ---------------------------
  // 4) Run your HSD module (visitor)
  // ---------------------------
  final visitor = SecretVisitor(engine, content, filePath);
  unit.accept(visitor);

  // If you later add other components, you will do:
  //
  // final netIssues = NetworkVisitor(...).run(unit);
  // final storageIssues = StorageVisitor(...).run(unit);
  // final validationIssues = ValidationVisitor(...).run(unit);
  //
  // final allIssues = [
  //   ...visitor.issues,
  //   ...netIssues,
  //   ...storageIssues,
  //   ...validationIssues,
  // ];
  //
  // And output using allIssues.

  final allIssues = visitor.issues;

  // ---------------------------
  // 5) Output (same behavior as before)
  // ---------------------------

  // Minimal stdout payload for VS Code extension
  OutputWriter.printStdout(allIssues);

  // Rich findings.json for dashboard/diagnostics
  OutputWriter.writeFindingsJson(
    filePath: filePath,
    content: content,
    issues: allIssues,
  );
}
