// import 'dart:convert';
// import 'dart:io';

// import 'package:analyzer/dart/analysis/utilities.dart';

// import 'package:dart_analyzer/core/output.dart';
// import 'package:dart_analyzer/core/paths.dart';
// // Import both modules
// import 'package:dart_analyzer/hsd/index.dart';
// import 'package:dart_analyzer/ivd/index.dart';

// void main(List<String> args) {
//   if (args.isEmpty) {
//     stderr.writeln('Usage: dart run bin/analyzer.dart <path-to-dart-file>');
//     exitCode = 2;
//     return;
//   }

//   final filePath = args.first;
//   final file = File(filePath);

//   if (!file.existsSync()) {
//     stderr.writeln(
//       "PathNotFoundException: Cannot open file, path = '$filePath'",
//     );
//     exitCode = 2;
//     return;
//   }

//   // 1. Setup HSD Rules
//   final rulesFile = RulesPathResolver.resolveRulesFile(
//     'hardcoded_secrets_rules.json',
//   );
//   List<Map<String, dynamic>> rawRules = const [];
//   if (rulesFile.existsSync()) {
//     try {
//       rawRules = (jsonDecode(rulesFile.readAsStringSync()) as List)
//           .cast<Map<String, dynamic>>();
//     } catch (e) {
//       stderr.writeln('⚠️ Failed to parse rules.json: $e');
//     }
//   }
//   final hsdEngine = RulesEngine();
//   hsdEngine.loadDynamicRules(rawRules);

//   // 2. Parse Code
//   final content = file.readAsStringSync();
//   final result = parseString(content: content, path: filePath);
//   final unit = result.unit;

//   // 3. Run HSD Visitor
//   final secretVisitor = SecretVisitor(hsdEngine, content, filePath);
//   unit.accept(secretVisitor);

//   // 4. Run IVD Visitor (NEW)
//   final ivdVisitor = IvdVisitor(filePath);
//   unit.accept(ivdVisitor);

//   // 5. Combine Issues
//   final allIssues = [...secretVisitor.issues, ...ivdVisitor.issues];

//   // 6. Output
//   OutputWriter.printStdout(allIssues);

//   // Optional: Write findings.json for dashboard
//   OutputWriter.writeFindingsJson(
//     filePath: filePath,
//     content: content,
//     issues: allIssues,
//   );
// }

// dart-analyzer/bin/analyzer.dart

import 'dart:convert';
import 'dart:io';
import 'package:analyzer/dart/analysis/utilities.dart';
import 'package:dart_analyzer/core/output.dart';
import 'package:dart_analyzer/core/paths.dart';
import 'package:dart_analyzer/hsd/index.dart'; // HSD Module
import 'package:dart_analyzer/ivd/index.dart'; // IVD Module

void main(List<String> args) {
  if (args.isEmpty) return;

  final filePath = args.first;
  final file = File(filePath);
  if (!file.existsSync()) return;

  // 1. Load HSD Rules
  final rulesFile = RulesPathResolver.resolveRulesFile(
    'hardcoded_secrets_rules.json',
  );
  List<Map<String, dynamic>> rawRules = const [];
  if (rulesFile.existsSync()) {
    try {
      rawRules = (jsonDecode(rulesFile.readAsStringSync()) as List)
          .cast<Map<String, dynamic>>();
    } catch (_) {}
  }
  final hsdEngine = RulesEngine();
  hsdEngine.loadDynamicRules(rawRules);

  // 2. Parse Code
  final content = file.readAsStringSync();
  final result = parseString(content: content, path: filePath);
  final unit = result.unit;

  // 3. Run HSD Visitor (Secrets)
  final secretVisitor = SecretVisitor(hsdEngine, content, filePath);
  unit.accept(secretVisitor);

  // 4. Run IVD Visitor (Input Validation) <-- CRITICAL STEP
  final ivdVisitor = IvdVisitor(filePath);
  unit.accept(ivdVisitor);

  // 5. Merge & Output
  final allIssues = [...secretVisitor.issues, ...ivdVisitor.issues];
  OutputWriter.printStdout(allIssues);
  OutputWriter.writeFindingsJson(
    filePath: filePath,
    content: content,
    issues: allIssues,
  );
}
