// dart-analyzer/bin/analyzer.dart

import 'dart:io';
import 'package:analyzer/dart/analysis/utilities.dart';
import 'package:dart_analyzer/core/output.dart';
import 'package:dart_analyzer/ivd/index.dart'; // Keeping IVD Module

void main(List<String> args) {
  if (args.isEmpty) {
    print('Usage: dart analyzer.dart <file_path>');
    return;
  }

  final filePath = args.first;
  final file = File(filePath);

  if (!file.existsSync()) {
    print('Error: File not found at $filePath');
    return;
  }

  // 1. Parse Code
  final content = file.readAsStringSync();
  final result = parseString(content: content, path: filePath);
  final unit = result.unit;

  // 2. Run IVD Visitor (Input Validation)
  // This focuses strictly on identifying missing or weak validation logic
  final ivdVisitor = IvdVisitor(filePath);
  unit.accept(ivdVisitor);

  // 3. Output Findings
  final allIssues = ivdVisitor.issues;

  OutputWriter.printStdout(allIssues);
  OutputWriter.writeFindingsJson(
    filePath: filePath,
    content: content,
    issues: allIssues,
  );
}
