import 'dart:convert';
import 'dart:io';
import 'package:analyzer/dart/analysis/utilities.dart';
import 'package:dart_analyzer/core/output.dart';
import 'package:dart_analyzer/core/paths.dart';
import 'package:dart_analyzer/ivd/index.dart';

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

  // 1. Load IVD Rules from JSON
  final rulesFile = RulesPathResolver.resolveRulesFile(
    'input_validation_rules.json',
  );
  List<Map<String, dynamic>> ivdRules = [];

  if (rulesFile.existsSync()) {
    try {
      ivdRules = (jsonDecode(rulesFile.readAsStringSync()) as List)
          .cast<Map<String, dynamic>>();
    } catch (e) {
      stderr.writeln('Error parsing IVD rules: $e');
    }
  }

  // 2. Parse Code
  final content = file.readAsStringSync();
  final result = parseString(content: content, path: filePath);
  final unit = result.unit;

  // 3. Run IVD Visitor with loaded rules
  final ivdVisitor = IvdVisitor(filePath, ivdRules);
  unit.accept(ivdVisitor);

  // 4. Output Findings
  final allIssues = ivdVisitor.issues;
  OutputWriter.printStdout(allIssues);
  OutputWriter.writeFindingsJson(
    filePath: filePath,
    content: content,
    issues: allIssues,
  );
}
