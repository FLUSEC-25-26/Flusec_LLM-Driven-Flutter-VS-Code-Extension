
// bin/dart_analyzer.dart
//
// ONE analyzer.exe – runs Network module now.
// Later, add other components and merge all issues in one output.

import 'dart:io';
import 'package:analyzer/dart/analysis/utilities.dart';
import 'package:dart_analyzer/core/output.dart';
import 'package:dart_analyzer/net/index.dart' as net;

void main(List<String> args) {
  if (args.isEmpty) {
    stderr.writeln('Usage: dart run bin/dart_analyzer.dart <path-to-dart-file>');
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

  // DEBUG: confirm which file is analyzed
  stderr.writeln('[NET] analyzing: ${file.absolute.path}');

  // Parse -> AST
  final content = file.readAsStringSync();
  final result = parseString(content: content, path: filePath);
  final unit = result.unit;

  // Run Network (all severities = "warning")
  final netIssues = net.NetworkAnalyzer.run(unit, content, filePath);
  stderr.writeln('[NET] issues = ${netIssues.length}'); // DEBUG count

  // Stdout array (what your VS Code extension consumes)
  OutputWriter.printStdout(netIssues);

  // Optional: richer .out file for dashboards (uncomment if you need it now)
  /*
  OutputWriter.writeFindingsJson(
    filePath: filePath,
    content: content,
    issues: netIssues,
  );
  */
}
