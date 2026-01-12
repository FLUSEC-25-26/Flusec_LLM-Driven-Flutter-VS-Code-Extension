import 'dart:convert';
import 'dart:io';

import 'package:analyzer/dart/analysis/utilities.dart';
import 'package:dart_analyzer/core/output.dart';
import 'package:dart_analyzer/core/paths.dart';
import 'package:dart_analyzer/hsd/index.dart';

List<Map<String, dynamic>> _readRuleList(File f) {
  if (!f.existsSync()) return const [];
  try {
    final raw = jsonDecode(f.readAsStringSync());
    if (raw is List) {
      return raw.whereType<Map>().map((m) => m.cast<String, dynamic>()).toList();
    }
  } catch (_) {}
  return const [];
}

Map<String, dynamic> _readMap(File f) {
  if (!f.existsSync()) return {};
  try {
    final raw = jsonDecode(f.readAsStringSync());
    if (raw is Map) return raw.cast<String, dynamic>();
  } catch (_) {}
  return {};
}

void main(List<String> args) {
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

  // Load rules + heuristics from resolved workspace data/
  final rulesFile = RulesPathResolver.resolveRulesFile('hardcoded_secrets_rules.json');
  final heuristicsFile =
      RulesPathResolver.resolveRulesFile('hardcoded_secrets_heuristics.json');

  final rawRules = _readRuleList(rulesFile);
  if (rawRules.isNotEmpty) {
    stderr.writeln('♻️ Reloaded ${rawRules.length} rule(s) from ${rulesFile.path}');
  } else {
    stderr.writeln('⚠️ rules.json not found – continuing with built-in rules.');
  }

  final heuristics = _readMap(heuristicsFile);

  final engine = RulesEngine();
  engine.loadDynamicRules(rawRules);
  engine.loadHeuristics(heuristics);

  final content = file.readAsStringSync();
  final result = parseString(content: content, path: filePath);
  final unit = result.unit;

  final visitor = SecretVisitor(engine, content, filePath);
  unit.accept(visitor);

  OutputWriter.printStdout(visitor.issues);
}
