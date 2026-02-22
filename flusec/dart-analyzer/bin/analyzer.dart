// bin/analyzer.dart
//
// ONE analyzer.exe — runs ALL security components on a Dart file.
//
// Currently active:
//   1. HSD  — Hardcoded Secrets Detection + Maintainability Metrics
//   2. NET  — Insecure Network Communication Advisor
//   3. IDS  — Insecure Data Storage Advisor
//
// Future (uncomment when ready):
//   4. IIV  — Insufficient Input Validation Advisor
//
// Each component produces List<Issue>. All issues are merged and output ONCE
// via OutputWriter.printStdout() (which the VS Code extension reads from stdout).

import 'dart:convert';
import 'dart:io';

import 'package:analyzer/dart/analysis/utilities.dart';
import 'package:dart_analyzer/core/output.dart';
import 'package:dart_analyzer/core/paths.dart';
import 'package:dart_analyzer/core/issue.dart';

// Component imports
import 'package:dart_analyzer/hsd/index.dart';
import 'package:dart_analyzer/net/index.dart' as net;
import 'package:dart_analyzer/ids/index.dart' as ids;

// Future component imports (uncomment when ready):
// import 'package:dart_analyzer/iiv/index.dart' as iiv;

// ---------------------------------------------------------------------------
// Shared file readers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

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

  // Parse the Dart file into an AST (shared by all components)
  final content = file.readAsStringSync();
  final result = parseString(content: content, path: filePath);
  final unit = result.unit;

  // Collect all issues from every component
  final allIssues = <Issue>[];

  // =========================================================================
  // 1) HSD — Hardcoded Secrets Detection
  // =========================================================================
  try {
    final hsdRulesFile =
        RulesPathResolver.resolveRulesFile('hardcoded_secrets_rules.json');
    final hsdHeuristicsFile =
        RulesPathResolver.resolveRulesFile('hardcoded_secrets_heuristics.json');

    final rawRules = _readRuleList(hsdRulesFile);
    if (rawRules.isNotEmpty) {
      stderr.writeln('♻️ [HSD] Reloaded ${rawRules.length} rule(s) from ${hsdRulesFile.path}');
    } else {
      stderr.writeln('⚠️ [HSD] Rules file not found or empty. Rule-based detection may be limited.');
    }

    final heuristics = _readMap(hsdHeuristicsFile);

    final engine = RulesEngine();
    engine.loadDynamicRules(rawRules);
    engine.loadHeuristics(heuristics);

    final visitor = SecretVisitor(engine, content, filePath);
    unit.accept(visitor);

    allIssues.addAll(visitor.issues);
    stderr.writeln('[HSD] Found ${visitor.issues.length} issue(s).');
  } catch (e, st) {
    stderr.writeln('⚠️ [HSD] Error during analysis: $e\n$st');
  }

  // =========================================================================
  // 2) NET — Insecure Network Communication
  // =========================================================================
  try {
    final netRulesFile =
        RulesPathResolver.resolveRulesFile('insecure_network_rules.json');

    final netRulesEngine = net.NetworkRulesEngine();

    final rawNetRules = _readRuleList(netRulesFile);
    if (rawNetRules.isNotEmpty) {
      netRulesEngine.loadRules(rawNetRules);
      stderr.writeln('♻️ [NET] Loaded ${rawNetRules.length} rule(s) from ${netRulesFile.path}');
    } else {
      netRulesEngine.loadRules(const []);
      stderr.writeln('⚠️ [NET] No rules file found. Network detection disabled.');
    }

    final netIssues = net.NetworkAnalyzer.run(unit, content, filePath, netRulesEngine);

    allIssues.addAll(netIssues);
    stderr.writeln('[NET] Found ${netIssues.length} issue(s).');
  } catch (e, st) {
    stderr.writeln('⚠️ [NET] Error during analysis: $e\n$st');
  }

  // =========================================================================
  // 3) IDS — Insecure Data Storage
  // =========================================================================
  try {
    final idsRulesFile =
        RulesPathResolver.resolveRulesFile('insecure_data_storage_rules.json');

    final idsRulesEngine = ids.IdsRulesEngine();

    final rawIdsRules = _readRuleList(idsRulesFile);
    if (rawIdsRules.isNotEmpty) {
      idsRulesEngine.loadRules(rawIdsRules);
      stderr.writeln('♻️ [IDS] Loaded ${rawIdsRules.length} rule(s) from ${idsRulesFile.path}');
    } else {
      idsRulesEngine.loadRules(const []);
      stderr.writeln('⚠️ [IDS] No rules file found. Storage detection disabled.');
    }

    final idsVisitor = ids.StorageVisitor(unit, content, filePath, idsRulesEngine);
    unit.accept(idsVisitor);
    idsVisitor.debugCounters();

    allIssues.addAll(idsVisitor.issues);
    stderr.writeln('[IDS] Found ${idsVisitor.issues.length} issue(s).');
  } catch (e, st) {
    stderr.writeln('⚠️ [IDS] Error during analysis: $e\n$st');
  }

  // =========================================================================
  // 4) IIV — Insufficient Input Validation (FUTURE — uncomment when ready)
  // =========================================================================
  // try {
  //   final iivRulesFile =
  //       RulesPathResolver.resolveRulesFile('insufficient_input_validation_rules.json');
  //   // ... load rules, run visitor ...
  //   // final iivIssues = iiv.ValidationAnalyzer.run(unit, content, filePath, iivRulesEngine);
  //   // allIssues.addAll(iivIssues);
  // } catch (e, st) {
  //   stderr.writeln('⚠️ [IIV] Error during analysis: $e\n$st');
  // }

  // =========================================================================
  // OUTPUT — single combined output for ALL components
  // =========================================================================
  stderr.writeln('━━━ Total: ${allIssues.length} issue(s) from all components ━━━');

  OutputWriter.printStdout(allIssues);
}