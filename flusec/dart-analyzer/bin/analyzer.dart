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
import 'package:dart_analyzer/iiv/index.dart' as iiv;

// ---------------------------------------------------------------------------
// Shared file readers
// ---------------------------------------------------------------------------

List<Map<String, dynamic>> _readRuleList(File f) {
  if (!f.existsSync()) return const [];
  try {
    final raw = jsonDecode(f.readAsStringSync());
    if (raw is List) {
      return raw
          .whereType<Map>()
          .map((m) => m.cast<String, dynamic>())
          .toList();
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
// Single-file analysis
// ---------------------------------------------------------------------------

List<Issue> _analyzeFile(String filePath) {
  final file = File(filePath);
  if (!file.existsSync()) {
    stderr.writeln("PathNotFoundException: Cannot open file, path = '$filePath'");
    return [];
  }

  final content = file.readAsStringSync();
  final result = parseString(content: content, path: filePath);
  final unit = result.unit;

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
      stderr.writeln(
        '♻️ [HSD] Reloaded ${rawRules.length} rule(s) from ${hsdRulesFile.path}',
      );
    } else {
      stderr.writeln('⚠️ [HSD] Rules file not found or empty.');
    }

    final heuristics = _readMap(hsdHeuristicsFile);

    final engine = RulesEngine();
    engine.loadDynamicRules(rawRules);
    engine.loadHeuristics(heuristics);

    final visitor = SecretVisitor(engine, content, filePath);
    visitor.setUnit(unit);
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
      stderr.writeln(
        '♻️ [NET] Loaded ${rawNetRules.length} rule(s) from ${netRulesFile.path}',
      );
    } else {
      netRulesEngine.loadRules(const []);
      stderr.writeln('⚠️ [NET] No rules file found.');
    }

    final netIssues =
        net.NetworkAnalyzer.run(unit, content, filePath, netRulesEngine);

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
      stderr.writeln(
        '♻️ [IDS] Loaded ${rawIdsRules.length} rule(s) from ${idsRulesFile.path}',
      );
    } else {
      idsRulesEngine.loadRules(const []);
      stderr.writeln('⚠️ [IDS] No rules file found.');
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
  // 4) IIV — Insufficient Input Validation
  // =========================================================================
  try {
    final iivRulesFile =
        RulesPathResolver.resolveRulesFile('input_validation_rules.json');

    final iivRulesEngine = iiv.IivRulesEngine();

    final rawIivRules = _readRuleList(iivRulesFile);
    if (rawIivRules.isNotEmpty) {
      iivRulesEngine.loadRules(rawIivRules);
      stderr.writeln(
        '♻️ [IIV] Loaded ${rawIivRules.length} rule(s) from ${iivRulesFile.path}',
      );
    } else {
      iivRulesEngine.loadRules(const []);
      stderr.writeln('⚠️ [IIV] No rules file found.');
    }

    // Existing IIV rule-based visitor
    final iivVisitor = iiv.IivVisitor(unit, filePath, iivRulesEngine);
    unit.accept(iivVisitor);
    iivVisitor.debugCounters();

    allIssues.addAll(iivVisitor.issues);
    stderr.writeln('[IIV] Input validation issues: ${iivVisitor.issues.length}');

    // New cohesion visitor under IIV bucket
    final cohesionVisitor = iiv.CohesionVisitor(filePath);
    unit.accept(cohesionVisitor);

    allIssues.addAll(cohesionVisitor.issues);
    stderr.writeln('[IIV] Cohesion issues: ${cohesionVisitor.issues.length}');
    stderr.writeln(
      '[IIV] Found ${iivVisitor.issues.length + cohesionVisitor.issues.length} issue(s).',
    );
  } catch (e, st) {
    stderr.writeln('⚠️ [IIV] Error during analysis: $e\n$st');
  }

  return allIssues;
}

// ---------------------------------------------------------------------------
// Project scan (--project <dir>)
// ---------------------------------------------------------------------------

List<String> _collectDartFiles(Directory dir) {
  final files = <String>[];
  for (final entity in dir.listSync(recursive: true, followLinks: false)) {
    if (entity is File && entity.path.endsWith('.dart')) {
      final name = entity.uri.pathSegments.last;
      if (!name.startsWith('.') &&
          !entity.path.contains('.dart_tool') &&
          !entity.path.contains('build') &&
          !entity.path.contains('.flusec') &&
          !entity.path.contains('generated')) {
        files.add(entity.path);
      }
    }
  }
  return files;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

void main(List<String> args) {
  if (args.isEmpty) {
    stderr.writeln('Usage: analyzer.exe <path-to-dart-file>');
    stderr.writeln('       analyzer.exe --project <dir>');
    exitCode = 2;
    return;
  }

  // --project mode
  if (args.length >= 2 && args[0] == '--project') {
    final dir = Directory(args[1]);
    if (!dir.existsSync()) {
      stderr.writeln("Directory not found: ${args[1]}");
      exitCode = 2;
      return;
    }

    final dartFiles = _collectDartFiles(dir);
    stderr.writeln(
      '📁 Project scan: found ${dartFiles.length} Dart file(s) in ${dir.path}',
    );

    final allIssues = <Issue>[];
    for (final f in dartFiles) {
      try {
        allIssues.addAll(_analyzeFile(f));
      } catch (e) {
        stderr.writeln('⚠️ Error analyzing $f: $e');
      }
    }

    stderr.writeln(
      '━━━ Total: ${allIssues.length} issue(s) from ${dartFiles.length} file(s) ━━━',
    );
    OutputWriter.printStdout(allIssues);
    return;
  }

  // Single file mode
  final allIssues = _analyzeFile(args.first);

  stderr.writeln(
    '━━━ Total: ${allIssues.length} issue(s) from all components ━━━',
  );
  OutputWriter.printStdout(allIssues);
}