// bin/analyzer.dart
//
// ONE analyzer.exe — runs ALL security components on a Dart file OR directory.
//
// Usage:
//   analyzer.exe <path-to-dart-file>       — scan a single file
//   analyzer.exe --project <path-to-dir>   — scan all .dart files recursively
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
// Engine initialization (shared across all files in project scan)
// ---------------------------------------------------------------------------

/// Initialize HSD engine once (reused across all files)
RulesEngine _initHsdEngine() {
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
  return engine;
}

/// Initialize NET engine once
net.NetworkRulesEngine _initNetEngine() {
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
  return netRulesEngine;
}

/// Initialize IDS engine once
ids.IdsRulesEngine _initIdsEngine() {
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
  return idsRulesEngine;
}

// ---------------------------------------------------------------------------
// Scan a single file using pre-initialized engines
// ---------------------------------------------------------------------------

List<Issue> _scanFile(
  String filePath,
  String content,
  RulesEngine hsdEngine,
  net.NetworkRulesEngine netEngine,
  ids.IdsRulesEngine idsEngine,
) {
  final result = parseString(content: content, path: filePath);
  final unit = result.unit;
  final fileIssues = <Issue>[];

  // 1) HSD
  try {
    final visitor = SecretVisitor(hsdEngine, content, filePath);
    visitor.setUnit(unit); // Required for taint analysis
    unit.accept(visitor);
    fileIssues.addAll(visitor.issues);
  } catch (e) {
    stderr.writeln('⚠️ [HSD] Error scanning $filePath: $e');
  }

  // 2) NET
  try {
    final netIssues = net.NetworkAnalyzer.run(unit, content, filePath, netEngine);
    fileIssues.addAll(netIssues);
  } catch (e) {
    stderr.writeln('⚠️ [NET] Error scanning $filePath: $e');
  }

  // 3) IDS
  try {
    final idsVisitor = ids.StorageVisitor(unit, content, filePath, idsEngine);
    unit.accept(idsVisitor);
    fileIssues.addAll(idsVisitor.issues);
  } catch (e) {
    stderr.writeln('⚠️ [IDS] Error scanning $filePath: $e');
  }

  // 4) IIV (future)
  // try {
  //   final iivIssues = iiv.ValidationAnalyzer.run(unit, content, filePath, iivEngine);
  //   fileIssues.addAll(iivIssues);
  // } catch (e) {
  //   stderr.writeln('⚠️ [IIV] Error scanning $filePath: $e');
  // }

  return fileIssues;
}

// ---------------------------------------------------------------------------
// Collect all .dart files recursively from a directory
// ---------------------------------------------------------------------------

List<File> _collectDartFiles(Directory dir) {
  final dartFiles = <File>[];

  try {
    final entities = dir.listSync(recursive: true, followLinks: false);
    for (final entity in entities) {
      if (entity is File && entity.path.endsWith('.dart')) {
        // Skip common non-source directories
        final relativePath = entity.path.replaceAll('\\', '/');
        if (relativePath.contains('/.dart_tool/') ||
            relativePath.contains('/build/') ||
            relativePath.contains('/.flusec/') ||
            relativePath.contains('/generated/')) {
          continue;
        }
        dartFiles.add(entity);
      }
    }
  } catch (e) {
    stderr.writeln('⚠️ Error listing directory: $e');
  }

  // Sort for deterministic output
  dartFiles.sort((a, b) => a.path.compareTo(b.path));
  return dartFiles;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

void main(List<String> args) {
  if (args.isEmpty) {
    stderr.writeln('Usage:');
    stderr.writeln('  analyzer.exe <path-to-dart-file>       — scan a single file');
    stderr.writeln('  analyzer.exe --project <path-to-dir>   — scan all .dart files recursively');
    exitCode = 2;
    return;
  }

  // Check for --project flag
  final isProjectScan = args.length >= 2 && args[0] == '--project';

  if (isProjectScan) {
    // =====================================================================
    // PROJECT SCAN MODE — scan all .dart files in directory
    // =====================================================================
    final dirPath = args[1];
    final dir = Directory(dirPath);

    if (!dir.existsSync()) {
      stderr.writeln("Directory not found: '$dirPath'");
      exitCode = 2;
      return;
    }

    stderr.writeln('━━━ FLUSEC Project Scan: $dirPath ━━━');

    // Initialize all engines ONCE (shared across all files)
    final hsdEngine = _initHsdEngine();
    final netEngine = _initNetEngine();
    final idsEngine = _initIdsEngine();

    // Collect all .dart files
    final dartFiles = _collectDartFiles(dir);
    stderr.writeln('📁 Found ${dartFiles.length} Dart file(s) to scan.');

    if (dartFiles.isEmpty) {
      stdout.writeln(jsonEncode([]));
      return;
    }

    // Scan each file and collect all issues
    final allIssues = <Issue>[];
    int filesScanned = 0;
    int filesWithIssues = 0;

    for (final file in dartFiles) {
      try {
        final content = file.readAsStringSync();
        final issues = _scanFile(
          file.path,
          content,
          hsdEngine,
          netEngine,
          idsEngine,
        );

        if (issues.isNotEmpty) {
          filesWithIssues++;
        }

        allIssues.addAll(issues);
        filesScanned++;

        // Progress indicator every 10 files
        if (filesScanned % 10 == 0) {
          stderr.writeln('  ... scanned $filesScanned / ${dartFiles.length} files');
        }
      } catch (e) {
        stderr.writeln('⚠️ Failed to scan ${file.path}: $e');
      }
    }

    // Summary
    stderr.writeln('━━━ Project Scan Complete ━━━');
    stderr.writeln('  Files scanned:      $filesScanned');
    stderr.writeln('  Files with issues:  $filesWithIssues');
    stderr.writeln('  Total issues:       ${allIssues.length}');

    // Count by component
    final hsdCount = allIssues.where((i) => i.component == 'hsd').length;
    final netCount = allIssues.where((i) => i.component == 'net').length;
    final idsCount = allIssues.where((i) => i.component == 'ids').length;
    stderr.writeln('  HSD: $hsdCount | NET: $netCount | IDS: $idsCount');

    // Output all issues as JSON to stdout
    OutputWriter.printStdout(allIssues);

  } else {
    // =====================================================================
    // SINGLE FILE MODE — original behavior (backwards compatible)
    // =====================================================================
    final filePath = args.first;
    final file = File(filePath);

    if (!file.existsSync()) {
      stderr.writeln("PathNotFoundException: Cannot open file, path = '$filePath'");
      exitCode = 2;
      return;
    }

    // Initialize engines
    final hsdEngine = _initHsdEngine();
    final netEngine = _initNetEngine();
    final idsEngine = _initIdsEngine();

    // Read and scan the single file
    final content = file.readAsStringSync();
    final allIssues = _scanFile(filePath, content, hsdEngine, netEngine, idsEngine);

    // Summary
    final hsdCount = allIssues.where((i) => i.component == 'hsd').length;
    final netCount = allIssues.where((i) => i.component == 'net').length;
    final idsCount = allIssues.where((i) => i.component == 'ids').length;
    stderr.writeln('[HSD] Found $hsdCount issue(s).');
    stderr.writeln('[NET] Found $netCount issue(s).');
    stderr.writeln('[IDS] Found $idsCount issue(s).');
    stderr.writeln('━━━ Total: ${allIssues.length} issue(s) from all components ━━━');

    OutputWriter.printStdout(allIssues);
  }
}