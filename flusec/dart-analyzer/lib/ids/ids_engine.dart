// lib/ids/ids_engine.dart
//
// Main IDS analysis engine that orchestrates the scanning process

import 'dart:io';
import 'package:analyzer/dart/analysis/utilities.dart';

import 'ids_models.dart';
import 'insecure_storage_rules.dart';
import 'storage_visitor.dart';

/// Main analyzer for Insecure Data Storage (IDS) detection
class IDSAnalyzer {
  final InsecureStorageRulesEngine rulesEngine;

  IDSAnalyzer() : rulesEngine = InsecureStorageRulesEngine();

  /// Analyze a Dart file for insecure data storage patterns
  /// 
  /// Returns a list of [IDSIssue] objects representing detected vulnerabilities
  List<IDSIssue> analyzeFile(String filePath) {
    final file = File(filePath);
    
    if (!file.existsSync()) {
      throw FileSystemException('File not found', filePath);
    }

    // Read and parse the Dart file
    final content = file.readAsStringSync();
    final result = parseString(content: content, path: filePath);
    final unit = result.unit;

    // Run the storage visitor to detect issues
    final visitor = StorageVisitor(rulesEngine, content, filePath);
    unit.accept(visitor);

    return visitor.issues;
  }

  /// Analyze multiple files
  List<IDSIssue> analyzeFiles(List<String> filePaths) {
    final allIssues = <IDSIssue>[];
    
    for (final filePath in filePaths) {
      try {
        final issues = analyzeFile(filePath);
        allIssues.addAll(issues);
      } catch (e) {
        stderr.writeln('Error analyzing $filePath: $e');
      }
    }
    
    return allIssues;
  }

  /// Get statistics about detected issues
  Map<String, dynamic> getStatistics(List<IDSIssue> issues) {
    final severityCounts = <String, int>{};
    final dataTypeCounts = <String, int>{};
    final storageContextCounts = <String, int>{};

    for (final issue in issues) {
      severityCounts[issue.severity] = (severityCounts[issue.severity] ?? 0) + 1;
      dataTypeCounts[issue.dataType] = (dataTypeCounts[issue.dataType] ?? 0) + 1;
      storageContextCounts[issue.storageContext] = 
          (storageContextCounts[issue.storageContext] ?? 0) + 1;
    }

    return {
      'totalIssues': issues.length,
      'bySeverity': severityCounts,
      'byDataType': dataTypeCounts,
      'byStorageContext': storageContextCounts,
    };
  }
}
