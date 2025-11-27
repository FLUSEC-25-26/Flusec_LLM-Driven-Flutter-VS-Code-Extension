import 'dart:io';
import 'dart:convert';
import 'package:analyzer/dart/analysis/utilities.dart';
import 'package:analyzer/dart/ast/ast.dart';
import 'package:path/path.dart' as path;
import 'models.dart';
import 'visitors.dart';

class SecurityAnalyzer {
  List<SecurityRule> rules = [];

  SecurityAnalyzer() {
    _loadRules();
  }

  void _loadRules() {
    // In a real app, this might load from a file relative to the executable
    // For now, we will try to load from 'data/insecure_storage_rules.json'
    // relative to the script or current directory.
    
    // Assuming the data folder is in the same directory as the executable or project root
    var rulesFile = File('data/insecure_storage_rules.json');
    if (!rulesFile.existsSync()) {
      // Try looking up one level (if running from bin/)
      rulesFile = File('../data/insecure_storage_rules.json');
    }

    if (rulesFile.existsSync()) {
      var jsonContent = rulesFile.readAsStringSync();
      var jsonList = jsonDecode(jsonContent) as List;
      rules = jsonList.map((j) => SecurityRule.fromJson(j)).toList();
    } else {
      print('Warning: Rules file not found.');
    }
  }

  List<Finding> analyzeFile(String filePath) {
    var file = File(filePath);
    if (!file.existsSync()) {
      return [];
    }

    var result = parseString(content: file.readAsStringSync());
    var unit = result.unit;
    var lineInfo = result.lineInfo;

    var visitor = InsecureStorageVisitor(rules, filePath, lineInfo);
    unit.visitChildren(visitor);

    return visitor.findings;
  }
}
