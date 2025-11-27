import 'dart:io';
import 'dart:convert';
import 'package:dart_analyzer/engine.dart';
import 'package:dart_analyzer/models.dart';

void main(List<String> arguments) {
  if (arguments.isEmpty) {
    print('Usage: analyzer <file_path>');
    exit(1);
  }

  String filePath = arguments[0];
  var analyzer = SecurityAnalyzer();
  List<Finding> findings = analyzer.analyzeFile(filePath);

  var jsonOutput = jsonEncode(findings.map((f) => f.toJson()).toList());
  print(jsonOutput);
}
