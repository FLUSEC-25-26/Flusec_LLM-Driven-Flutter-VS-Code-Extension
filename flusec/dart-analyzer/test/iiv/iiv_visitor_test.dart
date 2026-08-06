import 'dart:convert';
import 'dart:io';

import 'package:analyzer/dart/analysis/utilities.dart';
import 'package:dart_analyzer/core/issue.dart';
import 'package:dart_analyzer/iiv/iiv_rules.dart';
import 'package:dart_analyzer/iiv/iiv_visitor.dart';
import 'package:test/test.dart';

IivRulesEngine _loadRules() {
  final file = File('data/input_validation_rules.json');
  final raw = jsonDecode(file.readAsStringSync()) as List<dynamic>;
  final rules = raw
      .whereType<Map>()
      .map((item) => item.cast<String, dynamic>())
      .toList();

  return IivRulesEngine()..loadRules(rules);
}

List<Issue> _analyze(String source) {
  final result = parseString(content: source, path: 'test_case.dart');
  final visitor = IivVisitor(result.unit, 'test_case.dart', _loadRules());
  result.unit.accept(visitor);
  return visitor.issues;
}

bool _hasRule(List<Issue> issues, String ruleId) {
  return issues.any((issue) => issue.ruleId == ruleId);
}

void main() {
  group('SQL injection', () {
    test('detects direct interpolation', () {
      final issues = _analyze(r'''
Future<void> load(dynamic db, String userInput) async {
  await db.rawQuery("SELECT * FROM users WHERE id = '$userInput'");
}
''');

      expect(_hasRule(issues, 'FLUSEC.IIV.001'), isTrue);
    });

    test('detects a locally constructed dynamic query', () {
      final issues = _analyze(r'''
Future<void> load(dynamic db, String userInput) async {
  final query = "SELECT * FROM users WHERE id = '$userInput'";
  await db.rawQuery(query);
}
''');

      expect(_hasRule(issues, 'FLUSEC.IIV.001'), isTrue);
    });

    test('does not report a parameterized query', () {
      final issues = _analyze(r'''
Future<void> load(dynamic db, String userInput) async {
  await db.rawQuery(
    'SELECT * FROM users WHERE id = ?',
    [userInput],
  );
}
''');

      expect(_hasRule(issues, 'FLUSEC.IIV.001'), isFalse);
    });
  });

  group('Command injection', () {
    test('does not report fixed executable and fixed arguments', () {
      final issues = _analyze(r'''
Future<void> runTool() async {
  await Process.run('git', ['status']);
}
''');

      expect(_hasRule(issues, 'FLUSEC.IIV.002'), isFalse);
    });

    test('reports runtime-controlled process arguments', () {
      final issues = _analyze(r'''
Future<void> runTool(String userInput) async {
  await Process.run('tool', [userInput]);
}
''');

      expect(_hasRule(issues, 'FLUSEC.IIV.002'), isTrue);
    });
  });

  group('File selection', () {
    test('reports unrestricted pickFiles', () {
      final issues = _analyze(r'''
Future<void> selectFile(dynamic picker) async {
  await picker.pickFiles();
}
''');

      expect(_hasRule(issues, 'FLUSEC.IIV.003'), isTrue);
    });

    test('does not report custom type with extension allow-list', () {
      final issues = _analyze(r'''
Future<void> selectFile(dynamic picker) async {
  await picker.pickFiles(
    type: FileType.custom,
    allowedExtensions: ['pdf'],
  );
}
''');

      expect(_hasRule(issues, 'FLUSEC.IIV.003'), isFalse);
    });
  });

  group('Deep links', () {
    test('does not report a source call by itself', () {
      final issues = _analyze(r'''
Future<void> readLink(dynamic links) async {
  final uri = await links.getInitialUri();
  print(uri);
}
''');

      expect(_hasRule(issues, 'FLUSEC.IIV.004'), isFalse);
    });

    test('reports deep-link value sent to URL sink without validation', () {
      final issues = _analyze(r'''
Future<void> openLink(dynamic links) async {
  final uri = await links.getInitialUri();
  await launchUrl(uri);
}
''');

      expect(_hasRule(issues, 'FLUSEC.IIV.004'), isTrue);
    });

    test('does not report a guarded deep-link sink', () {
      final issues = _analyze(r'''
Future<void> openLink(dynamic links) async {
  final uri = await links.getInitialUri();
  if (uri != null && uri.scheme == 'https' && uri.host == 'example.com') {
    await launchUrl(uri);
  }
}
''');

      expect(_hasRule(issues, 'FLUSEC.IIV.004'), isFalse);
    });
  });

  group('TextFormField', () {
    test('reports editable TextFormField without validator', () {
      final issues = _analyze(r'''
Widget build() {
  return TextFormField(
    controller: controller,
  );
}
''');

      expect(_hasRule(issues, 'FLUSEC.IIV.005'), isTrue);
    });

    test('does not report TextFormField with validator', () {
      final issues = _analyze(r'''
Widget build() {
  return TextFormField(
    validator: (value) => value == null || value.isEmpty ? 'Required' : null,
  );
}
''');

      expect(_hasRule(issues, 'FLUSEC.IIV.005'), isFalse);
    });

    test('does not report read-only TextFormField', () {
      final issues = _analyze(r'''
Widget build() {
  return TextFormField(
    readOnly: true,
  );
}
''');

      expect(_hasRule(issues, 'FLUSEC.IIV.005'), isFalse);
    });
  });
}
