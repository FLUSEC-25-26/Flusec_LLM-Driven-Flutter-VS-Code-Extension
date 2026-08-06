import 'dart:convert';
import 'dart:io';

import 'package:analyzer/dart/analysis/utilities.dart';
import 'package:dart_analyzer/core/issue.dart';
import 'package:dart_analyzer/ids/ids_rules.dart';
import 'package:dart_analyzer/ids/storage_visitor.dart';
import 'package:test/test.dart';

IdsRulesEngine _loadRules() {
  final file = File('data/insecure_data_storage_rules.json');
  final raw = jsonDecode(file.readAsStringSync()) as List<dynamic>;
  final rules = raw
      .whereType<Map>()
      .map((item) => item.cast<String, dynamic>())
      .toList();

  return IdsRulesEngine()..loadRules(rules);
}

List<Issue> _analyze(String source) {
  final result = parseString(content: source, path: 'ids_test_case.dart');
  final visitor = StorageVisitor(
    result.unit,
    source,
    'ids_test_case.dart',
    _loadRules(),
  );
  result.unit.accept(visitor);
  return visitor.issues;
}

bool _hasRule(List<Issue> issues, String ruleId) {
  return issues.any((issue) => issue.ruleId == ruleId);
}

void main() {
  group('HSD and IDS boundary', () {
    test('does not report a hardcoded secret when there is no storage sink', () {
      final issues = _analyze(r'''
const apiSecret = 'development-value';
''');

      expect(issues, isEmpty);
    });
  });

  group('SharedPreferences', () {
    test('reports a runtime access token stored in SharedPreferences', () {
      final issues = _analyze(r'''
import 'package:shared_preferences/shared_preferences.dart';
Future<void> save(SharedPreferences prefs, String accessToken) async {
  await prefs.setString('session', accessToken);
}
''');

      expect(_hasRule(issues, 'FLUSEC.IDS.001'), isTrue);
    });

    test('does not report an ordinary theme preference', () {
      final issues = _analyze(r'''
import 'package:shared_preferences/shared_preferences.dart';
Future<void> save(SharedPreferences prefs, bool darkMode) async {
  await prefs.setBool('dark_mode', darkMode);
}
''');

      expect(_hasRule(issues, 'FLUSEC.IDS.001'), isFalse);
    });

    test('does not report an encrypted value', () {
      final issues = _analyze(r'''
import 'package:shared_preferences/shared_preferences.dart';
Future<void> save(SharedPreferences prefs, String accessToken) async {
  final encryptedValue = encrypt(accessToken);
  await prefs.setString('session', encryptedValue);
}
''');

      expect(_hasRule(issues, 'FLUSEC.IDS.001'), isFalse);
    });
  });

  group('File storage', () {
    test('reports sensitive data written to an ordinary file', () {
      final issues = _analyze(r'''
import 'dart:io';
Future<void> save(File file, String password) async {
  await file.writeAsString(password);
}
''');

      expect(_hasRule(issues, 'FLUSEC.IDS.002'), isTrue);
    });

    test('does not report ordinary file content', () {
      final issues = _analyze(r'''
import 'dart:io';
Future<void> save(File file, String applicationVersion) async {
  await file.writeAsString(applicationVersion);
}
''');

      expect(_hasRule(issues, 'FLUSEC.IDS.002'), isFalse);
    });

    test('reports serialized credentials only when written to storage', () {
      final issues = _analyze(r'''
import 'dart:convert';
import 'dart:io';
Future<void> save(File file, Map<String, dynamic> credentials) async {
  final serializedCredentials = jsonEncode(credentials);
  await file.writeAsString(serializedCredentials);
}
''');

      expect(_hasRule(issues, 'FLUSEC.IDS.002'), isTrue);
    });
  });

  group('External and cache storage', () {
    test('does not report external-directory retrieval by itself', () {
      final issues = _analyze(r'''
Future<void> prepare() async {
  final externalDirectory = await getExternalStorageDirectory();
  print(externalDirectory);
}
''');

      expect(_hasRule(issues, 'FLUSEC.IDS.004'), isFalse);
    });

    test('reports sensitive data written to external storage', () {
      final issues = _analyze(r'''
import 'dart:io';
Future<void> save(String accessToken) async {
  final externalDirectory = await getExternalStorageDirectory();
  final tokenFile = File('${externalDirectory.path}/session.txt');
  await tokenFile.writeAsString(accessToken);
}
''');

      expect(_hasRule(issues, 'FLUSEC.IDS.004'), isTrue);
    });

    test('reports sensitive data written to temporary storage', () {
      final issues = _analyze(r'''
import 'dart:io';
Future<void> save(String medicalRecord) async {
  final tempDirectory = await getTemporaryDirectory();
  final cacheFile = File('${tempDirectory.path}/record.txt');
  await cacheFile.writeAsString(medicalRecord);
}
''');

      expect(_hasRule(issues, 'FLUSEC.IDS.005'), isTrue);
    });
  });

  group('SQLite', () {
    test('reports credentials inserted into SQLite', () {
      final issues = _analyze(r'''
import 'package:sqflite/sqflite.dart';
Future<void> save(Database db, String password) async {
  await db.insert('users', {'password': password});
}
''');

      expect(_hasRule(issues, 'FLUSEC.IDS.003'), isTrue);
    });

    test('does not report non-sensitive application data', () {
      final issues = _analyze(r'''
import 'package:sqflite/sqflite.dart';
Future<void> save(Database db, String productTitle) async {
  await db.insert('products', {'title': productTitle});
}
''');

      expect(_hasRule(issues, 'FLUSEC.IDS.003'), isFalse);
    });
  });

  group('WebView browser storage', () {
    test('reports a token written to localStorage', () {
      final issues = _analyze(r'''
Future<void> save(dynamic controller, String accessToken) async {
  await controller.runJavascript(
    "localStorage.setItem('session', '$accessToken')",
  );
}
''');

      expect(_hasRule(issues, 'FLUSEC.IDS.006'), isTrue);
    });

    test('does not report a non-sensitive UI preference', () {
      final issues = _analyze(r'''
Future<void> save(dynamic controller, String theme) async {
  await controller.runJavascript(
    "localStorage.setItem('theme', '$theme')",
  );
}
''');

      expect(_hasRule(issues, 'FLUSEC.IDS.006'), isFalse);
    });
  });
}
