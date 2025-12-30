import 'dart:io';
import 'dart:convert';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:sqflite/sqflite.dart';
import 'package:path_provider/path_provider.dart';

void main() async {
  // Rule 1: storage.plain_shared_prefs (IDS-001)
  final prefs = await SharedPreferences.getInstance();
  prefs.setString('authToken', 'secret_token_123');
  prefs.setString('password', '123456');
  prefs.setString('api_key', 'sk_live_abc123xyz');

  // Rule 2: storage.plain_file_write (IDS-002)
  final file = File('secrets.txt');
  await file.writeAsString('my secret data');
  final passwordFile = File('user_password.txt');
  await passwordFile.writeAsBytes([1, 2, 3]);

  // Rule 3: storage.sqlite_plain (IDS-003)
  var db = await openDatabase('my_db.db');
  await db.insert('users', {'username': 'admin', 'password': 'password123'});
  await db.execute("INSERT INTO users (name, password) VALUES ('admin', '123456')");
  await db.rawInsert("INSERT INTO credentials (token) VALUES ('secret_token')");

  // Rule 4: storage.external_public_dir (IDS-004)
  var extDir = await getExternalStorageDirectory();
  var sdCardFile = File('/sdcard/backup.txt');
  await sdCardFile.writeAsString('sensitive user data');

  // Rule 5: storage.unprotected_cache_or_temp (IDS-005)
  var tempDir = await getTemporaryDirectory();
  var tempFile = File('${tempDir.path}/auth_token.tmp');
  await tempFile.writeAsString('bearer_token_xyz');

  // Rule 6: storage.webview_localstorage (IDS-006)
  // Mocking WebView controller call
  var controller;
  controller.runJavascript("localStorage.setItem('token', '123')");
  controller.evaluateJavascript("sessionStorage.setItem('password', 'secret')");
  controller.runJavascript("document.cookie = 'auth=xyz123'");

  // Rule 7: storage.insecure_serialization (IDS-007)
  var userData = {'password': '123', 'creditCard': '4111111111111111'};
  var json = jsonEncode(userData);
  await File('user_data.json').writeAsString(json);

  // Rule 8: storage.log_secrets (IDS-008)
  print('User password is: 123456');
  debugPrint('Auth token: abcdef');
  var apiKey = 'sk_live_secret123';
  print('API Key: $apiKey');

  // Rule 9: storage.unprotected_backup (IDS-009)
  var backupFile = File('backup.db');
  await backupFile.copy('/sdcard/app_backup.db');
  var exportData = {'users': [], 'passwords': []};
  await File('export.json').writeAsString(jsonEncode(exportData));
}
