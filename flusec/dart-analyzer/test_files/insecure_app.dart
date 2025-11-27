import 'dart:io';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:sqflite/sqflite.dart';
import 'package:path_provider/path_provider.dart';
import 'dart:convert';

void main() async {
  // Rule 1: storage.plain_shared_prefs
  final prefs = await SharedPreferences.getInstance();
  prefs.setString('authToken', 'secret_token_123');
  prefs.setString('password', '123456');

 /* // Rule 2: storage.plain_file_write
  final file = File('secrets.txt');
  await file.writeAsString('my secret data');

  // Rule 3: storage.sqlite_plain
  var db = await openDatabase('my_db.db');
  await db.insert('users', {'username': 'admin', 'password': 'password123'});
  await db.execute("INSERT INTO users (name, password) VALUES ('admin', '123456')");

  // Rule 4: storage.external_public_dir
  var extDir = await getExternalStorageDirectory();
  var sdCardFile = File('/sdcard/backup.txt');

  // Rule 5: storage.unprotected_cache_or_temp
  var tempDir = await getTemporaryDirectory();

  // Rule 6: storage.webview_localstorage
  // Mocking WebView controller call
  var controller;
  controller.runJavascript("localStorage.setItem('token', '123')");

  // Rule 7: storage.insecure_serialization
  var data = {'password': '123'};
  var json = jsonEncode(data);

  // Rule 8: storage.log_secrets
  print('User password is: 123456');
  debugPrint('Auth token: abcdef');  */
}
