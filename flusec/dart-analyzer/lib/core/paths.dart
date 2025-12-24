// lib/core/paths.dart
//
// Handles locating rule JSON files in a way that works in:
// 1) Local development (running analyzer in this project root)
// 2) Packaged VS Code extension (exe sits elsewhere)
//
// We keep this in core because every future component will likely have its own
// rules JSON file (network/storage/validation/etc.) and the path logic is shared.

import 'dart:io';
import 'package:path/path.dart' as path;

class RulesPathResolver {
  /// Resolve a rules file that lives under "data/" in either:
  /// - current working directory
  /// - alongside the compiled script/exe (bin/../data)
  ///
  /// Example fileName: "hardcoded_secrets_rules.json"
  static File resolveRulesFile(String fileName) {
    // Local project run: <cwd>/data/<fileName>
    final currentDir = Directory.current.path;
    final localRules = File(path.join(currentDir, 'data', fileName));

    // Packaged/installed run: <scriptDir>/../data/<fileName>
    final extensionRules = File(path.join(
      path.dirname(Platform.script.toFilePath()),
      '..',
      'data',
      fileName,
    ));

    return localRules.existsSync() ? localRules : extensionRules;
  }
}