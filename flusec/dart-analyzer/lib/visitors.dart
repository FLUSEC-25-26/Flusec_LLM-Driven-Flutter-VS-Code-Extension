import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';
import 'package:analyzer/source/line_info.dart';
import 'models.dart';

class InsecureStorageVisitor extends RecursiveAstVisitor<void> {
  final List<SecurityRule> rules;
  final List<Finding> findings = [];
  final String filePath;

  final LineInfo lineInfo;

  InsecureStorageVisitor(this.rules, this.filePath, this.lineInfo);

  @override
  void visitMethodInvocation(MethodInvocation node) {
    String methodName = node.methodName.name;
    String? targetName;
    
    if (node.target is SimpleIdentifier) {
      targetName = (node.target as SimpleIdentifier).name;
    }

    // Rule 1: storage.plain_shared_prefs
    if (_matchesRule1(methodName, targetName, node)) {
      _addFinding('storage.plain_shared_prefs', node);
    }

    // Rule 2: storage.plain_file_write
    if (_matchesRule2(methodName, targetName, node)) {
      _addFinding('storage.plain_file_write', node);
    }

    // Rule 3: storage.sqlite_plain
    if (_matchesRule3(methodName, targetName, node)) {
      _addFinding('storage.sqlite_plain', node);
    }

    // Rule 4: storage.external_public_dir (Method calls)
    if (_matchesRule4Method(methodName, targetName)) {
      _addFinding('storage.external_public_dir', node);
    }

    // Rule 5: storage.unprotected_cache_or_temp
    if (_matchesRule5(methodName, targetName)) {
      _addFinding('storage.unprotected_cache_or_temp', node);
    }

    // Rule 6: storage.webview_localstorage
    if (_matchesRule6(methodName, node)) {
      _addFinding('storage.webview_localstorage', node);
    }

    // Rule 7: storage.insecure_serialization
    if (_matchesRule7(methodName)) {
      _addFinding('storage.insecure_serialization', node);
    }

    // Rule 8: storage.log_secrets
    if (_matchesRule8(methodName, node)) {
      _addFinding('storage.log_secrets', node);
    }

    super.visitMethodInvocation(node);
  }

  @override
  void visitInstanceCreationExpression(InstanceCreationExpression node) {
    String typeName = node.constructorName.type.name2.lexeme;

    // Rule 2: storage.plain_file_write (File creation)
    if (typeName == 'File') {
       // Check if this file instance is used for writing later or created with sensitive path
       // For now, we flag if it looks like a write operation might happen or if path is external
    }
    
    super.visitInstanceCreationExpression(node);
  }

  @override
  void visitSimpleStringLiteral(SimpleStringLiteral node) {
    // Rule 4: storage.external_public_dir (String literals)
    if (node.value.contains('/sdcard') || node.value.contains('/storage/')) {
      _addFinding('storage.external_public_dir', node);
    }
    super.visitSimpleStringLiteral(node);
  }

  // --- Rule Matchers ---

  bool _matchesRule1(String methodName, String? targetName, MethodInvocation node) {
    // SharedPreferences.setString, setBool, etc.
    if (targetName != null && (targetName.contains('prefs') || targetName.contains('sharedPreferences'))) {
       if (methodName.startsWith('set')) {
          // Check arguments for sensitive keys
          if (node.argumentList.arguments.isNotEmpty) {
            var firstArg = node.argumentList.arguments.first;
            if (firstArg is SimpleStringLiteral) {
              return _isSensitive(firstArg.value);
            }
          }
       }
    }
    return false;
  }

  bool _matchesRule2(String methodName, String? targetName, MethodInvocation node) {
    // File.writeAsString, writeAsBytes
    if (methodName == 'writeAsString' || methodName == 'writeAsBytes' || methodName == 'writeFrom' || methodName == 'openWrite') {
      // Heuristic: if target looks like a file
      return true; 
    }
    return false;
  }

  bool _matchesRule3(String methodName, String? targetName, MethodInvocation node) {
    // sqflite: insert, rawInsert, execute
    if (methodName == 'insert' || methodName == 'rawInsert' || (methodName == 'execute' && _hasInsertSql(node))) {
      if (targetName != null && (targetName == 'db' || targetName == 'database')) {
        return true;
      }
    }
    return false;
  }

  bool _matchesRule4Method(String methodName, String? targetName) {
    // getExternalStorageDirectory
    return methodName == 'getExternalStorageDirectory' || methodName == 'getExternalStorageDirectories';
  }

  bool _matchesRule5(String methodName, String? targetName) {
    // getTemporaryDirectory
    return methodName == 'getTemporaryDirectory' || methodName == 'getApplicationSupportDirectory';
  }

  bool _matchesRule6(String methodName, MethodInvocation node) {
    // Webview: runJavascript, evaluateJavascript with localStorage
    if (methodName == 'runJavascript' || methodName == 'evaluateJavascript') {
      if (node.argumentList.arguments.isNotEmpty) {
        var arg = node.argumentList.arguments.first;
        if (arg is SimpleStringLiteral) {
          return arg.value.contains('localStorage.setItem') || arg.value.contains('sessionStorage.setItem') || arg.value.contains('document.cookie');
        }
      }
    }
    return false;
  }

  bool _matchesRule7(String methodName) {
    // jsonEncode
    return methodName == 'jsonEncode';
  }

  bool _matchesRule8(String methodName, MethodInvocation node) {
    // print, debugPrint with sensitive args
    if (methodName == 'print' || methodName == 'debugPrint') {
       if (node.argumentList.arguments.isNotEmpty) {
         // Check if arguments look sensitive
         for (var arg in node.argumentList.arguments) {
           if (arg is SimpleIdentifier && _isSensitive(arg.name)) {
             return true;
           }
           if (arg is SimpleStringLiteral && _isSensitive(arg.value)) {
             return true;
           }
         }
       }
    }
    return false;
  }

  // --- Helpers ---

  bool _isSensitive(String text) {
    var lower = text.toLowerCase();
    var sensitiveKeywords = ['token', 'auth', 'password', 'secret', 'apikey', 'api_key', 'accesstoken', 'refreshtoken'];
    return sensitiveKeywords.any((k) => lower.contains(k));
  }

  bool _hasInsertSql(MethodInvocation node) {
    if (node.argumentList.arguments.isNotEmpty) {
      var arg = node.argumentList.arguments.first;
      if (arg is SimpleStringLiteral) {
        return arg.value.toUpperCase().contains('INSERT INTO');
      }
    }
    return false;
  }

  void _addFinding(String ruleId, AstNode node) {
    var rule = rules.firstWhere((r) => r.id == ruleId, orElse: () => SecurityRule(id: ruleId, description: 'Unknown', severity: 'LOW', category: 'Unknown', remediation: '', patterns: []));
    
    // Avoid duplicates for same node
    if (findings.any((f) => f.lineNumber == node.offset && f.ruleId == ruleId)) return;

    var location = lineInfo.getLocation(node.offset);
    
    findings.add(Finding(
      ruleId: rule.id,
      message: rule.description,
      severity: rule.severity,
      filePath: filePath,
      lineNumber: location.lineNumber,
      columnNumber: location.columnNumber,
      codeSnippet: node.toSource(),
      remediation: rule.remediation,
    ));
  }
}
