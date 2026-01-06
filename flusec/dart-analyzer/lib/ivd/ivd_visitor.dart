import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';
import '../core/issue.dart';

class IvdVisitor extends RecursiveAstVisitor<void> {
  final String filePath;
  final List<Issue> issues = [];

  IvdVisitor(this.filePath);

  void _addIssue(AstNode node, String id, String severity, String msg) {
    // Get line number safely
    final unit = node.root as CompilationUnit;
    final loc = unit.lineInfo.getLocation(node.offset);

    issues.add(
      Issue(
        filePath,
        id,
        msg,
        severity,
        loc.lineNumber,
        loc.columnNumber,
        functionName: _getEnclosingFunctionName(node),
        // We leave complexity null for IVD to keep it simple for now,
        // or you can import the Complexity calculator from HSD if you want.
      ),
    );
  }

  String? _getEnclosingFunctionName(AstNode node) {
    AstNode? current = node;
    while (current != null) {
      if (current is FunctionDeclaration) return current.name.lexeme;
      if (current is MethodDeclaration) return current.name.lexeme;
      current = current.parent;
    }
    return null;
  }

  @override
  void visitMethodInvocation(MethodInvocation node) {
    final methodName = node.methodName.name;

    // --- 1. SQL Injection ---
    // Detects: rawQuery("SELECT * FROM $userInput");
    const sqlMethods = [
      'rawQuery',
      'execute',
      'rawInsert',
      'rawUpdate',
      'rawDelete',
    ];
    if (sqlMethods.contains(methodName)) {
      if (node.argumentList.arguments.isNotEmpty) {
        final arg = node.argumentList.arguments.first;
        // Check if the SQL string uses interpolation (variables inside string)
        if (arg is StringInterpolation) {
          _addIssue(
            node,
            'FLUSEC.IVD.SQLI',
            'critical',
            'Potential SQL Injection: Avoid String interpolation in $methodName. Use parameterized queries (e.g. "?") to prevent exploitation.',
          );
        }
      }
    }

    // --- 2. Command Injection ---
    // Detects: Process.run(userInput, []);
    if ((methodName == 'run' ||
            methodName == 'start' ||
            methodName == 'runSync') &&
        node.target.toString() == 'Process') {
      // If the first argument is a simple variable (Identifier), it's risky
      if (node.argumentList.arguments.isNotEmpty) {
        final arg = node.argumentList.arguments.first;
        if (arg is SimpleIdentifier || arg is StringInterpolation) {
          _addIssue(
            node,
            'FLUSEC.IVD.CMD_INJECT',
            'critical',
            'Potential Command Injection: User input passed directly to system shell via Process.$methodName.',
          );
        }
      }
    }

    // --- 3. Unsafe File Uploads ---
    // Detects: FilePicker.platform.pickFiles() without allowedExtensions
    if (methodName == 'pickFiles' && node.toString().contains('FilePicker')) {
      bool hasAllowedExtensions = node.argumentList.arguments.any(
        (arg) =>
            arg is NamedExpression &&
            arg.name.label.name == 'allowedExtensions',
      );

      if (!hasAllowedExtensions) {
        _addIssue(
          node,
          'FLUSEC.IVD.UNSAFE_UPLOAD',
          'high',
          'Unsafe File Upload: FilePicker used without "allowedExtensions". Limit file types to prevent malicious code execution.',
        );
      }
    }

    // --- 4. Deep-Link Poisoning ---
    // Detects usage of UniLinks or getInitialUri without validation context
    if (['getInitialUri', 'uriLinkStream'].contains(methodName)) {
      _addIssue(
        node,
        'FLUSEC.IVD.DEEP_LINK',
        'high',
        'Deep Link Entry Point: Ensure the URI returned by $methodName is validated (host/scheme check) before usage to prevent poisoning.',
      );
    }

    super.visitMethodInvocation(node);
  }

  @override
  void visitInstanceCreationExpression(InstanceCreationExpression node) {
    final typeName = node.constructorName.type.name.lexeme;

    // --- 5. Invalid Form Validation ---
    // Detects: TextFormField() without a validator property
    if (typeName == 'TextFormField') {
      bool hasValidator = node.argumentList.arguments.any(
        (arg) => arg is NamedExpression && arg.name.label.name == 'validator',
      );

      if (!hasValidator) {
        _addIssue(
          node,
          'FLUSEC.IVD.NO_VALIDATOR',
          'medium',
          'Missing Form Validation: TextFormField created without a "validator". User input could be malicious or malformed.',
        );
      }
    }

    super.visitInstanceCreationExpression(node);
  }
}
