import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';
import '../core/issue.dart';

class CohesionVisitor extends RecursiveAstVisitor<void> {
  final String filePath;
  final List<Issue> issues = [];

  CohesionVisitor(this.filePath);

  @override
  void visitClassDeclaration(ClassDeclaration node) {
    final className = node.name.lexeme;
    final classFields = <String>{};
    final methodFieldAccess = <String, Set<String>>{};

    // 1. Collect all instance fields (variables) in the class
    for (var member in node.members) {
      if (member is FieldDeclaration && !member.isStatic) {
        for (var variable in member.fields.variables) {
          classFields.add(variable.name.lexeme);
        }
      }
    }

    // 2. Collect all methods and find out which fields they touch
    for (var member in node.members) {
      if (member is MethodDeclaration &&
          !member.isStatic &&
          !member.isGetter &&
          !member.isSetter) {
        final methodName = member.name.lexeme;
        methodFieldAccess[methodName] = {};

        // Use a sub-visitor to walk through the method's code body
        member.body.accept(
          _FieldAccessVisitor(classFields, methodFieldAccess[methodName]!),
        );
      }
    }

    // 3. Cohesion Logic: Are there too many methods ignoring the class state?
    // We only evaluate classes that have a meaningful amount of logic (e.g., 3+ methods, 1+ fields)
    if (classFields.isNotEmpty && methodFieldAccess.length >= 3) {
      int disconnectedMethods = 0;

      for (var accessSet in methodFieldAccess.values) {
        if (accessSet.isEmpty) {
          disconnectedMethods++;
        }
      }

      // Metric Threshold: If more than 50% of methods don't use ANY class variables, cohesion is low.
      if (disconnectedMethods > (methodFieldAccess.length / 2)) {
        final unit = node.root as CompilationUnit;
        final loc = unit.lineInfo.getLocation(node.offset);

        issues.add(
          Issue(
            filePath,
            'FLUSEC.ARC.COHESION', // ARC = Architecture rule
            'Low Cohesion: $disconnectedMethods out of ${methodFieldAccess.length} methods in "$className" do not interact with any class variables. Consider splitting this class or making these methods static/external.',
            'warning',
            loc.lineNumber,
            loc.columnNumber,
            functionName: className,
          ),
        );
      }
    }

    super.visitClassDeclaration(node);
  }
}

/// A private helper visitor that looks for variable usage inside a method body.
class _FieldAccessVisitor extends RecursiveAstVisitor<void> {
  final Set<String> classFields;
  final Set<String> accessedFields;

  _FieldAccessVisitor(this.classFields, this.accessedFields);

  @override
  void visitSimpleIdentifier(SimpleIdentifier node) {
    // If the identifier matches a class field name, record that it was accessed
    if (classFields.contains(node.name)) {
      accessedFields.add(node.name);
    }
    super.visitSimpleIdentifier(node);
  }
}
