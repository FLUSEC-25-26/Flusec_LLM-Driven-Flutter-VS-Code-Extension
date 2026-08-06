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

    // 1. Collect all non-static instance fields in the class.
    for (final member in node.members) {
      if (member is FieldDeclaration && !member.isStatic) {
        for (final variable in member.fields.variables) {
          classFields.add(variable.name.lexeme);
        }
      }
    }

    // 2. Collect all non-static, non-getter, non-setter methods
    //    and record which class fields each method touches.
    for (final member in node.members) {
      if (member is MethodDeclaration &&
          !member.isStatic &&
          !member.isGetter &&
          !member.isSetter) {
        final methodName = member.name.lexeme;
        methodFieldAccess[methodName] = <String>{};

        member.body.accept(
          _FieldAccessVisitor(classFields, methodFieldAccess[methodName]!),
        );
      }
    }

    // 3. Cohesion rule:
    //    Only evaluate classes with at least 1 field and at least 3 methods.
    //    If more than 50% of methods do not touch any class fields,
    //    report low cohesion.
    if (classFields.isNotEmpty && methodFieldAccess.length >= 3) {
      int disconnectedMethods = 0;

      for (final accessedFields in methodFieldAccess.values) {
        if (accessedFields.isEmpty) {
          disconnectedMethods++;
        }
      }

      if (disconnectedMethods > (methodFieldAccess.length / 2)) {
        final unit = node.root as CompilationUnit;
        final loc = unit.lineInfo.getLocation(node.offset);

        issues.add(
          Issue(
            filePath,
            'FLUSEC.IIV.COHESION',
            'Low Cohesion: $disconnectedMethods out of ${methodFieldAccess.length} methods in "$className" do not interact with any class variables. Consider splitting this class or making unrelated methods static/external.',
            'warning',
            loc.lineNumber,
            loc.columnNumber,
            functionName: className,
            component: 'iiv',
          ),
        );
      }
    }

    super.visitClassDeclaration(node);
  }
}

class _FieldAccessVisitor extends RecursiveAstVisitor<void> {
  final Set<String> classFields;
  final Set<String> accessedFields;

  _FieldAccessVisitor(this.classFields, this.accessedFields);

  @override
  void visitSimpleIdentifier(SimpleIdentifier node) {
    if (classFields.contains(node.name)) {
      accessedFields.add(node.name);
    }
    super.visitSimpleIdentifier(node);
  }
}
