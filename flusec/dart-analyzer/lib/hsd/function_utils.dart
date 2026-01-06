// lib/hsd/function_utils.dart
//
// Helpers to find the enclosing function/method/constructor around a node.
// This is part of YOUR feature (context for secrets), so it stays inside hsd/.

import 'package:analyzer/dart/ast/ast.dart';

class FunctionUtils {
  /// Find the enclosing function / method / constructor / function expression (lambda).
  static AstNode? enclosingExecutable(AstNode node) {
    AstNode? current = node;
    while (current != null) {
      if (current is FunctionDeclaration ||
          current is MethodDeclaration ||
          current is ConstructorDeclaration ||
          current is FunctionExpression) {
        return current;
      }
      current = current.parent;
    }
    return null;
  }

  /// Human-readable name for an executable node.
  static String executableName(AstNode exec) {
  // Normal named functions / methods / ctors
  if (exec is FunctionDeclaration) {
    return exec.name.lexeme;
  }
  if (exec is MethodDeclaration) {
    return exec.name.lexeme;
  }
  if (exec is ConstructorDeclaration) {
    final typeName = exec.returnType?.toSource() ?? '';
    final ctorName = exec.name?.lexeme ?? '';
    return ctorName.isEmpty ? typeName : '$typeName.$ctorName';
  }

  // Handle the common case where we actually get the FunctionExpression
  // that belongs to a named declaration like:
  //   void cx1_simple() { ... }
  if (exec is FunctionExpression) {
    final parent = exec.parent;
    if (parent is FunctionDeclaration) {
      return parent.name.lexeme;
    }
    if (parent is MethodDeclaration) {
      return parent.name.lexeme;
    }
    if (parent is ConstructorDeclaration) {
      final typeName = parent.returnType?.toSource() ?? '';
      final ctorName = parent.name?.lexeme ?? '';
      return ctorName.isEmpty ? typeName : '$typeName.$ctorName';
    }
  }

  // Truly anonymous functions / lambdas
   return '<anonymous>';
  }
}
