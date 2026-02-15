
// lib/net/url_utils.dart
import 'package:analyzer/dart/ast/ast.dart';

class UrlUtils {
  static String? extractFirstStringArg(NodeList<Expression> args) {
    for (final a in args) {
      if (a is SimpleStringLiteral) return a.value;
      if (a is StringInterpolation) {
        final buf = StringBuffer();
        for (final e in a.elements) {
          if (e is InterpolationString) {
            buf.write(e.value);
          } else {
            return null; // dynamic part → skip
          }
        }
        final s = buf.toString();
        if (s.isNotEmpty) return s;
      }
    }
    return null;
  }
}