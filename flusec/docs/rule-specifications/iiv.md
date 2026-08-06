# FLUSEC IIV Rule Specification — Phase 1

## Purpose

This document defines the first production-oriented revision of the Insufficient Input Validation detector. The implementation remains syntax-based with lightweight same-function evidence tracking. It must not be described as complete interprocedural taint analysis.

## Common output fields

- `severity`: VS Code diagnostic presentation level.
- `securitySeverity`: potential security impact if the finding is valid.
- `confidence`: certainty that the detected pattern represents a real issue.
- `category`: `vulnerability` or `secure_coding`.
- `evidence`: structured detector evidence used by dashboards and later scoring.

## FLUSEC.IIV.001 — Dynamic SQL Query Construction

**Positive evidence**

- Dynamic string interpolation, concatenation, or a local variable containing a dynamic query.
- Query is passed to a raw SQL method.
- No separate bind-argument list is present.

**Secure negative evidence**

- Constant SQL with placeholders.
- Separate bind-argument list.

**Current limitation**

- Local-expression tracking only.
- Does not follow values through helper methods, fields, collections, or files.

## FLUSEC.IIV.002 — Dynamic Process Execution

**Positive evidence**

- Runtime-controlled executable or argument passed to `Process.run`, `Process.start`, or `Process.runSync`.

**Secure negative evidence**

- Fixed executable and fixed literal arguments.

**Current limitation**

- A dynamic value is suspicious but is not proof that it is attacker-controlled.
- Allow-list validation in a separate helper method may not be recognized.

## FLUSEC.IIV.003 — Unrestricted File Selection

**Positive evidence**

- `FilePicker.pickFiles` uses the default `FileType.any` or `FileType.custom` without a non-empty `allowedExtensions` list.

**Secure negative evidence**

- `FileType.custom` with an extension allow-list.
- Media-specific `FileType.image`, `FileType.video`, `FileType.audio`, or `FileType.media`.

**Important interpretation**

This is a secure-coding warning. File selection is not itself a file upload vulnerability. The application must still validate MIME type, file signature, size, destination, and processing behavior.

## FLUSEC.IIV.004 — Unvalidated Deep Link Flow

**Positive evidence**

- A configured deep-link source is assigned to a local variable.
- The variable reaches a configured navigation or URL-opening sink.
- No recognized validation guard surrounds the sink.

**Secure negative evidence**

- The deep-link source is only read or logged.
- The sink is guarded by recognized scheme, host, path, or allow-list checks.

**Current limitation**

- Same-function tracking only.
- Validation performed earlier through complex helper logic may not be recognized.

## FLUSEC.IIV.005 — Missing TextFormField Validator

**Positive evidence**

- Editable `TextFormField` without a `validator` named argument.

**Secure negative evidence**

- `validator` is present.
- `readOnly: true`.
- `enabled: false`.

**Important interpretation**

This is a low-severity secure-coding warning, not proof of exploitable input validation failure. Validation may be implemented at form submission, service, or server level.

## Removed from the IIV security count

Low cohesion is a maintainability metric. It is no longer included in IIV vulnerability totals. The existing `cohesion_visitor.dart` file may remain temporarily, but `analyzer.dart` no longer runs it under IIV.
