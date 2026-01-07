# FLUSEC – LLM-Driven Flutter Security Extension for VS Code

**FLUSEC** is a VS Code extension that performs **static security analysis** on Flutter/Dart projects.
It detects multiple classes of security vulnerabilities and provides **educational, privacy-preserving guidance** powered by a **local LLM** (via Ollama or compatible runtimes).

---

## ⚙️ Features

FLUSECc currently includes **four specialized detection advisors**, each targeting a major mobile-app security risk area:

| Module                                               | Description                                                                                                                                                                                                                                                                                    |
| ---------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 🔐 **Hardcoded Secrets Advisor (HSD)**               | Detects API keys, tokens, credentials and sensitive constants embedded in source code using **AST-analysis, regex heuristics, and entropy scoring**, enriched with **context indicators such as complexity, nesting depth, and code size** to estimate maintainability and remediation effort. |
| 🌐 **Secure Network Communication Advisor (SNC)**    | Identifies insecure HTTP usage, weak TLS validation, plaintext transmission patterns, and risky SSL overrides using **pattern-driven and structural analysis with contextual insights**.                                                                                                       |
| 💾 **Secure Data Storage Advisor (SDS)**             | Detects storage of sensitive data in plaintext, improper key handling, and weak storage decisions across preferences, files and local storage APIs — supported by **code-context awareness**.                                                                                                  |
| 🧮 **Input Validation & Sanitization Advisor (IVS)** | Flags missing or weak input validation that can cause logic flaws or injection risks, combining **rules + AST reasoning + contextual metadata**.                                                                                                                                               |

Each advisor supports:

 **AST-based static analysis (Dart Analyzer runtime)**
 **Heuristic & pattern-driven rule detection**
 **Context-aware metadata (complexity, nesting, size, etc.)**
 **Local-LLM-powered educational guidance (privacy-preserving)**

---

## 🧩 Architecture Overview

FluSec follows a **hybrid detection + local-LLM explanation model**:

1. **VS Code Extension (TypeScript)**
   – Handles UI, commands, diagnostics & LLM prompts
2. **Dart Analyzer Runtime**
   – Performs AST + heuristic static analysis deterministically
3. **Result Processing Layer**
   – Outputs structured JSON
4. **Developer Feedback Layer**
   – Diagnostics panel + interactive dashboard + hover help

```
VS Code → extension.ts
          │
          ▼
   analyzer.exe (Dart)
          │
          ▼
   findings.json
          │
          ├── Problems Panel (Diagnostics)
          └── Dashboard (webview)
```

### 🖼 System Architecture Diagram (Temporary Path)


![System Architecture](assets/sys_archi.png)



> Replace later with the final diagram file.

---

## 📁 Folder Structure

```
flusec/
├── dart-analyzer/
│   ├── bin/
│   │   ├── analyzer.dart
│   │   └── analyzer.exe
│   ├── lib/
│   │   └── rules.dart
│   ├── data/
│   │   └── rules.json
│   └── pubspec.yaml
│
├── src/
│   ├── extension.ts
│   ├── llm.ts
│   ├── diagnostics.ts
│   ├── features/
│   │   ├── hardcoded_secrets.ts
│   │   ├── insecure_network.ts
│   │   ├── insecure_storage.ts
│   │   └── input_validation.ts
│   └── ui/
│       ├── ruleManager/
│       └── web/
│           └── dashboard.html
│
├── web/
│   └── dashboard.html
│
├── assets/
│   ├── architecture/
│   │   └── flusec-system-architecture.png   # placeholder
│   └── ui/
│       ├── dashboard-preview.png            # placeholder
│       ├── rule-manager-preview.png         # placeholder
│       └── advisor-feedback-preview.png     # placeholder
│
├── dist/
├── esbuild.js
├── package.json
├── tsconfig.json
└── README.md
```

> In PP2 all UI assets will move fully under `src/ui`.

---

## 📦 Installation & Setup

### 1. Clone

```bash
git clone https://github.com/<your-org>/flusec.git
cd flusec
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Build Extension

```bash
npm run compile
```

### 4. Build Dart Analyzer

```bash
cd dart-analyzer
dart pub get
dart compile exe bin/analyzer.dart -o bin/analyzer.exe
```

### 5. Debug Run

Open in VS Code → Press **F5**

---

## 🧠 Key Commands

| Command                           | Description                                   |
| --------------------------------- | --------------------------------------------- |
| `Flusec: Scan current file`       | Runs static security scan on active Dart file |
| `Flusec: Manage Rules`            | Opens the Rule Manager UI (dynamic rules)     |
| `Flusec: Open Findings Dashboard` | Opens visualization dashboard                 |

---

## 📊 Dashboard & UI (Temporary Image Paths)

| UI View                | Temporary Path                           |
| ---------------------- | ---------------------------------------- |
| Findings Dashboard     | `assets/ui/dashboard-preview.png`        |
| Rule Manager           | `assets/ui/rule-manager-preview.png`     |
| Advisor Feedback Popup | `assets/ui/advisor-feedback-preview.png` |

> These will later include real screenshots.

---

## 🧰 Dependencies

### Extension

* VS Code API
* esbuild
* node-fetch
* TypeScript / ESLint

### Analyzer

* Dart analyzer
* crypto
* path

---

## 🚀 Future Enhancements (PP2+)

✔ Unified rule repository
✔ Advanced rule-tuning UI
✔ Analytics & trends dashboard
✔ Broader local-LLM support

---

## 👥 TEAM

| NAME                     | ROLE                                 |
| ------------------------ | ------------------------------------ |
| **KUMARAGE D.C.K.**      | HARD-CODED SECRETS ADVISOR           |
| **GUNAWARDANA T.G.H.M.** | SECURE DATA STORAGE MODULE           |
| **AYANAJA H.P.M.G.**     | SECURE NETWORK COMMUNICATION ADVISOR |
| **RUPASINGHE W.A.L.P.**  | INPUT VALIDATION ADVISOR             |

---


