Perfect ✅ — here’s a clean, **professional `README.md`** you can use for your overall *FluSec* VS Code extension (covers the full integrated project, not just your component).

It’s written clearly so both your group and supervisors understand the purpose, structure, and setup.

---

# 🧠 FluSec – LLM-Driven Flutter Security Extension for VS Code

**FluSec** is a VS Code extension that performs **static security analysis** on Flutter/Dart projects.
It detects multiple classes of security vulnerabilities and provides **educational, privacy-preserving feedback** powered by a local LLM (via Ollama or compatible runtimes).

---

## ⚙️ Features

FluSec includes four detection modules, each targeting a different category of common mobile app security risks:

| Module                                      | Description                                                                                             |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| 🔐 **Hardcoded Secrets Detection (HSD)**    | Detects API keys, tokens, and credentials embedded in code using regex, entropy, and heuristic methods. |
| 🌐 **Insecure Network Communication (INC)** | Flags unsafe HTTP usage, unencrypted data transmission, and insecure SSL configurations.                |
| 💾 **Insecure Data Storage (IDS)**          | Identifies sensitive data stored in plaintext or weakly protected local storage.                        |
| 🧮 **Insufficient Input Validation (IIV)**  | Detects missing or weak input validation that can lead to code injection or logic flaws.                |

Each module supports:

* **AST-based analysis** (via the Dart Analyzer)
* **Pattern and heuristic rules**
* **Context-aware LLM feedback** for educational explanations and remediation guidance

---

## 🧩 Architecture Overview

FluSec uses a **hybrid architecture**:

1. The **VS Code Extension (TypeScript)** handles UI, commands, diagnostics, and LLM feedback.
2. The **Dart Analyzer Runtime** performs the actual static analysis (AST + regex + heuristics).
3. Results are saved as JSON and visualized in the **Findings Dashboard** within VS Code.

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

---

## 📁 Folder Structure

```
flusec/
├── dart-analyzer/
│   ├── bin/
│   │   ├── analyzer.dart       # Analyzer entrypoint
│   │   └── analyzer.exe        # Compiled executable
│   ├── lib/
│   │   └── rules.dart          # Rule engine and detection logic
│   ├── data/
│   │   └── rules.json          # Dynamic rule definitions
│   └── pubspec.yaml            # Dart dependencies
│
├── src/
│   ├── extension.ts            # VS Code extension entrypoint
│   ├── llm.ts                  # Local LLM (Ollama) API integration
│   ├── diagnostics.ts          # Shared diagnostics handler
│   ├── features/               # Detection modules integration layer
│   │   ├── hardcoded_secrets.ts
│   │   ├── insecure_network.ts
│   │   ├── insecure_storage.ts
│   │   └── input_validation.ts
│   └── ui/
│       ├── ruleManager/        # Future rule management interfaces
│       └── web/
│           └── dashboard.html  # Unified visualization dashboard
│
├── web/         # Temporary location for dashboard.html
│   └── dashboard.html
│
├── dist/                       # Compiled JS output for VS Code runtime
├── esbuild.js                  # Build bundler
├── package.json                # VS Code extension metadata
├── tsconfig.json               # TypeScript configuration
└── README.md                   # This file
```

> 💡 *In PP1, `web/dashboard.html` is kept at root for simplicity.
> In PP2, it will move to `src/ui/web/dashboard.html` to unify all UI components.*

---

## 📦 Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/<your-org>/flusec.git
cd flusec
```

### 2. Install VS Code Extension Dependencies

```bash
npm install
```

### 3. Compile the TypeScript Extension

```bash
npm run compile
```

### 4. Compile the Dart Analyzer to Executable

```bash
cd dart-analyzer
dart pub get
dart compile exe bin/analyzer.dart -o bin/analyzer.exe
```

### 5. Launch Extension for Debug

In VS Code, press **F5** → opens new “Extension Development Host”.

---

## 🧠 Key Commands (as defined in `package.json`)

| Command                                         | Description                                                    |
| ----------------------------------------------- | -------------------------------------------------------------- |
| `Flusec: Scan current file for vulnerabilities` | Runs the analyzer on the active Dart file and reports results. |
| `Flusec: Manage Rules`                          | Opens the Rule Manager UI (for editing detection rules).       |
| `Flusec: Open Findings Dashboard`               | Opens the unified dashboard to view results visually.          |

---

## 🧰 Dependencies

### TypeScript / Extension

* `vscode` – VS Code API
* `esbuild` – Bundling
* `node-fetch` – HTTP requests to Ollama
* `typescript`, `eslint` – Development & linting

### Dart / Analyzer

* `analyzer` – Dart AST parsing
* `crypto` – Entropy & hashing utilities
* `path` – File path handling

---

## 🧠 Future Enhancements (PP2 and Beyond)

* Integrate all four components with shared rule sets
* Add dynamic rule management via Rule Manager UI
* Extend dashboard with analytics and LLM-powered summaries
* Support offline local LLMs (Phi-3, Mistral, Qwen, etc.) through Ollama

---

## 👥 Team Roles

| Module                         | Responsibility                           |
| ------------------------------ | ---------------------------------------- |
| Hardcoded Secrets              | Detection & LLM remediation logic        |
| Insecure Network Communication | HTTP/SSL security scanning               |
| Insecure Data Storage          | Sensitive data handling analysis         |
| Insufficient Input Validation  | Input sanitization & validation analysis |



Would you like me to generate this as a downloadable **`README.md` file** (so you can directly push it to your GitHub repo)?
