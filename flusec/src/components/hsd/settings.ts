// src/components/hsd/settings.ts
//
// HSD = Hardcoded Secrets Detection component settings.
//
// When other components are added, they will each have their own settings.ts:
// - network/settings.ts
// - storage/settings.ts
// - validation/settings.ts
//
// Each will define:
// - componentId
// - rules json filename
// - commands (scan, manage rules, open findings)

export const HSD_COMPONENT_ID = "hsd";

// This must match the rules json your Dart analyzer expects/loads.
// In your analyzer.dart you used:
// hardcoded_secrets_rules.json
export const HSD_RULES_FILE = "hardcoded_secrets_rules.json";

// VS Code commands (keep the same command names you already use)
export const CMD_SCAN_FILE = "flusec.scanFile";
export const CMD_MANAGE_RULES = "flusec.manageRules";
export const CMD_OPEN_FINDINGS = "flusec.openFindings";
