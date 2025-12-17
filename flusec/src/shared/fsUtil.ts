// src/shared/fsUtil.ts
//
// Small shared FS helpers.
// Used by findings writer (component findings.json) and anything else.

import * as fs from "fs";
import * as path from "path";

export function ensureDirForFile(filePath: string) {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}
