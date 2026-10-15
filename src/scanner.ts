import { execSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { generateId } from "./ids.js";

export interface SecretScanFinding {
  id: string;
  filePath: string;
  line: number;
  column: number;
  ruleId: string;
  description: string;
  redactedValue: string;
  rawValue: string;
  entropy: number;
  suggestedHandle?: string | undefined;
}

export interface SecretScanResult {
  scannedFiles: number;
  findingsCount: number;
  findings: SecretScanFinding[];
  clean: boolean;
  durationMs: number;
}

export interface ScanRule {
  id: string;
  description: string;
  regex: RegExp;
  minEntropy?: number | undefined;
}

export const SCAN_RULES: ScanRule[] = [
  {
    id: "private-key",
    description: "Asymmetric private key block",
    regex: /-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED|PRIVATE) KEY-----/,
  },
  {
    id: "openai-api-key",
    description: "OpenAI API secret key",
    regex: /\b(sk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{24,})\b/,
  },
  {
    id: "anthropic-api-key",
    description: "Anthropic Claude API key",
    regex: /\b(sk-ant-(?:api03-)?[A-Za-z0-9_-]{24,})\b/,
  },
  {
    id: "google-gemini-key",
    description: "Google Gemini API key",
    regex: /\b(AIzaSy[A-Za-z0-9_-]{20,})\b/,
  },
  {
    id: "aws-access-key-id",
    description: "AWS IAM Access Key ID",
    regex: /\b(AKIA[0-9A-Z]{16})\b/,
  },
  {
    id: "github-token",
    description: "GitHub personal access token or OAuth credential",
    regex: /\b(gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,})\b/,
  },
  {
    id: "slack-token",
    description: "Slack Bot/User/App token",
    regex: /\b(xox[baprs]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,})\b/,
  },
  {
    id: "stripe-secret-key",
    description: "Stripe live or test secret key",
    regex: /\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,})\b/,
  },
  {
    id: "database-url",
    description: "Database connection string containing embedded credentials",
    regex:
      /\b((?:postgres|postgresql|mysql|mongodb\+srv):\/\/[^\s:@]+:[^\s:@]+@[^\s/]+(?:\/[^\s?]*)?)\b/,
  },
  {
    id: "jwt-token",
    description: "JSON Web Token (JWT) with encoded bearer claims",
    regex: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/,
  },
  {
    id: "env-assignment-secret",
    description: "High-entropy credential assigned in key-value config",
    regex:
      /(?:(?:API_KEY|SECRET_KEY|ACCESS_TOKEN|AUTH_TOKEN|CLIENT_SECRET|PASSWORD|PRIVATE_KEY)\s*[:=]\s*["']?([^"'\s#\r\n]{16,})["']?)/i,
    minEntropy: 3.5,
  },
];

export const DEFAULT_IGNORED_DIRS = new Set([
  ".git",
  "node_modules",
  "dist",
  "build",
  "coverage",
  ".llm-vault",
  ".gemini",
  "scratch",
  "__pycache__",
  ".turbo",
]);

export const DEFAULT_IGNORED_EXTENSIONS = new Set([
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".ico",
  ".webp",
  ".pdf",
  ".zip",
  ".tar",
  ".gz",
  ".woff",
  ".woff2",
  ".ttf",
  ".eot",
  ".exe",
  ".dll",
  ".so",
  ".dylib",
  ".wasm",
  ".lock",
]);

export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;
  const freq: Record<string, number> = {};
  for (let i = 0; i < str.length; i++) {
    const char = str[i]!;
    freq[char] = (freq[char] ?? 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(3));
}

export function redactSecret(value: string): string {
  if (!value || value.length === 0) return "[REDACTED]";
  if (value.length <= 8) return "********";
  const prefixLen = Math.min(4, Math.floor(value.length / 4));
  const suffixLen = Math.min(4, Math.floor(value.length / 4));
  const prefix = value.slice(0, prefixLen);
  const suffix = value.slice(-suffixLen);
  return `${prefix}****${suffix}`;
}

export function isBinaryBuffer(buffer: Buffer): boolean {
  const checkLen = Math.min(buffer.length, 1024);
  for (let i = 0; i < checkLen; i++) {
    if (buffer[i] === 0) return true;
  }
  return false;
}

export function scanContent(
  content: string,
  filePath = "inline",
  options?: { minEntropy?: number | undefined },
): SecretScanFinding[] {
  const findings: SecretScanFinding[] = [];
  const lines = content.split(/\r?\n/);
  const minEntropyThreshold = options?.minEntropy ?? 3.5;

  let findingCounter = 1;

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const line = lines[lineIdx]!;
    const lineNum = lineIdx + 1;

    if (!line.trim() || line.trim().startsWith("#!")) continue;
    if (line.includes("{{vault:sec_")) continue;

    for (const rule of SCAN_RULES) {
      const match = rule.regex.exec(line);
      if (!match) continue;

      const rawValue = match[1] ?? match[0];
      if (!rawValue || rawValue.length < 8) continue;

      if (
        rawValue.includes("****") ||
        rawValue.includes("YOUR_") ||
        rawValue.includes("EXAMPLE_") ||
        rawValue.startsWith("sk-proj-test")
      ) {
        continue;
      }

      const entropy = calculateShannonEntropy(rawValue);
      const ruleEntropyReq = rule.minEntropy ?? minEntropyThreshold;

      if (rule.minEntropy && entropy < ruleEntropyReq) {
        continue;
      }

      const col = match.index + 1;
      const suggestedSecId = generateId("sec");

      findings.push({
        id: `finding_${path.basename(filePath)}_${lineNum}_${findingCounter++}`,
        filePath,
        line: lineNum,
        column: col,
        ruleId: rule.id,
        description: rule.description,
        redactedValue: redactSecret(rawValue),
        rawValue,
        entropy,
        suggestedHandle: `{{vault:${suggestedSecId}}}`,
      });
    }
  }

  return findings;
}

export interface ScanOptions {
  directory?: string | undefined;
  files?: string[] | undefined;
  stagedOnly?: boolean | undefined;
  minEntropy?: number | undefined;
  ignoredDirs?: string[] | undefined;
}

export async function scanWorkspace(options: ScanOptions = {}): Promise<SecretScanResult> {
  const startTime = Date.now();
  const rootDir = path.resolve(options.directory ?? process.cwd());
  const findings: SecretScanFinding[] = [];
  let scannedFiles = 0;

  let targetFiles: string[] = [];

  if (options.files && options.files.length > 0) {
    targetFiles = options.files.map((f) => path.resolve(rootDir, f));
  } else if (options.stagedOnly) {
    try {
      const gitOutput = execSync("git diff --cached --name-only --diff-filter=ACMR", {
        cwd: rootDir,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      });
      targetFiles = gitOutput
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter(Boolean)
        .map((f) => path.resolve(rootDir, f));
    } catch {
      targetFiles = [];
    }
  } else {
    targetFiles = walkDirectory(rootDir, options.ignoredDirs);
  }

  for (const filePath of targetFiles) {
    if (!fs.existsSync(filePath)) continue;

    const ext = path.extname(filePath).toLowerCase();
    if (DEFAULT_IGNORED_EXTENSIONS.has(ext)) continue;

    try {
      const stats = fs.statSync(filePath);
      if (stats.isDirectory() || stats.size > 5 * 1024 * 1024) continue;

      const buffer = fs.readFileSync(filePath);
      if (isBinaryBuffer(buffer)) continue;

      const content = buffer.toString("utf8");
      const relativePath = path.relative(rootDir, filePath).replace(/\\/g, "/");
      const fileFindings = scanContent(content, relativePath, {
        minEntropy: options.minEntropy,
      });

      if (fileFindings.length > 0) {
        findings.push(...fileFindings);
      }
      scannedFiles++;
    } catch {
      // Ignore unreadable files
    }
  }

  return {
    scannedFiles,
    findingsCount: findings.length,
    findings,
    clean: findings.length === 0,
    durationMs: Date.now() - startTime,
  };
}

function walkDirectory(dir: string, customIgnoredDirs?: string[] | undefined): string[] {
  const results: string[] = [];
  const ignored = new Set([...DEFAULT_IGNORED_DIRS, ...(customIgnoredDirs ?? [])]);

  function walk(current: string) {
    let entries: fs.Dirent[] = [];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (!ignored.has(entry.name) && !entry.name.startsWith(".")) {
          walk(path.join(current, entry.name));
        }
      } else if (entry.isFile()) {
        results.push(path.join(current, entry.name));
      }
    }
  }

  walk(dir);
  return results;
}

const HOOK_MARKER = "# llm-vault pre-commit secret scanner";

const HOOK_SCRIPT = `#!/bin/sh
${HOOK_MARKER}
# Blocks unencrypted credentials from git staging.

echo "[llm-vault] Running pre-commit secret scan on staged files..."

if command -v llm-vault >/dev/null 2>&1; then
  llm-vault scan --staged --fail-on-found
  EXIT_CODE=$?
elif [ -f "./node_modules/.bin/llm-vault" ]; then
  ./node_modules/.bin/llm-vault scan --staged --fail-on-found
  EXIT_CODE=$?
elif command -v npx >/dev/null 2>&1; then
  npx --no-install @llm-vault/cli scan --staged --fail-on-found
  EXIT_CODE=$?
else
  echo "[llm-vault] Notice: llm-vault CLI not installed globally; proceeding."
  exit 0
fi

if [ $EXIT_CODE -ne 0 ]; then
  echo ""
  echo "[llm-vault] ERROR: Unencrypted credentials detected in staged files!"
  echo "[llm-vault] Run 'llm-vault absorb <file>' to migrate them to {{vault:sec_...}} handles,"
  echo "[llm-vault] or unstage sensitive files before committing."
  echo ""
  exit 1
fi

exit 0
`;

export interface PreCommitHookStatus {
  installed: boolean;
  hookPath: string;
  executable: boolean;
  isLlmVaultHook: boolean;
}

export function getGitHooksDir(rootDir = process.cwd()): string | null {
  const gitDir = path.resolve(rootDir, ".git");
  if (!fs.existsSync(gitDir)) return null;

  const stat = fs.statSync(gitDir);
  if (stat.isDirectory()) {
    return path.join(gitDir, "hooks");
  }

  try {
    const gitFileContent = fs.readFileSync(gitDir, "utf8");
    const match = /gitdir:\s*(.+)/.exec(gitFileContent);
    if (match && match[1]) {
      const resolvedGitDir = path.resolve(rootDir, match[1].trim());
      return path.join(resolvedGitDir, "hooks");
    }
  } catch {
    // Ignore read errors
  }

  return null;
}

export function getPreCommitHookStatus(rootDir = process.cwd()): PreCommitHookStatus {
  const hooksDir = getGitHooksDir(rootDir);
  if (!hooksDir) {
    return {
      installed: false,
      hookPath: "",
      executable: false,
      isLlmVaultHook: false,
    };
  }

  const hookPath = path.join(hooksDir, "pre-commit");
  if (!fs.existsSync(hookPath)) {
    return {
      installed: false,
      hookPath,
      executable: false,
      isLlmVaultHook: false,
    };
  }

  try {
    const content = fs.readFileSync(hookPath, "utf8");
    const isLlmVaultHook = content.includes(HOOK_MARKER);
    const stats = fs.statSync(hookPath);
    const executable = process.platform === "win32" || Boolean(stats.mode & 0o111);

    return {
      installed: true,
      hookPath,
      executable,
      isLlmVaultHook,
    };
  } catch {
    return {
      installed: false,
      hookPath,
      executable: false,
      isLlmVaultHook: false,
    };
  }
}

export function installPreCommitHook(rootDir = process.cwd()): PreCommitHookStatus {
  const hooksDir = getGitHooksDir(rootDir);
  if (!hooksDir) {
    throw new Error(
      `Cannot install git hook: Not a git repository (no .git directory found at ${rootDir})`,
    );
  }

  if (!fs.existsSync(hooksDir)) {
    fs.mkdirSync(hooksDir, { recursive: true });
  }

  const hookPath = path.join(hooksDir, "pre-commit");

  if (fs.existsSync(hookPath)) {
    const existing = fs.readFileSync(hookPath, "utf8");
    if (!existing.includes(HOOK_MARKER)) {
      const chained = `${existing.trim()}\n\n# Chained llm-vault hook\n${HOOK_SCRIPT}\n`;
      fs.writeFileSync(hookPath, chained, { encoding: "utf8", mode: 0o755 });
    }
  } else {
    fs.writeFileSync(hookPath, HOOK_SCRIPT, { encoding: "utf8", mode: 0o755 });
  }

  try {
    fs.chmodSync(hookPath, 0o755);
  } catch {
    // Windows chmod may be no-op
  }

  return getPreCommitHookStatus(rootDir);
}

export function removePreCommitHook(rootDir = process.cwd()): PreCommitHookStatus {
  const status = getPreCommitHookStatus(rootDir);
  if (!status.installed || !status.hookPath) {
    return status;
  }

  try {
    const content = fs.readFileSync(status.hookPath, "utf8");
    if (content.trim() === HOOK_SCRIPT.trim()) {
      fs.unlinkSync(status.hookPath);
    } else if (content.includes(HOOK_MARKER)) {
      const lines = content.split(/\r?\n/);
      const filtered = lines.filter((line) => !line.includes("llm-vault"));
      fs.writeFileSync(status.hookPath, filtered.join("\n"), { encoding: "utf8", mode: 0o755 });
    }
  } catch {
    // Ignore removal error
  }

  return getPreCommitHookStatus(rootDir);
}
