#!/usr/bin/env node

const { execSync, spawn } = require("child_process");
const { existsSync } = require("fs");
const { join } = require("path");
const os = require("os");

const PACKAGE = "prism-scanner";
const VENV_DIR = join(os.homedir(), ".prism", "venv");

function findPython() {
  for (const cmd of ["python3", "python"]) {
    try {
      const version = execSync(`${cmd} --version 2>&1`, { encoding: "utf-8" });
      if (version.includes("Python 3.")) return cmd;
    } catch {}
  }
  return null;
}

function ensureInstalled(python) {
  const venvPrism =
    process.platform === "win32"
      ? join(VENV_DIR, "Scripts", "prism")
      : join(VENV_DIR, "bin", "prism");

  if (existsSync(venvPrism)) return venvPrism;

  console.error(`[prism-scanner] Setting up Python environment...`);

  // Create venv
  execSync(`${python} -m venv "${VENV_DIR}"`, { stdio: "inherit" });

  // Install prism-scanner
  const pip =
    process.platform === "win32"
      ? join(VENV_DIR, "Scripts", "pip")
      : join(VENV_DIR, "bin", "pip");

  execSync(`"${pip}" install ${PACKAGE}`, { stdio: "inherit" });

  if (!existsSync(venvPrism)) {
    console.error(`[prism-scanner] Installation failed.`);
    process.exit(1);
  }

  return venvPrism;
}

function main() {
  const python = findPython();
  if (!python) {
    console.error(
      "[prism-scanner] Python 3 is required but not found.\n" +
        "Install it from https://python.org or via your package manager."
    );
    process.exit(1);
  }

  const prismBin = ensureInstalled(python);
  const args = process.argv.slice(2);

  const child = spawn(prismBin, args, { stdio: "inherit" });
  child.on("close", (code) => process.exit(code ?? 0));
}

main();
