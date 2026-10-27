import { spawnSync } from "node:child_process";
import { closeSync, openSync, readFileSync, readSync } from "node:fs";

export type KeychainResult = { available: boolean; present: boolean; passphrase?: string };

function security(args: string[]) {
  if (process.platform !== "darwin") return undefined;
  // argv avoids shell expansion/injection. security's -w interface requires argv;
  // it can still be briefly visible to process inspection. Never echo child stderr.
  return spawnSync("security", args, { encoding: "utf8", timeout: 5000, stdio: ["ignore", "pipe", "pipe"] });
}

export function readKeychainPassphrase(): KeychainResult {
  const result = security(["find-generic-password", "-a", "wellspring", "-s", "wellspring-master", "-w"]);
  if (!result || result.error) return { available: false, present: false };
  if (result.status !== 0) return { available: true, present: false };
  // security adds one newline; preserve any whitespace in the actual passphrase.
  const passphrase = result.stdout.replace(/\r?\n$/, "");
  return { available: true, present: passphrase.length > 0, passphrase: passphrase || undefined };
}

export function storeKeychainPassphrase(passphrase: string): void {
  const result = security(["add-generic-password", "-U", "-a", "wellspring", "-s", "wellspring-master", "-w", passphrase]);
  if (!result || result.error) throw new Error("keychain unavailable (requires macOS security)");
  if (result.status !== 0) throw new Error("could not store passphrase in keychain; unlock the login keychain and retry");
}

export function removeKeychainPassphrase(): void {
  const result = security(["delete-generic-password", "-a", "wellspring", "-s", "wellspring-master"]);
  if (!result || result.error) throw new Error("keychain unavailable (requires macOS security)");
  if (result.status !== 0 && result.status !== 44) throw new Error("could not remove passphrase from keychain");
}

function promptHidden(label: string): string {
  if (!process.stdin.isTTY || !process.stdin.setRawMode) throw new Error("interactive passphrase entry requires a TTY");
  const wasRaw = process.stdin.isRaw;
  const fd = openSync("/dev/tty", "r");
  const bytes: number[] = [];
  process.stderr.write(label);
  try {
    process.stdin.setRawMode(true);
    const byte = Buffer.alloc(1);
    for (;;) {
      if (readSync(fd, byte, 0, 1, null) !== 1) throw new Error("passphrase input ended");
      if (byte[0] === 3 || byte[0] === 4) throw new Error("passphrase entry cancelled");
      if (byte[0] === 10 || byte[0] === 13) break;
      if (byte[0] === 127 || byte[0] === 8) {
        // Remove a complete UTF-8 character when backspacing.
        while (bytes.length && (bytes[bytes.length - 1] & 0xc0) === 0x80) bytes.pop();
        bytes.pop();
      } else bytes.push(byte[0]);
    }
    return Buffer.from(bytes).toString("utf8");
  } finally {
    process.stdin.setRawMode(wasRaw);
    closeSync(fd);
    process.stderr.write("\n");
    bytes.fill(0);
  }
}

export const SEALED_KEY_ERROR = "master key is sealed and the passphrase is incorrect or unavailable; set WELLSPRING_PASSPHRASE / WELLSPRING_PASSPHRASE_FILE or store it in the macOS keychain (wellspring keychain store)";

/** Earlier configured sources are authoritative: never fall back after a wrong password. */
export function obtainPassphrase(confirmInteractive = false): string {
  let passphrase: string | undefined;
  if (process.env.WELLSPRING_PASSPHRASE !== undefined) passphrase = process.env.WELLSPRING_PASSPHRASE;
  else if (process.env.WELLSPRING_PASSPHRASE_FILE !== undefined) {
    try { passphrase = readFileSync(process.env.WELLSPRING_PASSPHRASE_FILE, "utf8").replace(/\r?\n$/, ""); }
    catch { throw new Error("cannot read WELLSPRING_PASSPHRASE_FILE"); }
  } else passphrase = readKeychainPassphrase().passphrase;
  if (passphrase === undefined && process.stdin.isTTY) passphrase = promptHidden("Master key passphrase: ");
  if (!passphrase) throw new Error(SEALED_KEY_ERROR);
  if (confirmInteractive && process.stdin.isTTY && promptHidden("Confirm master key passphrase: ") !== passphrase) {
    throw new Error("passphrase confirmation does not match");
  }
  return passphrase;
}
