// Run against the private release stage or source-home install, before hashing
// its capsule. An operator supplies the project ID through a provisioned file.
import { readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { resolve } from "node:path";

const capsule = resolve(process.argv[2]);
const operator = process.env.ELASTOS_WALLETCONNECT_PROJECT_FILE;
if (operator || process.env.ELASTOS_WALLETCONNECT_PROJECT_ID) {
  const projectId = (operator ? await readFile(operator, "utf8") : process.env.ELASTOS_WALLETCONNECT_PROJECT_ID).trim();
  if (!/^[A-Za-z0-9_-]{8,128}$/.test(projectId)) throw new Error("Invalid WalletConnect operator project file");
  const manifest = JSON.parse(await readFile(resolve(capsule, "vendor/adapter.json"), "utf8"));
  const sdk = await readFile(resolve(capsule, "vendor/reown-appkit.js"));
  if (manifest.sdk_package !== "@walletconnect/ethereum-provider"
      || manifest.sdk_version !== "2.23.9"
      || manifest.sdk_sha256 !== createHash("sha256").update(sdk).digest("hex")) {
    throw new Error("WalletConnect reviewed adapter hash mismatch");
  }
  await writeFile(resolve(capsule, "vendor/connector.json"), JSON.stringify({
    schema: "elastos.walletconnect.connector/v1", project_id: projectId,
    sdk_package: manifest.sdk_package, sdk_version: manifest.sdk_version, sdk_sha256: manifest.sdk_sha256,
  }, null, 2) + "\n", { mode: 0o600 });
}
