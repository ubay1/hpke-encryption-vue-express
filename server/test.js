const http = require("http");

const BASE = "http://localhost:9001";

function request(path, method = "GET", body = null) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE);
    const options = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname,
      method,
      headers: { "Content-Type": "application/json" },
    };

    const req = http.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        try {
          resolve(JSON.parse(data));
        } catch {
          resolve(data);
        }
      });
    });

    req.on("error", reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

async function main() {
  try {
    // 1. Get server public key
    console.log("=== 1. Get Server Public Key ===");
    const { publicKey } = await request("/api/public-key");
    console.log("Key type:", publicKey.kty);
    console.log("Modulus (n):", publicKey.n.substring(0, 50) + "...");

    // 2. Encrypt data using server's own public key
    console.log("\n=== 2. Encrypt Data ===");
    const encrypted = await request("/api/encrypt", "POST", {
      data: "Hello Secret World!",
      recipientPublicKey: publicKey,
    });
    console.log(
      "Encrypted (first 50 chars):",
      encrypted.encrypted?.substring(0, 50) + "...",
    );
    console.log("IV:", encrypted.iv);
    console.log(
      "Encrypted Key (first 50 chars):",
      encrypted.encryptedKey?.substring(0, 50) + "...",
    );

    // 3. Decrypt data
    console.log("\n=== 3. Decrypt Data ===");
    const decrypted = await request("/api/decrypt", "POST", encrypted);
    console.log("Decrypted:", decrypted.data);

    console.log("\n✅ All tests passed!");
  } catch (error) {
    console.error("❌ Test failed:", error.message);
    console.error(error);
  }
}

main();
