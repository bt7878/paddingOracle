import crypto from "node:crypto";

const key = crypto.randomBytes(32);

export function encrypt(text: string): string {
  const iv = crypto.randomBytes(16);

  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  const encrypted = Buffer.concat([
    iv,
    cipher.update(text, "utf8"),
    cipher.final(),
  ]);

  return encrypted.toString("base64");
}

export function decrypt(encrypted: string): string {
  const buf = Buffer.from(encrypted, "base64");

  const iv = buf.subarray(0, 16);
  const cipherText = buf.subarray(16);

  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  let decrypted = decipher.update(cipherText, undefined, "utf8");
  decrypted += decipher.final("utf8");

  return decrypted;
}
