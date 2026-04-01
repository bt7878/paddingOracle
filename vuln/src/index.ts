import express, { ErrorRequestHandler } from "express";
import { decrypt, encrypt } from "./crypto.js";
import morgan from "morgan";

const app = express();
app.use(morgan("tiny"));
app.use(express.json());

const jsonErrorHandler: ErrorRequestHandler = (err, _, res, next) => {
  if (err.type === "entity.parse.failed")
    return res.status(400).json({ error: "invalid json" });

  next(err);
};
app.use(jsonErrorHandler);

app.post("/encrypt", (req, res) => {
  const { text } = req.body ?? {};

  if (!text) return res.status(400).json({ error: "text is required" });

  const encrypted = encrypt(text);
  return res.json({ encrypted });
});

app.post("/oracle", (req, res) => {
  const { encrypted } = req.body ?? {};

  if (!encrypted)
    return res.status(400).json({ error: "encrypted is required" });

  try {
    decrypt(encrypted);
    return res.json({ decrypted: "valid" });
  } catch {
    return res.status(400).json({ error: "bad decrypt" });
  }
});

app.listen(3000, () => console.log("listening on http://localhost:3000"));
