import database from "./database";
import crypto from "crypto";

export interface JwtClaim {
  username: string;
  exp: number;
}

export default class AuthenticationHandler {
  tokens: Record<string, string>;
  secret: string;

  constructor() {
    this.tokens = {};
    this.secret = crypto.randomBytes(32).toString(`ascii`);
    database.query(`CREATE TABLE IF NOT EXISTS logins (
        id INT(10) PRIMARY KEY AUTO_INCREMENT,
        username VARCHAR(255) NOT NULL,
        hash VARCHAR(255) NOT NULL,
        salt VARCHAR(255) NOT NULL
    )`);
    console.log(
      `Loaded JWT authentication handler with hashing secret ${Buffer.from(
        this.secret
      ).toString("base64")}`
    );
  }

  generateSalt(rounds: number) {
    return crypto
      .randomBytes(Math.ceil(rounds / 2))
      .toString("hex")
      .slice(0, rounds);
  }

  hash(password: string, salt: string) {
    const h = crypto.createHmac(`sha512`, salt);
    h.update(password);
    return h.digest("hex");
  }

  createToken({ username, exp }: JwtClaim): string {
    const header = {
      typ: "JWT",
      alg: "HS256",
    };
    const claim = { username, exp };

    const json = {
      header: JSON.stringify(header),
      claim: JSON.stringify(claim),
    };

    const encoded = {
      header: Buffer.from(json.header).toString("base64"),
      claim: Buffer.from(json.claim).toString("base64"),
    };

    const signature = crypto
      .createHmac("sha256", this.secret)
      .update(`${encoded.header}.${encoded.claim}`)
      .digest("base64");

    return `${encoded.header}.${encoded.claim}.${signature}`;
  }

  async validateToken(token: string): Promise<JwtClaim | null> {
    const [header, claim, signature] = token.split(".");
    const newSignature = crypto
      .createHmac("sha256", this.secret)
      .update(`${header}.${claim}`)
      .digest("base64");

    if (signature == newSignature) {
      return JSON.parse(
        Buffer.from(claim, "base64").toString("utf-8")
      ) as JwtClaim;
    }

    return null;
  }

  async validate(username: string, password: string): Promise<boolean> {
    return new Promise<boolean>((resolver) => {
      database.query({
        query: `SELECT * FROM logins WHERE username = ?`,
        params: [username],
        callback: (results) => {
          if (!results.length) return resolver(false);
          const obj = results[0];
          const { hash, salt } = obj;
          return resolver(hash == this.hash(password, salt));
        },
      });
    });
  }

  async register(username: string, password: string): Promise<boolean> {
    return new Promise<boolean>((resolver) => {
      const salt = this.generateSalt(12);
      const hash = this.hash(password, salt);
      database.query({
        query: "SELECT * FROM logins WHERE username = ?",
        params: [username],
        callback: (results) => {
          if (results.length) return resolver(false);

          database.query({
            query: "INSERT INTO logins (username, salt, hash) VALUES (?, ?, ?)",
            params: [username, salt, hash],
          });
          return resolver(true);
        },
      });
    });
  }

  async authenticate(
    username: string,
    password: string
  ): Promise<string | undefined> {
    const valid = await this.validate(username, password);
    if (!valid) return undefined;
    const token = this.createToken({
      username: username,
      exp: Date.now() + 1000 * 60 * 60 * 12,
    });
    return token;
  }
}
