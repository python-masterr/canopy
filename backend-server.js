"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const http = require("node:http");
const path = require("node:path");
const { promisify } = require("node:util");
const { DatabaseSync } = require("node:sqlite");

const scrypt = promisify(crypto.scrypt);
const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;
const MAX_BODY_BYTES = 200 * 1024;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function createDatabase(databasePath) {
  fs.mkdirSync(path.dirname(databasePath), { recursive: true });
  const db = new DatabaseSync(databasePath);
  db.exec(`
    PRAGMA foreign_keys = ON;
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL,
      is_admin INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS login_events (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      logged_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS login_events_by_user
      ON login_events(user_id, logged_at DESC);
    CREATE TABLE IF NOT EXISTS screenings (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      results_json TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS screenings_by_user
      ON screenings(user_id, created_at DESC);
  `);
  if (!db.prepare("PRAGMA table_info(users)").all().some((column) => column.name === "is_admin")) {
    db.exec("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0");
  }
  return db;
}

function sendJson(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    "Cache-Control": "no-store",
  });
  res.end(body);
}

function readCookie(req, name) {
  const header = req.headers.cookie || "";
  for (const part of header.split(";")) {
    const separator = part.indexOf("=");
    if (separator > 0 && part.slice(0, separator).trim() === name) {
      return part.slice(separator + 1).trim();
    }
  }
  return "";
}

function publicUser(user) {
  return { id: user.id, name: user.name, email: user.email, isAdmin: Boolean(user.is_admin) };
}

async function readJson(req) {
  if (!(req.headers["content-type"] || "").toLowerCase().includes("application/json")) {
    throw new HttpError(415, "Send this request as JSON.");
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) {
      req.resume();
      throw new HttpError(413, "Request body is too large.");
    }
    chunks.push(chunk);
  }
  try {
    const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      throw new Error("Expected an object.");
    }
    return body;
  } catch {
    throw new HttpError(400, "Request body must be a valid JSON object.");
  }
}

function checkSameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return;
  let parsedOrigin;
  try {
    parsedOrigin = new URL(origin).origin;
  } catch {
    throw new HttpError(403, "This request origin is not allowed.");
  }
  const protocol = req.socket.encrypted ? "https" : "http";
  if (parsedOrigin !== `${protocol}://${req.headers.host}`) {
    throw new HttpError(403, "This request origin is not allowed.");
  }
}

function validateScreening(body) {
  if (Object.keys(body).some((key) => !["title", "results"].includes(key))) {
    throw new HttpError(400, "A screening may contain only a title and summary results.");
  }
  if (typeof body.title !== "string" || !body.title.trim() || body.title.length > 100) {
    throw new HttpError(400, "Screening title must be between 1 and 100 characters.");
  }
  if (!Array.isArray(body.results) || body.results.length < 1 || body.results.length > 20) {
    throw new HttpError(400, "A screening must contain between 1 and 20 resume summaries.");
  }
  const results = body.results.map((result) => {
    if (!result || typeof result !== "object" || Array.isArray(result) ||
        Object.keys(result).some((key) => !["name", "score", "skillCount", "years", "jobs"].includes(key)) ||
        typeof result.name !== "string" || !result.name.trim() || result.name.length > 80 ||
        !Number.isInteger(result.score) || result.score < 0 || result.score > 100 ||
        !Number.isInteger(result.skillCount) || result.skillCount < 0 || result.skillCount > 60 ||
        !Number.isInteger(result.years) || result.years < 0 || result.years > 80 ||
        !Array.isArray(result.jobs) || result.jobs.length > 3) {
      throw new HttpError(400, "A resume summary contains invalid fields.");
    }
    const jobs = result.jobs.map((job) => {
      if (!job || typeof job !== "object" || Array.isArray(job) ||
          Object.keys(job).some((key) => !["title", "pct"].includes(key)) ||
          typeof job.title !== "string" || !job.title.trim() || job.title.length > 80 ||
          !Number.isInteger(job.pct) || job.pct < 0 || job.pct > 100) {
        throw new HttpError(400, "A job match contains invalid fields.");
      }
      return { title: job.title, pct: job.pct };
    });
    return {
      name: result.name,
      score: result.score,
      skillCount: result.skillCount,
      years: result.years,
      jobs,
    };
  });
  return { title: body.title.trim(), results };
}

function createCanopyServer(options = {}) {
  const databasePath = options.databasePath || process.env.CANOPY_DB_PATH || path.join(__dirname, "data", "canopy.sqlite");
  const adminEmailSetting = options.adminEmail === undefined ? process.env.CANOPY_ADMIN_EMAIL : options.adminEmail;
  const adminPassword = options.adminPassword === undefined ? process.env.CANOPY_ADMIN_PASSWORD : options.adminPassword;
  if ((adminEmailSetting && !adminPassword) || (!adminEmailSetting && adminPassword)) {
    throw new Error("Set both CANOPY_ADMIN_EMAIL and CANOPY_ADMIN_PASSWORD to configure the administrator account.");
  }
  if (adminEmailSetting && typeof adminEmailSetting !== "string") {
    throw new Error("Administrator email or password configuration is invalid.");
  }
  const adminEmail = adminEmailSetting ? adminEmailSetting.trim().toLowerCase() : "";
  if (adminEmailSetting) {
    if (typeof adminEmailSetting !== "string" || !EMAIL_PATTERN.test(adminEmail) ||
        typeof adminPassword !== "string" || adminPassword.length < 8 || Buffer.byteLength(adminPassword) > 1024) {
      throw new Error("Administrator email or password configuration is invalid.");
    }
  }
  const db = createDatabase(databasePath);
  if (adminEmail) {
    const salt = crypto.randomBytes(16);
    const passwordHash = `${salt.toString("hex")}:${crypto.scryptSync(adminPassword, salt, 64).toString("hex")}`;
    const existingAdmin = db.prepare("SELECT id FROM users WHERE email = ?").get(adminEmail);
    if (existingAdmin) {
      db.prepare("UPDATE users SET is_admin = 1, password_hash = ? WHERE id = ?")
        .run(passwordHash, existingAdmin.id);
      db.prepare("DELETE FROM sessions WHERE user_id = ?").run(existingAdmin.id);
    } else {
      db.prepare("INSERT INTO users(id, email, name, password_hash, created_at, is_admin) VALUES (?, ?, ?, ?, ?, 1)")
        .run(crypto.randomUUID(), adminEmail, "Canopy Admin", passwordHash, new Date().toISOString());
    }
    db.prepare("UPDATE users SET is_admin = 0 WHERE is_admin = 1 AND email <> ?").run(adminEmail);
  }
  const findSession = db.prepare(`
    SELECT users.id, users.name, users.email, users.is_admin, sessions.token_hash
    FROM sessions JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ? AND sessions.expires_at > ?
  `);
  const insertSession = db.prepare(
    "INSERT INTO sessions(token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
  );
  const insertLoginEvent = db.prepare(
    "INSERT INTO login_events(id, user_id, logged_at) VALUES (?, ?, ?)",
  );

  async function createSession(res, user, req) {
    db.prepare("DELETE FROM sessions WHERE expires_at <= ?").run(new Date().toISOString());
    const token = crypto.randomBytes(32).toString("hex");
    const now = new Date();
    const expires = new Date(now.getTime() + SESSION_TTL_SECONDS * 1000);
    insertSession.run(
      crypto.createHash("sha256").update(token).digest("hex"),
      user.id,
      expires.toISOString(),
      now.toISOString(),
    );
    const secure = req.socket.encrypted ? "; Secure" : "";
    res.setHeader("Set-Cookie", `canopy_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL_SECONDS}${secure}`);
  }

  function authenticatedUser(req) {
    const token = readCookie(req, "canopy_session");
    if (!/^[a-f0-9]{64}$/.test(token)) return null;
    return findSession.get(
      crypto.createHash("sha256").update(token).digest("hex"),
      new Date().toISOString(),
    ) || null;
  }

  async function handle(req, res) {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "same-origin");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");

    let url;
    try {
      url = new URL(req.url, "http://localhost");
    } catch {
      throw new HttpError(400, "Invalid request URL.");
    }

    if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
      const html = await fsp.readFile(path.join(__dirname, "index.html"));
      res.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Length": html.byteLength,
        "Cache-Control": "no-cache",
      });
      res.end(html);
      return;
    }

    if (url.pathname.startsWith("/api/") && ["POST", "DELETE"].includes(req.method)) {
      checkSameOrigin(req);
    }

    if (req.method === "GET" && url.pathname === "/api/me") {
      const user = authenticatedUser(req);
      sendJson(res, 200, { user: user ? publicUser(user) : null });
      return;
    }

    if (req.method === "POST" && url.pathname === "/api/signup") {
      const body = await readJson(req);
      const name = typeof body.name === "string" ? body.name.trim() : "";
      const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
      const password = typeof body.password === "string" ? body.password : "";
      if (!name || name.length > 80) throw new HttpError(400, "Name must be between 1 and 80 characters.");
      if (email.length > 254 || !EMAIL_PATTERN.test(email)) throw new HttpError(400, "Enter a valid email address.");
      if (password.length < 8 || Buffer.byteLength(password) > 1024) {
        throw new HttpError(400, "Password must be at least 8 characters and no more than 1024 bytes.");
      }
      const salt = crypto.randomBytes(16);
      const passwordKey = await scrypt(password, salt, 64);
      const user = {
        id: crypto.randomUUID(),
        name,
        email,
        password_hash: `${salt.toString("hex")}:${passwordKey.toString("hex")}`,
      };
      try {
        db.prepare("INSERT INTO users(id, email, name, password_hash, created_at) VALUES (?, ?, ?, ?, ?)")
          .run(user.id, user.email, user.name, user.password_hash, new Date().toISOString());
      } catch (error) {
        if (error.code === "ERR_SQLITE_CONSTRAINT_UNIQUE") {
          throw new HttpError(409, "An account with that email already exists.");
        }
        throw error;
      }
      await createSession(res, user, req);
      insertLoginEvent.run(crypto.randomUUID(), user.id, new Date().toISOString());
      sendJson(res, 201, { user: publicUser(user) });
      return;
    }

    if (req.method === "POST" && url.pathname === "/api/login") {
      const body = await readJson(req);
      const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
      const password = typeof body.password === "string" ? body.password : "";
      const user = db.prepare("SELECT id, name, email, password_hash, is_admin FROM users WHERE email = ?").get(email);
      let verified = false;
      if (user && Buffer.byteLength(password) <= 1024) {
        const [saltHex, keyHex] = user.password_hash.split(":");
        const expected = Buffer.from(keyHex, "hex");
        const actual = await scrypt(password, Buffer.from(saltHex, "hex"), expected.length);
        verified = crypto.timingSafeEqual(actual, expected);
      }
      if (!verified) throw new HttpError(401, "Email or password is incorrect.");
      await createSession(res, user, req);
      insertLoginEvent.run(crypto.randomUUID(), user.id, new Date().toISOString());
      sendJson(res, 200, { user: publicUser(user) });
      return;
    }

    if (req.method === "POST" && url.pathname === "/api/logout") {
      const token = readCookie(req, "canopy_session");
      if (/^[a-f0-9]{64}$/.test(token)) {
        db.prepare("DELETE FROM sessions WHERE token_hash = ?")
          .run(crypto.createHash("sha256").update(token).digest("hex"));
      }
      const secure = req.socket.encrypted ? "; Secure" : "";
      res.setHeader("Set-Cookie", `canopy_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${secure}`);
      sendJson(res, 200, { ok: true });
      return;
    }

    if (req.method === "GET" && url.pathname === "/api/admin/users") {
      const user = authenticatedUser(req);
      if (!user) throw new HttpError(401, "Sign in as an administrator to view this page.");
      if (!user.is_admin) throw new HttpError(403, "Administrator access is required.");
      const users = db.prepare(`
        SELECT id, name, email, created_at
        FROM users ORDER BY created_at DESC
      `).all();
      const loginEvents = db.prepare(`
        SELECT login_events.id, login_events.user_id, users.name, users.email, login_events.logged_at
        FROM login_events JOIN users ON users.id = login_events.user_id
        ORDER BY login_events.logged_at DESC
      `).all();
      sendJson(res, 200, { users, loginEvents });
      return;
    }

    if (url.pathname === "/api/screenings") {
      const user = authenticatedUser(req);
      if (!user) throw new HttpError(401, "Sign in to manage saved screenings.");
      if (req.method === "GET") {
        const screenings = db.prepare(`
          SELECT id, title, created_at, results_json
          FROM screenings WHERE user_id = ? ORDER BY created_at DESC
        `).all(user.id).map((row) => ({
          id: row.id,
          title: row.title,
          createdAt: row.created_at,
          results: JSON.parse(row.results_json),
        }));
        sendJson(res, 200, { screenings });
        return;
      }
      if (req.method === "POST") {
        const screening = validateScreening(await readJson(req));
        const id = crypto.randomUUID();
        const createdAt = new Date().toISOString();
        db.prepare("INSERT INTO screenings(id, user_id, title, results_json, created_at) VALUES (?, ?, ?, ?, ?)")
          .run(id, user.id, screening.title, JSON.stringify(screening.results), createdAt);
        sendJson(res, 201, { screening: { id, title: screening.title, createdAt, results: screening.results } });
        return;
      }
    }

    const deleteMatch = req.method === "DELETE" && url.pathname.match(/^\/api\/screenings\/([a-f0-9-]{36})$/);
    if (deleteMatch) {
      const user = authenticatedUser(req);
      if (!user) throw new HttpError(401, "Sign in to manage saved screenings.");
      db.prepare("DELETE FROM screenings WHERE id = ? AND user_id = ?").run(deleteMatch[1], user.id);
      sendJson(res, 200, { ok: true });
      return;
    }

    sendJson(res, 404, { error: "Not found." });
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch((error) => {
      if (res.headersSent) {
        res.destroy(error);
        return;
      }
      if (error instanceof HttpError) {
        sendJson(res, error.status, { error: error.message });
        return;
      }
      console.error(error);
      sendJson(res, 500, { error: "An unexpected server error occurred." });
    });
  });
  server.database = db;
  return server;
}

if (require.main === module) {
  const server = createCanopyServer();
  const host = process.env.HOST || "127.0.0.1";
  const port = Number(process.env.PORT || 3000);
  server.listen(port, host, () => {
    console.log(`Canopy server listening at http://${host}:${server.address().port}`);
  });
}

module.exports = { createCanopyServer };
