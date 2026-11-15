"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { once } = require("node:events");
const { DatabaseSync } = require("node:sqlite");
const test = require("node:test");
const { createCanopyServer } = require("./backend-server");

async function startTestServer(t, options = {}) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "canopy-test-"));
  const server = createCanopyServer(Object.assign({}, options, { databasePath: path.join(directory, "test.sqlite") }));
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  t.after(async () => {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    server.database.close();
    await fs.rm(directory, { recursive: true, force: true });
  });
  return baseUrl;
}

async function request(baseUrl, route, options = {}) {
  const response = await fetch(baseUrl + route, options);
  const body = await response.json();
  return { response, body };
}

test("signup, screening persistence, deletion, and logout", async (t) => {
  const baseUrl = await startTestServer(t);
  const created = await request(baseUrl, "/api/signup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: "Canopy User", email: "USER@example.com", password: "passphrase-123" }),
  });
  assert.equal(created.response.status, 201);
  assert.equal(created.body.user.email, "user@example.com");
  const cookie = created.response.headers.get("set-cookie").split(";")[0];
  assert.match(created.response.headers.get("set-cookie"), /HttpOnly/);

  const saved = await request(baseUrl, "/api/screenings", {
    method: "POST",
    headers: { "Content-Type": "application/json", Cookie: cookie },
    body: JSON.stringify({
      title: "Test screening",
      results: [{ name: "Candidate", score: 82, skillCount: 6, years: 4, jobs: [{ title: "Backend Engineer", pct: 75 }] }],
    }),
  });
  assert.equal(saved.response.status, 201);
  assert.equal(saved.body.screening.results[0].score, 82);

  const listed = await request(baseUrl, "/api/screenings", { headers: { Cookie: cookie } });
  assert.equal(listed.body.screenings.length, 1);
  assert.equal(listed.body.screenings[0].title, "Test screening");

  const removed = await request(baseUrl, `/api/screenings/${saved.body.screening.id}`, {
    method: "DELETE",
    headers: { Cookie: cookie },
  });
  assert.equal(removed.response.status, 200);
  assert.equal((await request(baseUrl, "/api/screenings", { headers: { Cookie: cookie } })).body.screenings.length, 0);

  const loggedOut = await request(baseUrl, "/api/logout", { method: "POST", headers: { Cookie: cookie } });
  assert.equal(loggedOut.response.status, 200);
  assert.equal((await request(baseUrl, "/api/screenings", { headers: { Cookie: cookie } })).response.status, 401);

  const loggedIn = await request(baseUrl, "/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "user@example.com", password: "passphrase-123" }),
  });
  assert.equal(loggedIn.response.status, 200);
  const loginCookie = loggedIn.response.headers.get("set-cookie").split(";")[0];
  assert.equal((await request(baseUrl, "/api/me", { headers: { Cookie: loginCookie } })).body.user.email, "user@example.com");
});

test("rejects invalid credentials, unauthenticated writes, and raw resume fields", async (t) => {
  const baseUrl = await startTestServer(t);
  const crossOrigin = await request(baseUrl, "/api/login", {
    method: "POST",
    headers: { Origin: "https://attacker.example", "Content-Type": "application/json" },
    body: JSON.stringify({ email: "missing@example.com", password: "passphrase-123" }),
  });
  assert.equal(crossOrigin.response.status, 403);

  const rejected = await request(baseUrl, "/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "missing@example.com", password: "passphrase-123" }),
  });
  assert.equal(rejected.response.status, 401);

  const unauthorized = await request(baseUrl, "/api/screenings", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ title: "No auth", results: [] }),
  });
  assert.equal(unauthorized.response.status, 401);

  const created = await request(baseUrl, "/api/signup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: "Canopy User", email: "user@example.com", password: "passphrase-123" }),
  });
  const cookie = created.response.headers.get("set-cookie").split(";")[0];
  const rejectedSummary = await request(baseUrl, "/api/screenings", {
    method: "POST",
    headers: { "Content-Type": "application/json", Cookie: cookie },
    body: JSON.stringify({
      title: "Invalid",
      results: [{ name: "Candidate", score: 50, skillCount: 2, years: 1, jobs: [], text: "resume contents" }],
    }),
  });
  assert.equal(rejectedSummary.response.status, 400);
});

test("admin access is protected and exposes account and successful sign-in metadata only", async (t) => {
  const baseUrl = await startTestServer(t, {
    adminEmail: "admin@example.com",
    adminPassword: "admin-passphrase-123",
  });
  const created = await request(baseUrl, "/api/signup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: "Regular User", email: "regular@example.com", password: "passphrase-123" }),
  });
  const userCookie = created.response.headers.get("set-cookie").split(";")[0];

  const unauthorized = await request(baseUrl, "/api/admin/users");
  assert.equal(unauthorized.response.status, 401);
  const forbidden = await request(baseUrl, "/api/admin/users", { headers: { Cookie: userCookie } });
  assert.equal(forbidden.response.status, 403);

  const adminLogin = await request(baseUrl, "/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "admin@example.com", password: "admin-passphrase-123" }),
  });
  assert.equal(adminLogin.response.status, 200);
  assert.equal(adminLogin.body.user.isAdmin, true);
  const adminCookie = adminLogin.response.headers.get("set-cookie").split(";")[0];
  const dashboard = await request(baseUrl, "/api/admin/users", { headers: { Cookie: adminCookie } });
  assert.equal(dashboard.response.status, 200);
  assert.ok(dashboard.body.users.some((user) => user.email === "regular@example.com"));
  assert.ok(dashboard.body.loginEvents.some((event) => event.email === "regular@example.com"));
  assert.doesNotMatch(JSON.stringify(dashboard.body), /password|token/i);
});

test("adds admin and login history schema to an existing database", async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "canopy-migration-test-"));
  const databasePath = path.join(directory, "legacy.sqlite");
  const legacyDb = new DatabaseSync(databasePath);
  legacyDb.exec(`
    CREATE TABLE users (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE TABLE sessions (
      token_hash TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE TABLE screenings (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      results_json TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    INSERT INTO users VALUES ('existing-user', 'existing@example.com', 'Existing User', 'unused', '2025-01-01T00:00:00.000Z');
  `);
  legacyDb.close();
  const server = createCanopyServer({
    databasePath,
    adminEmail: "admin@example.com",
    adminPassword: "admin-passphrase-123",
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(async () => {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    server.database.close();
    await fs.rm(directory, { recursive: true, force: true });
  });

  const columns = server.database.prepare("PRAGMA table_info(users)").all().map((column) => column.name);
  assert.ok(columns.includes("is_admin"));
  assert.equal(server.database.prepare("SELECT COUNT(*) AS count FROM login_events").get().count, 0);
  assert.equal(server.database.prepare("SELECT is_admin FROM users WHERE email = ?").get("existing@example.com").is_admin, 0);
  assert.equal(server.database.prepare("SELECT is_admin FROM users WHERE email = ?").get("admin@example.com").is_admin, 1);
});

test("serves the website over HTTP", async (t) => {
  const baseUrl = await startTestServer(t);
  const response = await fetch(baseUrl + "/");
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type"), /text\/html/);
  const html = await response.text();
  assert.match(html, /Save screening/);
  assert.match(html, /id="adminLink"/);
  assert.match(html, /Successful sign-ins/);
  assert.doesNotMatch(html, /Continue with Google/);
});
