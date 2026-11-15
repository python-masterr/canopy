# Canopy

Canopy analyzes resume files and pasted text in the browser. The Node.js backend provides email/password accounts and an SQLite database for saved screening summaries. Original resume files and text are not uploaded.

## Run locally

Install Node.js 22.13 or newer, then run:

```sh
npm start
```

Open the address printed by the server (by default `http://127.0.0.1:3000`). Account registration, sign-in, and saved screenings require this server; opening `index.html` directly does not provide those features.

The database is created at `data/canopy.sqlite` on first run. Set `CANOPY_DB_PATH` to use another file, or `HOST` and `PORT` to change the listening address. Keep the database file private and back it up according to your retention needs. Saved summaries include candidate names, scores, detected skill counts, years of experience, and job matches; users can delete individual saved screenings in the page.

## Administrator dashboard

Set both `CANOPY_ADMIN_EMAIL` and `CANOPY_ADMIN_PASSWORD` in the server environment before starting the server. Use a unique, strong password and keep it out of source control. On startup, Canopy creates or promotes that account as the administrator and stores only a scrypt password hash. The administrator signs in through the normal sign-in form; the Admin link is then available in the navigation.

The dashboard shows account names, email addresses, account creation times, and successful sign-in timestamps. It does not store or expose passwords, session tokens, or failed sign-in attempts. Protect access to the server environment and database file.

## Test

```sh
npm test
```
