# Shortify

A production-ready URL shortener built with Node.js and Express. Shorten URLs, track visits with geo-analytics, and generate QR codes — with a focus on performance and security.

## Features

- **URL Shortening** — Generates unique short IDs with pre-generated slug pool via background workers
- **QR Code Generation** — Auto-generated QR code for every shortened URL
- **Visit Analytics** — Tracks visit history with IP geolocation (country, region, city) and an interactive world map
- **Custom Short IDs & Expiry** — Edit the short ID and set/update expiry dates
- **Authentication** — Email/password signup, OTP-based login, and Google OAuth
- **Safe Browsing** — URLs are checked against the Google Safe Browsing API before being saved
- **Rate Limiting** — Global rate limiter on all routes

## Tech Stack

| Layer | Technology |
|---|---|
| Server | Node.js, Express |
| Database | MongoDB (Mongoose) |
| Cache / Queue broker | Redis (ioredis) |
| Background jobs | BullMQ |
| Templating | EJS, ejs-mate |
| Auth | express-session, bcryptjs, Google OAuth 2.0 |
| Email | Nodemailer |

## Architecture

The app runs as **three separate processes** managed by `concurrently`:

- `app.js` — Express HTTP server
- `workers/slugWorker.js` — Pre-generates short ID slugs into a Redis set so slug assignment at request time is instant
- `workers/visitWorker.js` — Processes visit analytics (geo-lookup via ip-api.com, DB write) asynchronously after redirection, keeping redirect latency low (~30ms vs ~570ms synchronously)

## Getting Started

**Prerequisites:** Node.js, MongoDB, Redis

**1. Clone and install**
```bash
git clone <repo-url>
cd shortify
npm install
```

**2. Configure environment — create a `.env` file:**
```env
PORT=8000
MONGO_URL=mongodb://localhost:27017/URLshortener
SESSION_SECRET=your_secret

BASE_URL=http://localhost:8000

GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_REDIRECT_URL=http://localhost:8000/auth/google/callback

GOOGLE_SAFE_BROWSING_KEY=

EMAIL_USER=
EMAIL_PASS=

REDIS_URL=redis://localhost:6379
```

**3. Run**
```bash
npm run dev      # development (nodemon)
npm start        # production
```

## Project Structure

```
app.js                  # Express app entry point
workers/                # BullMQ background workers
queues/                 # BullMQ queue definitions
controllers/            # Route handlers
middlewares/            # Auth, validation, rate limiting, safe browsing
models/                 # Mongoose schemas (User, Url)
routes/                 # Express routers
views/                  # EJS templates
config/                 # Redis connection
```
