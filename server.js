
const express = require("express");
const crypto = require("crypto");
const dns = require("dns").promises;
const net = require("net");
const cheerio = require("cheerio");
const path = require("path");

const app = express();

app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(express.json({ limit: "10kb" }));

const PORT = process.env.PORT || 3000;
const PASSWORD = process.env.PROXY_PASSWORD;
const SECRET = process.env.SESSION_SECRET;

const ALLOWED = new Set(
  (process.env.ALLOWED_HOSTS || "")
    .split(",")
    .map(x => x.trim().toLowerCase())
    .filter(Boolean)
);

const MAX_BYTES = 2 * 1024 * 1024;

if (!PASSWORD || !SECRET || SECRET.length < 32) {
  throw new Error(
    "Set PROXY_PASSWORD and SESSION_SECRET (minimum 32 characters)."
  );
}

// Cookie parser
app.use((req, res, next) => {
  req.cookies = {};

  for (const part of (req.headers.cookie || "").split(";")) {
    const i = part.indexOf("=");

    if (i > 0) {
      req.cookies[part.slice(0, i).trim()] =
        decodeURIComponent(part.slice(i + 1).trim());
    }
  }

  next();
});

function sign(value) {
  return crypto
    .createHmac("sha256", SECRET)
    .update(value)
    .digest("base64url");
}

function safeEqual(a, b) {
  const x = Buffer.from(a);
  const y = Buffer.from(b);

  return x.length === y.length &&
    crypto.timingSafeEqual(x, y);
}

function makeToken() {
  const payload = Buffer.from(
    JSON.stringify({
      exp: Date.now() + 8 * 60 * 60 * 1000
    })
  ).toString("base64url");

  return payload + "." + sign(payload);
}

function authenticated(req, res, next) {
  const token = req.cookies.nova_session;

  if (!token) {
    return res.status(401).json({
      error: "Please log in."
    });
  }

  const [payload, signature] = token.split(".");

  if (
    !payload ||
    !signature ||
    !safeEqual(signature, sign(payload))
  ) {
    return res.status(401).json({
      error: "Invalid session."
    });
  }

  try {
    const data = JSON.parse(
      Buffer.from(payload, "base64url").toString()
    );

    if (!data.exp || data.exp < Date.now()) {
      return res.status(401).json({
        error: "Session expired."
      });
    }
  } catch {
    return res.status(401).json({
      error: "Invalid session."
    });
  }

  next();
}

function validHost(host) {
  return ALLOWED.has(host.toLowerCase());
}

function isPrivateIP(ip) {
  const family = net.isIP(ip);

  if (family === 4) {
    const parts = ip.split(".").map(Number);

    return (
      parts[0] === 0 ||
      parts[0] === 10 ||
      parts[0] === 127 ||
      parts[0] >= 224 ||
      (parts[0] === 169 && parts[1] === 254) ||
      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
      (parts[0] === 192 && parts[1] === 168) ||
      (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127)
    );
  }

  if (family === 6) {
    const value = ip.toLowerCase();

    return (
      value === "::" ||
      value === "::1" ||
      value.startsWith("fc") ||
      value.startsWith("fd") ||
      value.startsWith("fe80:") ||
      value.startsWith("::ffff:")
    );
  }

  return true;
}

async function safeTarget(value) {
  let url;

  try {
    url = new URL(value);
  } catch {
    throw new Error("Invalid URL.");
  }

  if (url.protocol !== "https:") {
    throw new Error("Only HTTPS websites are allowed.");
  }

  if (url.username || url.password) {
    throw new Error("URL credentials are not allowed.");
  }

  const host = url.hostname.toLowerCase();

  if (!validHost(host) || net.isIP(host)) {
    throw new Error("Website is not approved.");
  }

  const records = await dns.lookup(host, {
    all: true,
    verbatim: true
  });

  if (
    !records.length ||
    records.some(record => isPrivateIP(record.address))
  ) {
    throw new Error("Private network destinations are blocked.");
  }

  return url;
}

// Login
app.post("/api/login", (req, res) => {
  const password = req.body?.password;

  if (
    typeof password !== "string" ||
    !safeEqual(password, PASSWORD)
  ) {
    return res.status(401).json({
      error: "Incorrect password."
    });
  }

  res.cookie("nova_session", makeToken(), {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 8 * 60 * 60 * 1000,
    path: "/"
  });

  res.json({
    success: true
  });
});

// Logout
app.post("/api/logout", (req, res) => {
  res.clearCookie("nova_session", {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    path: "/"
  });

  res.json({
    success: true
  });
});

// Session check
app.get("/api/me", authenticated, (req, res) => {
  res.json({
    authenticated: true
  });
});

// Health check
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    name: "Nova Proxy"
  });
});

// Website reader
app.get("/api/read", authenticated, async (req, res) => {
  try {
    let input = req.query.url;

    if (
      typeof input !== "string" ||
      input.length > 2000
    ) {
      return res.status(400).json({
        error: "Enter a valid website."
      });
    }

    // Search support
    if (!/^https:\/\//i.test(input)) {
      input =
        "https://html.duckduckgo.com/html/?q=" +
        encodeURIComponent(input);
    }

    const url = await safeTarget(input);

    const response = await fetch(url, {
      redirect: "manual",
      signal: AbortSignal.timeout(12000),
      headers: {
        "User-Agent": "NovaProxy/1.0",
        "Accept": "text/html"
      }
    });

    if (response.status >= 300 && response.status < 400) {
      return res.status(400).json({
        error: "Redirects are disabled. Enter an approved destination directly."
      });
    }

    if (!response.ok) {
      return res.status(502).json({
        error: "Website returned an error."
      });
    }

    const type =
      response.headers.get("content-type") || "";

    if (!type.toLowerCase().includes("text/html")) {
      return res.status(415).json({
        error: "Only HTML pages are supported."
      });
    }

    const declared = Number(
      response.headers.get("content-length") || 0
    );

    if (declared > MAX_BYTES) {
      return res.status(413).json({
        error: "Page is too large."
      });
    }

    const reader = response.body.getReader();
    const chunks = [];
    let size = 0;

    while (true) {
      const { done, value } = await reader.read();

      if (done) break;

      size += value.length;

      if (size > MAX_BYTES) {
        await reader.cancel();

        return res.status(413).json({
          error: "Page is too large."
        });
      }

      chunks.push(value);
    }

    const html = Buffer.concat(chunks).toString("utf8");
    const $ = cheerio.load(html);

    // Remove active content.
    $(
      "script, style, noscript, iframe, object, embed, form, svg"
    ).remove();

    const title =
      $("title").text().trim() || url.hostname;

    const content = $("body")
      .text()
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 30000);

    const links = [];

    $("a[href]").each((_, el) => {
      if (links.length >= 100) return;

      try {
        const target = new URL(
          $(el).attr("href"),
          url
        );

        if (
          target.protocol === "https:" &&
          validHost(target.hostname) &&
          !target.username &&
          !target.password
        ) {
          links.push({
            text: $(el).text().trim().slice(0, 120),
            url: target.href
          });
        }
      } catch {}
    });

    res.json({
      title,
      url: url.href,
      content,
      links
    });

  } catch (error) {
    res.status(400).json({
      error: error.message || "Unable to load website."
    });
  }
});

// Static frontend
app.use(express.static(path.join(__dirname, "public")));

// Frontend fallback
app.get("/{*splat}", (req, res) => {
  res.sendFile(
    path.join(__dirname, "public", "index.html")
  );
});

app.listen(PORT, "0.0.0.0", () => {
  console.log("Nova Proxy running on port " + PORT);
});
