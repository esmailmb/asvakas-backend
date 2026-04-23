"use strict";
require("dotenv").config();

const crypto         = require("crypto");
const express        = require("express");
const { Resend }     = require("resend");
const rateLimit      = require("express-rate-limit");
const svgCaptcha     = require("svg-captcha");

const app    = express();
const PORT   = process.env.PORT || 3000;
const resendApiKey = process.env.RESEND_API_KEY;
const isLocalDevMock = process.env.LOCAL_DEV === "true";
const resend = resendApiKey ? new Resend(resendApiKey) : null;
const captchaSigningSecret = process.env.CAPTCHA_SECRET || resendApiKey || (isLocalDevMock ? "local-dev-captcha-secret" : null);
const CAPTCHA_TTL_MS = Number(process.env.CAPTCHA_TTL_MS || 10 * 60 * 1000);
const CAPTCHA_MIN_SOLVE_MS = Number(process.env.CAPTCHA_MIN_SOLVE_MS || 3000);
const recaptchaSiteKey = (process.env.RECAPTCHA_SITE_KEY || "").trim();
const recaptchaSecretKey = (process.env.RECAPTCHA_SECRET_KEY || "").trim();
const recaptchaEnabled = Boolean(recaptchaSiteKey && recaptchaSecretKey);

function normalizeCaptchaAnswer(value) {
  return String(value || "").trim().replace(/\s+/g, "").toLowerCase();
}

function safeCompareStrings(left, right) {
  const leftBuffer = Buffer.from(String(left || ""), "utf8");
  const rightBuffer = Buffer.from(String(right || ""), "utf8");
  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }
  return crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function createCaptchaToken(answer) {
  const normalizedAnswer = normalizeCaptchaAnswer(answer);
  const expiresAt = Date.now() + CAPTCHA_TTL_MS;
  const nonce = crypto.randomBytes(12).toString("hex");
  const signature = crypto
    .createHmac("sha256", captchaSigningSecret)
    .update(normalizedAnswer + "." + expiresAt + "." + nonce)
    .digest("base64url");

  return {
    token: expiresAt + "." + nonce + "." + signature,
    expiresAt,
  };
}

function verifyCaptchaToken(token, answer) {
  if (!captchaSigningSecret || !token) {
    return false;
  }

  const parts = String(token).split(".");
  if (parts.length !== 3) {
    return false;
  }

  const expiresAt = Number(parts[0]);
  const nonce = parts[1];
  const providedSignature = parts[2];
  const normalizedAnswer = normalizeCaptchaAnswer(answer);

  if (!expiresAt || !nonce || !providedSignature || !normalizedAnswer || Date.now() > expiresAt) {
    return false;
  }

  const expectedSignature = crypto
    .createHmac("sha256", captchaSigningSecret)
    .update(normalizedAnswer + "." + expiresAt + "." + nonce)
    .digest("base64url");

  return safeCompareStrings(providedSignature, expectedSignature);
}

function getRequestIp(req) {
  const forwardedFor = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
  return forwardedFor || req.ip || req.socket.remoteAddress || "";
}

async function verifyRecaptchaToken(token, remoteIp) {
  if (!recaptchaEnabled || !token) {
    return false;
  }

  const payload = new URLSearchParams({
    secret: recaptchaSecretKey,
    response: String(token),
  });
  if (remoteIp) {
    payload.set("remoteip", remoteIp);
  }

  try {
    const response = await fetch("https://www.google.com/recaptcha/api/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: payload.toString(),
    });
    if (!response.ok) {
      return false;
    }

    const data = await response.json();
    return Boolean(data.success);
  } catch (error) {
    console.error("[captcha] reCAPTCHA verification failed:", error);
    return false;
  }
}

function sanitizeSubmissionData(rawData) {
  return Object.fromEntries(
    Object.entries(rawData).filter(function ([key]) {
      return !String(key).startsWith("_");
    })
  );
}

/* ── Trust Render's reverse proxy (fixes express-rate-limit X-Forwarded-For error) ── */
app.set("trust proxy", 1);

/* ── Body parsing ── */
app.use(express.json({ limit: "32kb" }));

/* ── CORS — allow only the front-end origin ── */
app.use(function (req, res, next) {
  const origin = process.env.ALLOWED_ORIGIN || "*";
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

/* ── Rate limiting: 5 submissions per IP per 15 min ── */
app.use(
  "/submit",
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    validate: { xForwardedForHeader: false },
    message: { ok: false, error: "Too many requests. Please try again later." },
  })
);

/* ── GET /captcha-challenge ── */
app.get("/captcha-config", function (_req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (recaptchaEnabled) {
    return res.json({ ok: true, provider: "recaptcha", siteKey: recaptchaSiteKey });
  }
  if (captchaSigningSecret) {
    return res.json({ ok: true, provider: "image" });
  }

  return res.status(503).json({ ok: false, error: "Security check is unavailable right now." });
});

app.get("/captcha-challenge", function (_req, res) {
  if (!captchaSigningSecret) {
    return res.status(503).json({ ok: false, error: "Security check is unavailable right now." });
  }

  const captcha = svgCaptcha.create({
    size: 5,
    noise: 4,
    color: true,
    background: "#f6f8fb",
    ignoreChars: "0Oo1Il",
  });
  const challenge = createCaptchaToken(captcha.text);

  res.setHeader("Cache-Control", "no-store");
  return res.json({ ok: true, svg: captcha.data, token: challenge.token, expiresAt: challenge.expiresAt });
});

/* ── POST /submit ── */
app.post("/submit", async function (req, res) {
  const rawData = req.body;

  /* Basic validation */
  if (!rawData || typeof rawData !== "object") {
    return res.status(400).json({ ok: false, error: "Invalid request." });
  }
  const formStartedAt = Number(rawData._formStartedAt || 0);
  const captchaToken = rawData._captchaToken || "";
  const captchaAnswer = rawData._captchaAnswer || "";
  const recaptchaToken = rawData._recaptchaToken || "";

  if (!formStartedAt || Date.now() - formStartedAt < CAPTCHA_MIN_SOLVE_MS) {
    return res.status(400).json({ ok: false, error: "Please take a moment to complete the security check and try again." });
  }

  const passedImageCaptcha = verifyCaptchaToken(captchaToken, captchaAnswer);
  const passedRecaptcha = recaptchaEnabled && recaptchaToken
    ? await verifyRecaptchaToken(recaptchaToken, getRequestIp(req))
    : false;

  if (!passedImageCaptcha && !passedRecaptcha) {
    if (recaptchaEnabled) {
      return res.status(400).json({ ok: false, error: "Please complete the Google security check and try again." });
    }
    return res.status(400).json({ ok: false, error: "Security check failed. Please enter the code shown and try again." });
  }

  const data = sanitizeSubmissionData(rawData);
  const fullName = (data["Full Name"] || [data["First Name"], data["Last Name"]].filter(Boolean).join(" ")).trim();
  const email    = (data["Email"] || "").trim();
  if (!fullName || !email) {
    return res.status(400).json({ ok: false, error: "Name and email are required." });
  }
  /* Simple email format check */
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ ok: false, error: "Invalid email address." });
  }
  if (!data["Full Name"]) {
    data["Full Name"] = fullName;
  }

  // Build HTML table rows for all fields
  function buildTableRows(obj) {
    return Object.entries(obj)
      .map(([k, v]) => `<tr><td style="font-weight:bold;padding:8px 0;width:40%;">${k}:</td><td style="padding:8px 0;">${v}</td></tr>`)
      .join("");
  }

  const serviceType = data["Service Type"] || "New Inquiry";
  const fromEmail = process.env.FROM_EMAIL || "info@asvakas.com";
  const toEmail   = process.env.TO_EMAIL   || "info@asvakas.com";

  if (isLocalDevMock && !resend) {
    console.log("[submit] LOCAL_DEV mock submission:", JSON.stringify(data));
    return res.json({ ok: true, mocked: true });
  }

  if (!resend) {
    console.error("[submit] Missing RESEND_API_KEY. Email delivery is not configured.");
    return res.status(500).json({ ok: false, error: "Email service is not configured. Please email us directly." });
  }

  // HTML email for admin (styled like user receipt)
  const adminHtml = `
    <div style="max-width:600px;margin:0 auto;padding:32px 24px;border:1px solid #e0e0e0;border-radius:12px;font-family:'Segoe UI',Arial,sans-serif;background:#fafbfc;">
      <h2 style="color:#1a237e;font-size:2rem;margin-bottom:18px;font-weight:700;">New Project Inquiry</h2>
      <table style="width:100%;border-collapse:collapse;font-size:1.08rem;">
        ${Object.entries(data).map(([k, v]) => `
          <tr>
            <td style="font-weight:bold;padding:8px 0 8px 0;width:38%;color:#222;vertical-align:top;">${k}:</td>
            <td style="padding:8px 0 8px 0;color:#222;">${v}</td>
          </tr>`).join('')}
      </table>
    </div>
  `;
  // Plain text fallback
  const lines = Object.entries(data)
    .map(function ([k, v]) { return k + ": " + v; })
    .join("\n");

  // HTML email for user receipt
  const userHtml = `
    <div style="max-width:500px;margin:0 auto;padding:24px;border:1px solid #e0e0e0;border-radius:8px;font-family:sans-serif;background:#fafbfc;">
      <h2 style="color:#1a237e;margin-bottom:16px;">Thank you for contacting Asvakas</h2>
      <p>We have received your inquiry and will get back to you soon. Here is a summary of your request:</p>
      <table style="width:100%;border-collapse:collapse;">${buildTableRows(data)}</table>
      <p style="margin-top:16px;">If you have any questions, reply to this email or contact us at info@asvakas.com.</p>
    </div>
  `;

  console.log("[submit] Sending email — from:", fromEmail, "to:", toEmail, "subject: Project Inquiry —", serviceType);

  try {
    // Send to admin
    const { data: sendData, error } = await resend.emails.send({
      from:     "Asvakas Website <" + fromEmail + ">",
      to:       [toEmail],
      reply_to: email,
      subject:  "Project Inquiry \u2014 " + serviceType,
      text:     lines,
      html:     adminHtml,
    });
    if (error) {
      console.error("[submit] Resend error (admin):", JSON.stringify(error));
      return res.status(500).json({ ok: false, error: "Failed to send. Please email us directly." });
    }
    // Send receipt to user
    await resend.emails.send({
      from:     "Asvakas Website <" + fromEmail + ">",
      to:       [email],
      subject:  "We received your inquiry",
      text:     lines,
      html:     userHtml,
    });
    console.log("[submit] Emails sent successfully. Resend ID:", sendData && sendData.id);
    return res.json({ ok: true });
  } catch (err) {
    console.error("[submit] Resend exception:", err.message);
    return res.status(500).json({ ok: false, error: "Failed to send. Please email us directly." });
  }
});

/* ── Health check (Render uses this to verify the service is up) ── */
app.get("/health", function (_req, res) {
  res.json({ status: "ok" });
});

app.listen(PORT, function () {
  console.log("Asvakas contact server running on port " + PORT);
});
