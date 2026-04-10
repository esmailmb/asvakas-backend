"use strict";
require("dotenv").config();

const express        = require("express");
const { Resend }     = require("resend");
const rateLimit      = require("express-rate-limit");

const app    = express();
const PORT   = process.env.PORT || 3000;
const resend = new Resend(process.env.RESEND_API_KEY);

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

/* ── POST /submit ── */
app.post("/submit", async function (req, res) {
  const data = req.body;

  /* Basic validation */
  if (!data || typeof data !== "object") {
    return res.status(400).json({ ok: false, error: "Invalid request." });
  }
  const fullName = (data["Full Name"] || "").trim();
  const email    = (data["Email"]     || "").trim();
  if (!fullName || !email) {
    return res.status(400).json({ ok: false, error: "Name and email are required." });
  }
  /* Simple email format check */
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ ok: false, error: "Invalid email address." });
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

  // HTML email for admin
  const adminHtml = `
    <div style="max-width:500px;margin:0 auto;padding:24px;border:1px solid #e0e0e0;border-radius:8px;font-family:sans-serif;background:#fafbfc;">
      <h2 style="color:#1a237e;margin-bottom:16px;">New Project Inquiry</h2>
      <table style="width:100%;border-collapse:collapse;">${buildTableRows(data)}</table>
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
