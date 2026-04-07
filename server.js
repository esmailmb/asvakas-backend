"use strict";
require("dotenv").config();

const express    = require("express");
const nodemailer = require("nodemailer");
const rateLimit  = require("express-rate-limit");

const app  = express();
const PORT = process.env.PORT || 3000;

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
    message: { ok: false, error: "Too many requests. Please try again later." },
  })
);

/* ── Nodemailer transporter (configured by env vars) ── */
const transporter = nodemailer.createTransport({
  host:   process.env.SMTP_HOST,
  port:   parseInt(process.env.SMTP_PORT || "587", 10),
  secure: process.env.SMTP_SECURE === "true",   /* true for port 465 */
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

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

  /* Build email body */
  const serviceType = data["Service Type"] || "New Inquiry";
  const lines = Object.entries(data)
    .map(function ([k, v]) { return k + ": " + v; })
    .join("\n");

  try {
    await transporter.sendMail({
      from:    '"Asvakas Website" <' + process.env.SMTP_USER + ">",
      to:      process.env.TO_EMAIL || "info@asvakas.com",
      replyTo: email,
      subject: "Project Inquiry \u2014 " + serviceType,
      text:    lines,
    });
    return res.json({ ok: true });
  } catch (err) {
    console.error("Mail send error:", err.message);
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
