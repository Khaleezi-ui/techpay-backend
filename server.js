// ─── server.js ────────────────────────────────────────────────────────────────
// TechPay API — Node.js + Express + PostgreSQL
// npm install express pg bcryptjs jsonwebtoken multer dotenv cors
// ─────────────────────────────────────────────────────────────────────────────

require("dotenv").config();
const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const cors = require("cors");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3001;

// ─── Middleware ────────────────────────────────────────────────────────────────
app.use(cors({ origin: process.env.FRONTEND_URL || "http://localhost:3000" }));
app.use(express.json());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// ─── PostgreSQL ────────────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
});
// ─── Multer (subida de imágenes locales) ──────────────────────────────────────
// Para producción, reemplazar con Cloudinary o S3 (ver comentario al final)
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, uploadDir),
  filename: (_, file, cb) => {
    const unique = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
    cb(null, `${unique}${path.extname(file.originalname)}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (_, file, cb) => {
    const ok = ["image/jpeg", "image/png"].includes(file.mimetype);
    cb(ok ? null : new Error("Solo se aceptan JPG y PNG"), ok);
  },
});

// ─── Auth Middleware ───────────────────────────────────────────────────────────
const auth = (requiredRole = null) => (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Token requerido" });
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET || "changeme");
    req.user = payload;
    if (requiredRole && payload.role !== requiredRole)
      return res.status(403).json({ error: "Acceso denegado" });
    next();
  } catch {
    res.status(401).json({ error: "Token inválido o expirado" });
  }
};

// ─── Database Schema ───────────────────────────────────────────────────────────
const initDB = async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role VARCHAR(20) NOT NULL CHECK (role IN ('admin', 'technician')),
      display_name VARCHAR(100),
      active BOOLEAN DEFAULT true,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS supervisors (
      id SERIAL PRIMARY KEY,
      name VARCHAR(100) UNIQUE NOT NULL,
      active BOOLEAN DEFAULT true,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS resources (
      id SERIAL PRIMARY KEY,
      number VARCHAR(50) UNIQUE NOT NULL,
      description TEXT,
      active BOOLEAN DEFAULT true,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS technicians (
      id SERIAL PRIMARY KEY,
      name VARCHAR(100) UNIQUE NOT NULL,
      active BOOLEAN DEFAULT true,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS works (
      id SERIAL PRIMARY KEY,
      start_datetime TIMESTAMPTZ NOT NULL,
      end_datetime TIMESTAMPTZ NOT NULL,
      technician VARCHAR(100) NOT NULL,
      assistant VARCHAR(100),
      supervisor VARCHAR(100) NOT NULL,
      resource VARCHAR(50) NOT NULL,
      sa VARCHAR(100),
      work_order VARCHAR(100),
      description TEXT,
      auth_image_url TEXT,
      created_by INTEGER REFERENCES users(id),
      created_at TIMESTAMPTZ DEFAULT NOW(),
      CONSTRAINT end_after_start CHECK (end_datetime > start_datetime)
    );
  `);

  // Seed admin user if not exists
  const adminExists = await pool.query("SELECT id FROM users WHERE username = 'admin'");
  if (adminExists.rows.length === 0) {
    const hash = await bcrypt.hash("admin123", 12);
    await pool.query(
      "INSERT INTO users (username, password_hash, role, display_name) VALUES ($1, $2, $3, $4)",
      ["admin", hash, "admin", "Administrador"]
    );
    console.log("✓ Usuario admin creado (admin / admin123)");
  }
};

// ─── AUTH Routes ───────────────────────────────────────────────────────────────
app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: "Usuario y contraseña requeridos" });

  const result = await pool.query(
    "SELECT * FROM users WHERE username = $1 AND active = true", [username]
  );
  const user = result.rows[0];
  if (!user || !(await bcrypt.compare(password, user.password_hash)))
    return res.status(401).json({ error: "Credenciales incorrectas" });

  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role, displayName: user.display_name },
    process.env.JWT_SECRET || "changeme",
    { expiresIn: "8h" }
  );
  res.json({ token, user: { id: user.id, username: user.username, role: user.role, displayName: user.display_name } });
});

// ─── SUPERVISORS ───────────────────────────────────────────────────────────────
app.get("/api/supervisors", auth(), async (req, res) => {
  const r = await pool.query("SELECT * FROM supervisors ORDER BY name");
  res.json(r.rows);
});

app.post("/api/supervisors", auth("admin"), async (req, res) => {
  const { name, active = true } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: "Nombre requerido" });
  const clean = name.trim().toUpperCase();
  if (!/^[A-ZÁÉÍÓÚÜÑ\s]+$/.test(clean))
    return res.status(400).json({ error: "Solo letras mayúsculas permitidas" });
  try {
    const r = await pool.query(
      "INSERT INTO supervisors (name, active) VALUES ($1, $2) RETURNING *",
      [clean, active]
    );
    res.status(201).json(r.rows[0]);
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "Ya existe un supervisor con ese nombre" });
    throw e;
  }
});

app.put("/api/supervisors/:id", auth("admin"), async (req, res) => {
  const { name, active } = req.body;
  const clean = name?.trim().toUpperCase();
  try {
    const r = await pool.query(
      "UPDATE supervisors SET name = COALESCE($1, name), active = COALESCE($2, active) WHERE id = $3 RETURNING *",
      [clean, active, req.params.id]
    );
    if (!r.rows[0]) return res.status(404).json({ error: "No encontrado" });
    res.json(r.rows[0]);
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "Nombre duplicado" });
    throw e;
  }
});

app.delete("/api/supervisors/:id", auth("admin"), async (req, res) => {
  await pool.query("DELETE FROM supervisors WHERE id = $1", [req.params.id]);
  res.json({ success: true });
});

// ─── RESOURCES ─────────────────────────────────────────────────────────────────
app.get("/api/resources", auth(), async (req, res) => {
  const r = await pool.query("SELECT * FROM resources ORDER BY number");
  res.json(r.rows);
});

app.post("/api/resources", auth("admin"), async (req, res) => {
  const { number, description, active = true } = req.body;
  if (!number?.trim()) return res.status(400).json({ error: "Número requerido" });
  try {
    const r = await pool.query(
      "INSERT INTO resources (number, description, active) VALUES ($1, $2, $3) RETURNING *",
      [number.trim(), description, active]
    );
    res.status(201).json(r.rows[0]);
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "Número de recurso duplicado" });
    throw e;
  }
});

app.put("/api/resources/:id", auth("admin"), async (req, res) => {
  const { number, description, active } = req.body;
  const r = await pool.query(
    "UPDATE resources SET number = COALESCE($1, number), description = COALESCE($2, description), active = COALESCE($3, active) WHERE id = $4 RETURNING *",
    [number?.trim(), description, active, req.params.id]
  );
  if (!r.rows[0]) return res.status(404).json({ error: "No encontrado" });
  res.json(r.rows[0]);
});

app.delete("/api/resources/:id", auth("admin"), async (req, res) => {
  await pool.query("DELETE FROM resources WHERE id = $1", [req.params.id]);
  res.json({ success: true });
});

// ─── TECHNICIANS ───────────────────────────────────────────────────────────────
app.get("/api/technicians", auth(), async (req, res) => {
  const r = await pool.query("SELECT * FROM technicians ORDER BY name");
  res.json(r.rows);
});

app.post("/api/technicians", auth("admin"), async (req, res) => {
  const { name, active = true } = req.body;
  const clean = name?.trim().toUpperCase();
  if (!clean) return res.status(400).json({ error: "Nombre requerido" });
  if (!/^[A-ZÁÉÍÓÚÜÑ\s]+$/.test(clean))
    return res.status(400).json({ error: "Solo letras mayúsculas permitidas" });
  try {
    const r = await pool.query(
      "INSERT INTO technicians (name, active) VALUES ($1, $2) RETURNING *",
      [clean, active]
    );
    res.status(201).json(r.rows[0]);
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "Técnico duplicado" });
    throw e;
  }
});

app.put("/api/technicians/:id", auth("admin"), async (req, res) => {
  const { name, active } = req.body;
  const clean = name?.trim().toUpperCase();
  const r = await pool.query(
    "UPDATE technicians SET name = COALESCE($1, name), active = COALESCE($2, active) WHERE id = $3 RETURNING *",
    [clean, active, req.params.id]
  );
  if (!r.rows[0]) return res.status(404).json({ error: "No encontrado" });
  res.json(r.rows[0]);
});

app.delete("/api/technicians/:id", auth("admin"), async (req, res) => {
  await pool.query("DELETE FROM technicians WHERE id = $1", [req.params.id]);
  res.json({ success: true });
});

// ─── WORKS ─────────────────────────────────────────────────────────────────────
app.get("/api/works", auth(), async (req, res) => {
  const { from, to, technician } = req.query;
  let query = "SELECT * FROM works WHERE 1=1";
  const params = [];
  if (from) { params.push(from); query += ` AND start_datetime >= $${params.length}`; }
  if (to) { params.push(to); query += ` AND start_datetime <= $${params.length}`; }
  if (technician) { params.push(`%${technician.toUpperCase()}%`); query += ` AND technician ILIKE $${params.length}`; }
  query += " ORDER BY start_datetime DESC";
  const r = await pool.query(query, params);
  res.json(r.rows);
});

app.post("/api/works", auth(), upload.single("authImage"), async (req, res) => {
  const {
    startDatetime, endDatetime, technician, assistant,
    supervisor, resource, sa, workOrder, description,
  } = req.body;

  // Validations
  if (!startDatetime || !endDatetime || !technician || !supervisor || !resource)
    return res.status(400).json({ error: "Campos obligatorios faltantes" });
  if (new Date(endDatetime) <= new Date(startDatetime))
    return res.status(400).json({ error: "La fecha/hora de fin debe ser posterior al inicio" });
  const cleanTech = technician.trim().toUpperCase();
  if (!/^[A-ZÁÉÍÓÚÜÑ\s]+$/.test(cleanTech))
    return res.status(400).json({ error: "Técnico: solo letras mayúsculas" });

  const imageUrl = req.file
    ? `${process.env.BASE_URL || "http://localhost:" + PORT}/uploads/${req.file.filename}`
    : null;

  const r = await pool.query(
    `INSERT INTO works
     (start_datetime, end_datetime, technician, assistant, supervisor, resource, sa, work_order, description, auth_image_url, created_by)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,
    [startDatetime, endDatetime, cleanTech, assistant, supervisor, resource, sa, workOrder, description, imageUrl, req.user.id]
  );
  res.status(201).json(r.rows[0]);
});

app.put("/api/works/:id", auth("admin"), upload.single("authImage"), async (req, res) => {
  const {
    startDatetime, endDatetime, technician, assistant,
    supervisor, resource, sa, workOrder, description,
  } = req.body;

  if (startDatetime && endDatetime && new Date(endDatetime) <= new Date(startDatetime))
    return res.status(400).json({ error: "Fecha/hora inválida" });

  const existing = await pool.query("SELECT * FROM works WHERE id = $1", [req.params.id]);
  if (!existing.rows[0]) return res.status(404).json({ error: "No encontrado" });

  const imageUrl = req.file
    ? `${process.env.BASE_URL || "http://localhost:" + PORT}/uploads/${req.file.filename}`
    : existing.rows[0].auth_image_url;

  const r = await pool.query(
    `UPDATE works SET
      start_datetime = COALESCE($1, start_datetime),
      end_datetime = COALESCE($2, end_datetime),
      technician = COALESCE($3, technician),
      assistant = COALESCE($4, assistant),
      supervisor = COALESCE($5, supervisor),
      resource = COALESCE($6, resource),
      sa = COALESCE($7, sa),
      work_order = COALESCE($8, work_order),
      description = COALESCE($9, description),
      auth_image_url = $10
     WHERE id = $11 RETURNING *`,
    [startDatetime, endDatetime, technician?.trim().toUpperCase(), assistant,
      supervisor, resource, sa, workOrder, description, imageUrl, req.params.id]
  );
  res.json(r.rows[0]);
});

app.delete("/api/works/:id", auth("admin"), async (req, res) => {
  await pool.query("DELETE FROM works WHERE id = $1", [req.params.id]);
  res.json({ success: true });
});

// ─── USERS (admin only) ────────────────────────────────────────────────────────
app.get("/api/users", auth("admin"), async (req, res) => {
  const r = await pool.query("SELECT id, username, role, display_name, active, created_at FROM users ORDER BY username");
  res.json(r.rows);
});

app.post("/api/users", auth("admin"), async (req, res) => {
  const { username, password, role, display_name } = req.body;
  if (!username || !password || !role)
    return res.status(400).json({ error: "username, password y role son requeridos" });
  if (!["admin", "technician"].includes(role))
    return res.status(400).json({ error: "role debe ser admin o technician" });
  const hash = await bcrypt.hash(password, 12);
  try {
    const r = await pool.query(
      "INSERT INTO users (username, password_hash, role, display_name) VALUES ($1,$2,$3,$4) RETURNING id, username, role, display_name",
      [username, hash, role, display_name]
    );
    res.status(201).json(r.rows[0]);
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "Username ya existe" });
    throw e;
  }
});

app.put("/api/users/:id", auth("admin"), async (req, res) => {
  const { password, role, display_name, active } = req.body;
  const updates = [];
  const params = [];

  if (password) { params.push(await bcrypt.hash(password, 12)); updates.push(`password_hash = $${params.length}`); }
  if (role) { params.push(role); updates.push(`role = $${params.length}`); }
  if (display_name) { params.push(display_name); updates.push(`display_name = $${params.length}`); }
  if (active !== undefined) { params.push(active); updates.push(`active = $${params.length}`); }

  if (!updates.length) return res.status(400).json({ error: "Nada que actualizar" });
  params.push(req.params.id);
  const r = await pool.query(
    `UPDATE users SET ${updates.join(", ")} WHERE id = $${params.length} RETURNING id, username, role, display_name, active`,
    params
  );
  if (!r.rows[0]) return res.status(404).json({ error: "No encontrado" });
  res.json(r.rows[0]);
});

// ─── REPORTS (CSV raw data for Excel) ─────────────────────────────────────────
app.get("/api/reports/csv", auth("admin"), async (req, res) => {
  const { from, to, technician } = req.query;
  let query = "SELECT * FROM works WHERE 1=1";
  const params = [];
  if (from) { params.push(from); query += ` AND start_datetime >= $${params.length}`; }
  if (to) { params.push(to); query += ` AND start_datetime <= $${params.length}`; }
  if (technician) { params.push(`%${technician}%`); query += ` AND technician ILIKE $${params.length}`; }
  query += " ORDER BY start_datetime DESC";

  const r = await pool.query(query, params);
  const headers = ["fecha_inicio", "fecha_fin", "tecnico", "ayudante", "supervisor", "recurso", "SA", "orden_trabajo", "descripcion"];
  const rows = r.rows.map((w) => [
    w.start_datetime?.toISOString(), w.end_datetime?.toISOString(),
    w.technician, w.assistant || "", w.supervisor, w.resource,
    w.sa || "", w.work_order || "", `"${(w.description || "").replace(/"/g, '""')}"`,
  ]);
  const csv = [headers, ...rows].map((row) => row.join(";")).join("\n");
  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="reporte_techpay_${Date.now()}.csv"`);
  res.send("\uFEFF" + csv);
});

// ─── Global error handler ──────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error(err);
  if (err.code === "LIMIT_FILE_SIZE") return res.status(413).json({ error: "Imagen demasiado grande (máx 5MB)" });
  res.status(500).json({ error: err.message || "Error interno del servidor" });
});

// ─── Start ─────────────────────────────────────────────────────────────────────
(async () => {
  await initDB();
  app.listen(PORT, () => console.log(`\n🚀 TechPay API corriendo en http://localhost:${PORT}\n`));
})();

/*
─────────────────────────────────────────────────────────────────────────────────
  ALMACENAMIENTO EN LA NUBE (reemplazar multer.diskStorage con esto en producción)
─────────────────────────────────────────────────────────────────────────────────

  OPCIÓN A — Cloudinary:
  npm install cloudinary multer-storage-cloudinary

  const cloudinary = require('cloudinary').v2;
  const { CloudinaryStorage } = require('multer-storage-cloudinary');
  cloudinary.config({ cloud_name: process.env.CLOUDINARY_NAME, api_key: process.env.CLOUDINARY_KEY, api_secret: process.env.CLOUDINARY_SECRET });
  const storage = new CloudinaryStorage({ cloudinary, params: { folder: 'techpay', allowed_formats: ['jpg','png'] } });

  OPCIÓN B — AWS S3:
  npm install @aws-sdk/client-s3 multer-s3

  const { S3Client } = require('@aws-sdk/client-s3');
  const multerS3 = require('multer-s3');
  const s3 = new S3Client({ region: process.env.AWS_REGION });
  const storage = multerS3({ s3, bucket: process.env.S3_BUCKET, key: (_, file, cb) => cb(null, `uploads/${Date.now()}-${file.originalname}`) });
─────────────────────────────────────────────────────────────────────────────────
*/
