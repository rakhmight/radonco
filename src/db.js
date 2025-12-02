// src/db.js
// Работа с SQLite (better-sqlite3) для RadOnco
import Database from "better-sqlite3";
import bcrypt from "bcryptjs";

let db;

/**
 * Инициализация БД (один экземпляр на всё приложение)
 */
export function initDb() {
  if (db) return db;

  const dbFile = process.env.DB_FILE || "radonco.db";
  db = new Database(dbFile);
  db.pragma("foreign_keys = ON");

  // === Пользователи (врачи/админы) ===
  db.prepare(`
    CREATE TABLE IF NOT EXISTS users (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      login         TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      full_name     TEXT,
      role          TEXT NOT NULL DEFAULT 'doctor', -- doctor | admin
      telegram_id   TEXT,
      created_at    TEXT DEFAULT (datetime('now', '+5 hours')),
      updated_at    TEXT DEFAULT (datetime('now', '+5 hours'))
    )
  `).run();

  // === Пациенты ===
  db.prepare(`
    CREATE TABLE IF NOT EXISTS patients (
      id                 INTEGER PRIMARY KEY AUTOINCREMENT,
      patient_id         TEXT NOT NULL UNIQUE,          
      full_name          TEXT NOT NULL,
      birth_date         TEXT,
      region             TEXT,
      diagnosis          TEXT,
      topometry          TEXT,
      method_gray        REAL,                          
      diary              TEXT,
      complaints         TEXT,
      prescriptions      TEXT,
      discharge_summary  TEXT,
      complications      TEXT,
      status             TEXT DEFAULT 'on_treatment',   
      created_by         INTEGER,
      updated_by         INTEGER,
      created_at         TEXT DEFAULT (datetime('now', '+5 hours')),
      updated_at         TEXT DEFAULT (datetime('now', '+5 hours')),
      FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL,
      FOREIGN KEY(updated_by) REFERENCES users(id) ON DELETE SET NULL
    )
  `).run();

  
  db.prepare(`
    CREATE TABLE IF NOT EXISTS patient_changes (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      patient_id  INTEGER NOT NULL,     
      user_id     INTEGER,              
      source      TEXT,                 
      description TEXT,
      changed_at  TEXT DEFAULT (datetime('now', '+5 hours')),
      FOREIGN KEY(patient_id) REFERENCES patients(id) ON DELETE CASCADE,
      FOREIGN KEY(user_id)   REFERENCES users(id)    ON DELETE SET NULL
    )
  `).run();

 
  db.prepare(`
    CREATE TABLE IF NOT EXISTS patient_views (
      id                  INTEGER PRIMARY KEY AUTOINCREMENT,
      patient_id          INTEGER NOT NULL,
      user_id             INTEGER NOT NULL,
      last_seen_change_id INTEGER DEFAULT 0,
      UNIQUE(patient_id, user_id),
      FOREIGN KEY(patient_id) REFERENCES patients(id) ON DELETE CASCADE,
      FOREIGN KEY(user_id)   REFERENCES users(id)    ON DELETE CASCADE
    )
  `).run();

  return db;
}

export function generateNextPatientId() {
  if (!db) initDb();

  const row = db
    .prepare(
      `
      SELECT MAX(CAST(patient_id AS INTEGER)) AS max_num
      FROM patients
      WHERE patient_id GLOB '[0-9]*'
    `
    )
    .get();

  const maxNum = row && row.max_num ? Number(row.max_num) : 0;
  const base = Math.max(maxNum, 999); // гарантируем минимум 4 цифры
  const next = base + 1;

  return String(next);
}

/**
 * Создать админа по умолчанию, если база пустая.
 * Можно вызвать без аргументов: логин/пароль возьмутся из env или "admin"/"admin".
 */
export function ensureAdminUser(login, password) {
  if (!db) initDb();

  // логин/пароль по умолчанию
  const adminLogin = login || process.env.ADMIN_LOGIN || "admin";
  const adminPassword = password || process.env.ADMIN_PASSWORD || "admin";

  const passwordHash = bcrypt.hashSync(adminPassword, 10);

  // ищем пользователя с таким логином
  const existing = db
    .prepare("SELECT * FROM users WHERE login = ?")
    .get(adminLogin);

  if (existing) {
    // обновляем пароль и роль, если админ уже есть
    db.prepare(
      `
      UPDATE users
      SET password_hash = @password_hash,
          role          = 'admin',
          updated_at    = datetime('now', '+5 hours')
      WHERE id = @id
    `
    ).run({
      id: existing.id,
      password_hash: passwordHash,
    });
  } else {
    // создаём нового админа
    db.prepare(
      `
      INSERT INTO users (login, password_hash, full_name, role,
                         created_at, updated_at)
      VALUES (@login, @password_hash, @full_name, 'admin',
              datetime('now', '+5 hours'),
              datetime('now', '+5 hours'))
    `
    ).run({
      login: adminLogin,
      password_hash: passwordHash,
      full_name: "Главный администратор",
    });
  }

  console.log(
    `[db] Админ-пользователь "${adminLogin}" готов. Можно входить с этим паролем.`
  );
}


/* ==================== USERS ==================== */

export function findUserByLogin(login) {
  if (!db) initDb();
  return db
    .prepare("SELECT * FROM users WHERE login = ?")
    .get(login);
}

export function findUserByTelegramId(telegramId) {
  if (!db) initDb();
  return db
    .prepare("SELECT * FROM users WHERE telegram_id = ?")
    .get(String(telegramId));
}

export function listUsers() {
  if (!db) initDb();
  return db
    .prepare("SELECT * FROM users ORDER BY id ASC")
    .all();
}

export function getUserById(id) {
  if (!db) initDb();
  return db
    .prepare("SELECT * FROM users WHERE id = ?")
    .get(id);
}

/**
 * createUser ожидает уже HASH пароля.
 * passwordHash — результат bcrypt.hashSync(...)
 */
export function createUser({ login, passwordHash, full_name, role, telegram_id }) {
  if (!db) initDb();

  const stmt = db.prepare(`
    INSERT INTO users (login, password_hash, full_name, role, telegram_id,
                       created_at, updated_at)
    VALUES (@login, @password_hash, @full_name, @role, @telegram_id,
            datetime('now', '+5 hours'), datetime('now', '+5 hours'))
  `);

  const res = stmt.run({
    login,
    password_hash: passwordHash,
    full_name: full_name || null,
    role: role || "doctor",
    telegram_id: telegram_id || null,
  });

  return res.lastInsertRowid;
}

export function updateUser(
  id,
  { login, passwordHash, full_name, role, telegram_id }
) {
  if (!db) initDb();

  const current = getUserById(id);
  if (!current) throw new Error("Пользователь не найден");

  const data = {
    id,
    login: login ?? current.login,
    password_hash: passwordHash ?? current.password_hash,
    full_name: full_name ?? current.full_name,
    role: role ?? current.role,
    telegram_id: telegram_id ?? current.telegram_id,
  };

  const stmt = db.prepare(`
    UPDATE users
    SET login         = @login,
        password_hash = @password_hash,
        full_name     = @full_name,
        role          = @role,
        telegram_id   = @telegram_id,
        updated_at    = datetime('now', '+5 hours')
    WHERE id = @id
  `);

  stmt.run(data);
}

export function deleteUserById(id) {
  if (!db) initDb();
  db.prepare("DELETE FROM users WHERE id = ?").run(id);
}

/* ==================== PATIENTS ==================== */

export function listPatientsForUser(userId) {
  if (!db) initDb();

  const stmt = db.prepare(`
    SELECT
      p.id,
      p.patient_id,
      p.full_name,
      p.birth_date,
      p.region,
      p.diagnosis,
      p.status,
      p.created_at,
      p.updated_at,
      MAX(pc.id) AS last_change_id,
      MAX(pc.changed_at) AS last_change_at,
      COALESCE(pv.last_seen_change_id, 0) AS last_seen_change_id,
      CASE
        WHEN MAX(pc.id) IS NOT NULL
         AND MAX(pc.id) > COALESCE(pv.last_seen_change_id, 0)
        THEN 1 ELSE 0
      END AS has_unread
    FROM patients p
    LEFT JOIN patient_changes pc
      ON pc.patient_id = p.id
    LEFT JOIN patient_views pv
      ON pv.patient_id = p.id AND pv.user_id = @userId
    GROUP BY p.id
    ORDER BY p.created_at DESC, p.id DESC
  `);

  return stmt.all({ userId });
}

export function getPatientByRowId(id) {
  if (!db) initDb();
  return db
    .prepare("SELECT * FROM patients WHERE id = ?")
    .get(id);
}

export function getPatientByPatientId(patientId) {
  if (!db) initDb();
  return db
    .prepare("SELECT * FROM patients WHERE patient_id = ?")
    .get(String(patientId));
}

export function createPatient(data) {
  if (!db) initDb();

  const stmt = db.prepare(`
    INSERT INTO patients (
      patient_id,
      full_name,
      birth_date,
      region,
      diagnosis,
      topometry,
      method_gray,
      diary,
      complaints,
      prescriptions,
      discharge_summary,
      complications,
      status,
      created_by,
      updated_by,
      created_at,
      updated_at
    ) VALUES (
      @patient_id,
      @full_name,
      @birth_date,
      @region,
      @diagnosis,
      @topometry,
      @method_gray,
      @diary,
      @complaints,
      @prescriptions,
      @discharge_summary,
      @complications,
      @status,
      @created_by,
      @updated_by,
      datetime('now', '+5 hours'),
      datetime('now', '+5 hours')
    )
  `);

  const res = stmt.run({
    patient_id: data.patient_id,
    full_name: data.full_name,
    birth_date: data.birth_date || null,
    region: data.region || null,
    diagnosis: data.diagnosis || null,
    topometry: data.topometry || null,
    method_gray: data.method_gray ?? null,
    diary: data.diary || null,
    complaints: data.complaints || null,
    prescriptions: data.prescriptions || null,
    discharge_summary: data.discharge_summary || null,
    complications: data.complications || null,
    status: data.status || "on_treatment",
    created_by: data.created_by || null,
    updated_by: data.updated_by || null,
  });

  return res.lastInsertRowid;
}

export function updatePatient(id, data) {
  if (!db) initDb();

  const current = getPatientByRowId(id);
  if (!current) throw new Error("Пациент не найден");

  const merged = {
    id,
    full_name: data.full_name ?? current.full_name,
    birth_date: data.birth_date ?? current.birth_date,
    region: data.region ?? current.region,
    diagnosis: data.diagnosis ?? current.diagnosis,
    topometry: data.topometry ?? current.topometry,
    method_gray:
      data.method_gray !== undefined ? data.method_gray : current.method_gray,
    diary: data.diary ?? current.diary,
    complaints: data.complaints ?? current.complaints,
    prescriptions: data.prescriptions ?? current.prescriptions,
    discharge_summary:
      data.discharge_summary ?? current.discharge_summary,
    complications: data.complications ?? current.complications,
    status: data.status ?? current.status,
    updated_by: data.updated_by ?? current.updated_by,
  };

  const stmt = db.prepare(`
    UPDATE patients
    SET full_name         = @full_name,
        birth_date        = @birth_date,
        region            = @region,
        diagnosis         = @diagnosis,
        topometry         = @topometry,
        method_gray       = @method_gray,
        diary             = @diary,
        complaints        = @complaints,
        prescriptions     = @prescriptions,
        discharge_summary = @discharge_summary,
        complications     = @complications,
        status            = @status,
        updated_by        = @updated_by,
        updated_at        = datetime('now', '+5 hours')
    WHERE id = @id
  `);

  stmt.run(merged);
}

/**
 * Обновление отдельных полей по patient_id (для бота)
 * patch: объект с полями diary / complaints / prescriptions / discharge_summary / complications / method_gray / status / updated_by
 */
export function updatePatientFieldsByPatientId(patientId, patch) {
  if (!db) initDb();

  const patient = getPatientByPatientId(patientId);
  if (!patient) return null;

  const data = {
    id: patient.id,
    full_name: patient.full_name,
    birth_date: patient.birth_date,
    region: patient.region,
    diagnosis: patient.diagnosis,
    topometry: patient.topometry,
    method_gray:
      patch.method_gray !== undefined
        ? patch.method_gray
        : patient.method_gray,
    diary: patch.diary ?? patient.diary,
    complaints: patch.complaints ?? patient.complaints,
    prescriptions: patch.prescriptions ?? patient.prescriptions,
    discharge_summary:
      patch.discharge_summary ?? patient.discharge_summary,
    complications: patch.complications ?? patient.complications,
    status: patch.status ?? patient.status,
    updated_by: patch.updated_by ?? patient.updated_by,
  };

  updatePatient(patient.id, data);
  return patient.id;
}

export function deletePatientByRowId(id) {
  if (!db) initDb();
  db.prepare("DELETE FROM patients WHERE id = ?").run(id);
}

/* ==================== CHANGES & VIEWS ==================== */

/**
 * Записать изменение пациента.
 * Возвращает id записи в patient_changes.
 */
export function recordPatientChange(
  patientRowId,
  userId,
  source,
  description
) {
  if (!db) initDb();

  const stmt = db.prepare(`
    INSERT INTO patient_changes (patient_id, user_id, source, description, changed_at)
    VALUES (@patient_id, @user_id, @source, @description, datetime('now', '+5 hours'))
  `);

  const res = stmt.run({
    patient_id: patientRowId,
    user_id: userId || null,
    source: source || null,
    description: description || null,
  });

  return res.lastInsertRowid;
}

/**
 * Пометить, что пользователь посмотрел изменения по пациенту.
 * Если lastSeenChangeId не передан — берётся максимальный id из patient_changes.
 */
export function markPatientSeen(
  patientRowId,
  userId,
  lastSeenChangeId = null
) {
  if (!db) initDb();

  let changeId = lastSeenChangeId;
  if (!changeId) {
    const row = db
      .prepare(
        "SELECT MAX(id) AS max_id FROM patient_changes WHERE patient_id = ?"
      )
      .get(patientRowId);
    changeId = row && row.max_id ? row.max_id : 0;
  }

  const stmt = db.prepare(`
    INSERT INTO patient_views (patient_id, user_id, last_seen_change_id)
    VALUES (@patient_id, @user_id, @last_seen_change_id)
    ON CONFLICT(patient_id, user_id)
    DO UPDATE SET last_seen_change_id = excluded.last_seen_change_id
  `);

  stmt.run({
    patient_id: patientRowId,
    user_id: userId,
    last_seen_change_id: changeId,
  });
}

/**
 * Инфо о последнем изменении пациента (для подписи внизу карты)
 */
export function getLastChangeInfo(patientRowId) {
  if (!db) initDb();

  const row = db
    .prepare(
      `
      SELECT
        pc.id,
        pc.changed_at,
        pc.source,
        u.full_name AS user_name,
        u.login     AS user_login
      FROM patient_changes pc
      LEFT JOIN users u ON u.id = pc.user_id
      WHERE pc.patient_id = ?
      ORDER BY pc.id DESC
      LIMIT 1
    `
    )
    .get(patientRowId);

  if (!row) return null;

  return {
    id: row.id,
    changed_at: row.changed_at,
    source: row.source,
    user_name: row.user_name || row.user_login || null,
  };
}

// экспортируем db для отладки/логов, если где-то используется
export { db };
