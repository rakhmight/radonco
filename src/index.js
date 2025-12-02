// src/index.js
import "dotenv/config";
import express from "express";
import session from "express-session";
import path from "path";
import { fileURLToPath } from "url";
import { Telegraf, Markup } from "telegraf";
import bcrypt from "bcryptjs";

import {
  initDb,
  ensureAdminUser,
  findUserByLogin,
  findUserByTelegramId,
  listUsers,
  getUserById,
  createUser,
  updateUser,
  deleteUserById,
  listPatientsForUser,
  getPatientByRowId,
  getPatientByPatientId,
  createPatient,
  updatePatient,
  updatePatientFieldsByPatientId,
  deletePatientByRowId,
  recordPatientChange,
  markPatientSeen,
  getLastChangeInfo,
  generateNextPatientId, 
} from "./db.js";

const editSessions = new Map();


initDb();
ensureAdminUser();


const BOT_TOKEN = process.env.BOT_TOKEN;
let bot = null;

const ALLOWED_IDS = (process.env.ALLOWED_TELEGRAM_IDS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

  function notifyAll(text) {
  if (!bot || !ALLOWED_IDS.length) return;
  ALLOWED_IDS.forEach((id) => {
    bot.telegram
      .sendMessage(id, text, { parse_mode: "Markdown" })
      .catch((err) =>
        console.error("[Bot] Ошибка отправки уведомления", id, err.message)
      );
  });
}


const app = express();
const PORT = process.env.PORT || 3000;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.static(path.join(__dirname, "public")));

app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "radonco-secret",
    resave: false,
    saveUninitialized: false,
  })
);


function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.redirect("/login");
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user) {
    return res.redirect("/login");
  }
  if (req.session.user.role !== "admin") {
    return res.status(403).send("Доступ разрешён только администратору.");
  }
  next();
}

/* ---- маршруты ---- */

// редирект на логин/пациентов
app.get("/", (req, res) => {
  if (req.session.user) {
    return res.redirect("/patients");
  }
  res.redirect("/login");
});

// логин
app.get("/login", (req, res) => {
  if (req.session.user) {
    return res.redirect("/patients");
  }
  res.render("login", { error: null });
});

app.post("/login", (req, res) => {
  const { login, password } = req.body;
  const user = findUserByLogin(login);

  if (!user) {
    return res.status(401).render("login", {
      error: "Неверный логин или пароль",
    });
  }

  const ok = bcrypt.compareSync(password, user.password_hash);
  if (!ok) {
    return res.status(401).render("login", {
      error: "Неверный логин или пароль",
    });
  }

  req.session.user = {
    id: user.id,
    login: user.login,
    full_name: user.full_name,
    role: user.role,
  };

  res.redirect("/patients");
});

// выход
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

/* ---- Администрирование пользователей (только admin) ---- */

// список пользователей
app.get("/admin/users", requireAdmin, (req, res) => {
  const users = listUsers();
  res.render("admin_users", {
    user: req.session.user,
    users,
  });
});

// форма создания пользователя
app.get("/admin/users/new", requireAdmin, (req, res) => {
  res.render("admin_user_form", {
    user: req.session.user,
    mode: "create",
    u: {},
    error: null,
  });
});

// создание пользователя
app.post("/admin/users/new", requireAdmin, (req, res) => {
  const { login, full_name, role, telegram_id, password } = req.body;

  if (!login || !password) {
    return res.status(400).send("Логин и пароль обязательны");
  }

  const trimmedLogin = login.trim();
  const trimmedPassword = password.trim();

  try {
    const passwordHash = bcrypt.hashSync(trimmedPassword, 10);

    createUser({
      login: trimmedLogin,
      passwordHash,
      full_name: full_name ? full_name.trim() : null,
      role: role || "doctor",
      telegram_id: telegram_id ? String(telegram_id).trim() : null,
    });

    res.redirect("/admin/users");
  } catch (e) {
    console.error("Ошибка создания пользователя:", e);
    return res
      .status(400)
      .send("Ошибка создания пользователя: " + (e.message || e));
  }
});

// форма редактирования пользователя
app.get("/admin/users/:id/edit", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const u = getUserById(id);
  if (!u) {
    return res.status(404).send("Пользователь не найден");
  }

  res.render("admin_user_form", {
    user: req.session.user,
    mode: "edit",
    u,
    error: null,
  });
});

// редактирование существующего пользователя (админ)
app.post("/admin/users/:id/edit", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const { login, full_name, role, telegram_id, password } = req.body;

  let passwordHash;
  if (password && password.trim()) {
    const trimmedPassword = password.trim();
    passwordHash = bcrypt.hashSync(trimmedPassword, 10);
  }

  try {
    updateUser(id, {
      login: login ? login.trim() : undefined,
      full_name: full_name ? full_name.trim() : undefined,
      role: role || undefined,
      telegram_id: telegram_id ? String(telegram_id).trim() : undefined,
      passwordHash,
    });

    res.redirect("/admin/users");
  } catch (e) {
    console.error("Ошибка обновления пользователя:", e);
    return res
      .status(400)
      .send("Ошибка обновления пользователя: " + (e.message || e));
  }
});

// удаление пользователя
app.post("/admin/users/:id/delete", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const u = getUserById(id);
  if (!u) {
    return res.status(404).send("Пользователь не найден");
  }

  if (req.session.user && req.session.user.id === u.id) {
    return res.status(400).send("Нельзя удалить самого себя.");
  }

  deleteUserById(id);
  res.redirect("/admin/users");
});

/* ---- Пациенты (радиоонкология) ---- */

// список пациентов
app.get("/patients", requireAuth, (req, res) => {
  const user = req.session.user;
  const patients = listPatientsForUser(user.id);

  res.render("patients_list", {
    user,
    patients,
  });
});

// форма создания пациента
app.get("/patients/new", requireAuth, (req, res) => {
  res.render("patient_form", {
    user: req.session.user,
    patient: {},
    mode: "create",
    lastChange: null,
  });
});

app.post("/patients/new", requireAuth, (req, res) => {
  const body = req.body;

  // генерируем ID автоматически
  const generatedPatientId = generateNextPatientId();

  const data = {
    patient_id: generatedPatientId,
    full_name: (body.full_name || "").trim(),
    birth_date: body.birth_date || null,
    region: body.region || null,
    diagnosis: body.diagnosis || null,
    topometry: body.topometry || null,
    method_gray: body.method_gray ? Number(body.method_gray) : null,
    diary: body.diary || null,
    complaints: body.complaints || null,
    prescriptions: body.prescriptions || null,
    discharge_summary: body.discharge_summary || null,
    complications: body.complications || null,
    status: body.status || "on_treatment",
    created_by: req.session.user.id,
    updated_by: req.session.user.id,
  };

  if (!data.full_name) {
    return res.status(400).send("ФИО пациента обязательно");
  }

  let rowId;
  try {
    rowId = createPatient(data);
  } catch (e) {
    console.error("createPatient error:", e);
    return res
      .status(400)
      .send("Ошибка создания пациента: " + (e.message || e));
  }

  const actor =
    req.session.user?.full_name ||
    req.session.user?.login ||
    "неизвестный пользователь";

  // записываем изменение + сразу считаем, что автор его уже посмотрел
  const changeId = recordPatientChange(
    rowId,
    req.session.user.id,
    "web-create",
    "Создание карты пациента"
  );
  markPatientSeen(rowId, req.session.user.id, changeId);

  if (typeof notifyAll === "function") {
    notifyAll(
      `🧾 *Создана новая карта ЛТ*\nID: *${data.patient_id}*\nПациент: ${data.full_name}\nПользователь: ${actor}`
    );
  }

  res.redirect("/patients");
});

// форма редактирования
app.get("/patients/:id/edit", requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const patient = getPatientByRowId(id);

  if (!patient) {
    return res.status(404).send("Пациент не найден");
  }

  markPatientSeen(id, req.session.user.id);
  const lastChange = getLastChangeInfo(id);

  res.render("patient_form", {
    user: req.session.user,
    patient,
    mode: "edit",
    lastChange,
  });
});

// просмотр без редактирования
app.get("/patients/:id", requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const patient = getPatientByRowId(id);
  if (!patient) {
    return res.status(404).send("Пациент не найден");
  }

  markPatientSeen(id, req.session.user.id);
  const lastChange = getLastChangeInfo(id);

  res.render("patient_form", {
    user: req.session.user,
    patient,
    mode: "view",
    lastChange,
  });
});

// сохранение изменений
app.post("/patients/:id/edit", requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const patient = getPatientByRowId(id);

  if (!patient) {
    return res.status(404).send("Пациент не найден");
  }

  const body = req.body;

  const data = {
    patient_id: (body.patient_id || "").trim(),
    full_name: (body.full_name || "").trim(),
    birth_date: body.birth_date || null,
    region: body.region || null,
    diagnosis: body.diagnosis || null,
    topometry: body.topometry || null,
    method_gray: body.method_gray ? Number(body.method_gray) : null,
    diary: body.diary || null,
    complaints: body.complaints || null,
    prescriptions: body.prescriptions || null,
    discharge_summary: body.discharge_summary || null,
    complications: body.complications || null,
    status: body.status || "on_treatment",
  };

  updatePatient(id, data);

  const actor =
    req.session.user?.full_name ||
    req.session.user?.login ||
    "неизвестный пользователь";

  recordPatientChange(
    id,
    req.session.user.id,
    "web-edit",
    null,
    "Редактирование в веб-панели"
  );
  markPatientSeen(id, req.session.user.id);

  notifyAll(
    `♻️ *Обновлена карта ЛТ*\nID: *${data.patient_id}*\nПациент: ${data.full_name}\nПользователь: ${actor}`
  );

  res.redirect("/patients");
});

// удаление пациента
app.post("/patients/:id/delete", requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const patient = getPatientByRowId(id);
  if (!patient) {
    return res.status(404).send("Пациент не найден");
  }

  deletePatientByRowId(id);

  const actor =
    req.session.user?.full_name ||
    req.session.user?.login ||
    "неизвестный пользователь";

  notifyAll(
    `🗑 *Удалена карта ЛТ*\nID: *${patient.patient_id}*\nПациент: ${patient.full_name || ""}\nПользователь: ${actor}`
  );

  res.redirect("/patients");
});

app.listen(PORT, () => {
  console.log(`[HTTP] RadOnco веб-панель запущена на порту ${PORT}`);
});

/* ====== Telegram-бот (радиоонкология) ====== */

if (!BOT_TOKEN) {
  console.warn(" бот не запущен");
} else {
  bot = new Telegraf(BOT_TOKEN);

  function isAllowed(ctx) {
    const fromId = ctx.from?.id?.toString();
    return fromId && ALLOWED_IDS.includes(fromId);
  }

  function markSeenFromTelegram(ctx, patient) {
    if (!patient) return;
    const tgId = ctx.from?.id?.toString();
    if (!tgId) return;
    const u = findUserByTelegramId(tgId);
    if (!u) return;
    markPatientSeen(patient.id, u.id);
  }

  // общий middleware доступа
  bot.use((ctx, next) => {
    if (!isAllowed(ctx)) {
      return ctx.reply(
        "Доступ к радиоонкологическому боту ограничен. Обратитесь к администратору."
      );
    }
    return next();
  });

  bot.start((ctx) => {
    ctx.reply(
      "👋 Добро пожаловать в радиоонкологический бот.\n" +
        "Отправьте *ID пациента* (как в веб-панели), чтобы получить краткую карточку курса ЛТ: дневник, жалобы, назначения, выписка, осложнения.\n\n" +
        "Для изменения данных используйте команды:\n" +
        "• `/update_diary ID` — дневник ЛТ\n" +
        "• `/update_complaints ID` — жалобы\n" +
        "• `/update_prescriptions ID` — назначения\n" +
        "• `/update_discharge ID` — выписка\n" +
        "• `/update_complications ID` — осложнения\n" +
        "Команда `/cancel` — выйти из режима редактирования.",
      { parse_mode: "Markdown" }
    );
  });

  // Команды для редактирования полей
  bot.command("update_diary", makeUpdateCommand("diary", "Дневник курса ЛТ"));
  bot.command(
    "update_complaints",
    makeUpdateCommand("complaints", "Жалобы")
  );
  bot.command(
    "update_prescriptions",
    makeUpdateCommand("prescriptions", "Назначения")
  );
  bot.command(
    "update_discharge",
    makeUpdateCommand("discharge_summary", "Выписка")
  );
  bot.command(
    "update_complications",
    makeUpdateCommand("complications", "Осложнения")
  );

  // Отмена редактирования
  bot.command("cancel", (ctx) => {
    const chatId = ctx.chat.id.toString();
    if (editSessions.has(chatId)) {
      editSessions.delete(chatId);
      return ctx.reply("Режим редактирования отменён.");
    }
    return ctx.reply("Нет активного редактирования.");
  });

  // Обработка inline-кнопок
  bot.on("callback_query", async (ctx) => {
    const data = ctx.callbackQuery.data || "";

    // Показать актуальную карточку
    if (data.startsWith("show:")) {
      const patientId = data.slice("show:".length);
      const patient = getPatientByPatientId(patientId);

      if (!patient) {
        await safeEditMessageText(
          ctx,
          `Пациент с ID *${patientId}* в базе ЛТ не найден.`,
          { parse_mode: "Markdown" }
        );
      } else {
        const msg = formatPatientCardForBot(patient);
        await safeEditMessageText(ctx, msg, {
          parse_mode: "Markdown",
          ...patientActionsKeyboard(patient.patient_id),
        });
        markSeenFromTelegram(ctx, patient);
      }

      await ctx.answerCbQuery().catch(() => {});
      return;
    }

    // Редактирование конкретного поля
    if (data.startsWith("edit:")) {
      const parts = data.split(":"); // edit:field:patientId
      const field = parts[1];
      const patientId = parts[2];

      const labels = {
        diary: "Дневник курса ЛТ",
        complaints: "Жалобы",
        prescriptions: "Назначения",
        discharge_summary: "Выписка",
        complications: "Осложнения",
      };
      const label = labels[field] || field;

      await beginEditField(ctx, patientId, field, label);
      await ctx.answerCbQuery().catch(() => {});
      return;
    }

    await ctx.answerCbQuery().catch(() => {});
  });

  // Любой текст — либо ввод нового значения поля, либо запрос карточки по ID
  bot.on("text", async (ctx) => {
    const text = ctx.message.text.trim();

    // команды /... уже обработаны отдельными хендлерами
    if (text.startsWith("/")) return;

    const chatId = ctx.chat.id.toString();
    const session = editSessions.get(chatId);

    // === РЕЖИМ РЕДАКТИРОВАНИЯ ПОЛЯ ===
    if (session) {
      const newValue = text;

      updatePatientFieldsByPatientId(session.patientId, {
        [session.field]: newValue,
      });

      const patient = getPatientByPatientId(session.patientId);
      editSessions.delete(chatId);

      let confirm = `Поле "${session.label}" для пациента ID ${session.patientId} обновлено.\n`;
      if (patient && patient.full_name) {
        confirm += `Пациент: ${patient.full_name}`;
      }

      await ctx.reply(confirm);

      // логируем изменение
      let changedByUserId = null;
      const tgId = ctx.from?.id?.toString();
      if (tgId) {
        const u = findUserByTelegramId(tgId);
        if (u) {
          changedByUserId = u.id;
          markPatientSeen(patient.id, u.id);
        }
      }

      recordPatientChange(
        patient.id,
        changedByUserId,
        "bot",
        session.field,
        "Обновление из Telegram-бота"
      );

      // уведомление всем
      const who =
        ctx.from.username
          ? `@${ctx.from.username}`
          : ctx.from.first_name || ctx.from.id;
      notifyAll(
        `✏️ *Обновление из бота*\nПоле: *${session.label}*\nID: *${session.patientId}*\nПользователь Telegram: ${who}`
      );

      return;
    }

    // === Обычный режим: текст = ID пациента ===
    const patientId = text;
    const patient = getPatientByPatientId(patientId);

    if (!patient) {
      return ctx.reply(`Пациент с ID *${patientId}* в базе ЛТ не найден.`, {
        parse_mode: "Markdown",
      });
    }

    const msg = formatPatientCardForBot(patient);
    markSeenFromTelegram(ctx, patient);

    return ctx.reply(msg, {
      parse_mode: "Markdown",
      ...patientActionsKeyboard(patient.patient_id),
    });
  });

  bot.launch().then(() => {
    console.log("[Bot] Телеграм-бот радиоонкологии запущен");
  });

  // аккуратная остановка
  process.once("SIGINT", () => bot.stop("SIGINT"));
  process.once("SIGTERM", () => bot.stop("SIGTERM"));
}

/**
 * Формирование текста карточки пациента для бота
 */
function formatPatientCardForBot(p) {
  const lines = [];

  lines.push(`🧾 *Карта ЛТ* — ID: *${p.patient_id}*`);
  if (p.full_name) lines.push(`👤 Пациент: *${p.full_name}*`);
  if (p.diagnosis) lines.push(`🎯 Диагноз: ${p.diagnosis}`);
  if (p.method_gray) lines.push(`📡 Методика: ${p.method_gray}`);
  lines.push("");

  lines.push("📘 *Дневник:*");
  lines.push(p.diary ? p.diary : "—");
  lines.push("");

  lines.push("😣 *Жалобы:*");
  lines.push(p.complaints ? p.complaints : "—");
  lines.push("");

  lines.push("💊 *Назначения:*");
  lines.push(p.prescriptions ? p.prescriptions : "—");
  lines.push("");

  lines.push("📄 *Выписка:*");
  lines.push(p.discharge_summary ? p.discharge_summary : "—");
  lines.push("");

  lines.push("⚠️ *Осложнения:*");
  lines.push(p.complications ? p.complications : "—");

  return lines.join("\n");
}

/**
 * Inline-клавиатура под карточкой пациента
 */
function patientActionsKeyboard(patientId) {
  return Markup.inlineKeyboard([
    [Markup.button.callback("🔄 Обновить карту", `show:${patientId}`)],
    [
      Markup.button.callback("✏️ Дневник", `edit:diary:${patientId}`),
      Markup.button.callback("😣 Жалобы", `edit:complaints:${patientId}`),
    ],
    [
      Markup.button.callback(
        "💊 Назначения",
        `edit:prescriptions:${patientId}`
      ),
    ],
    [Markup.button.callback("📄 Выписка", `edit:discharge_summary:${patientId}`)],
    [
      Markup.button.callback(
        "⚠️ Осложнения",
        `edit:complications:${patientId}`
      ),
    ],
  ]);
}

/**
 * Общая логика начала редактирования поля (команда или inline-кнопка)
 */
function beginEditField(ctx, patientId, field, label) {
  const patient = getPatientByPatientId(patientId);
  if (!patient) {
    return ctx.reply(
      `Пациент с ID *${patientId}* в базе ЛТ не найден.`,
      { parse_mode: "Markdown" }
    );
  }

  const chatId = ctx.chat.id.toString();
  editSessions.set(chatId, { field, label, patientId });

  const currentValue = patient[field] || "—";

  return ctx.reply(
    `Редактируем поле "${label}" для пациента ID ${patientId}.\n` +
      (patient.full_name ? `Пациент: ${patient.full_name}\n` : "") +
      `Текущее значение:\n${currentValue}\n\n` +
      "Отправьте новый текст одним сообщением.\n" +
      "Команда /cancel — отменить редактирование."
  );
}

/**
 * Фабрика команд для начала редактирования поля
 */
function makeUpdateCommand(field, label) {
  return (ctx) => {
    const text = ctx.message.text.trim();
    const parts = text.split(/\s+/);
    const patientId = parts[1];

    if (!patientId) {
      const cmd = parts[0] || `/update_${field}`;
      return ctx.reply(
        `Укажите ID пациента после команды.\nНапример: ${cmd} 12345`
      );
    }

    return beginEditField(ctx, patientId, field, label);
  };
}

/**
 * Безопасное редактирование сообщения, чтобы не ловить
 * 400: Bad Request: message is not modified
 */
function safeEditMessageText(ctx, text, extra = {}) {
  const msg = ctx.callbackQuery?.message;

  const sameText = msg && msg.text === text;
  let sameMarkup = false;

  if (msg && msg.reply_markup && extra.reply_markup) {
    try {
      sameMarkup =
        JSON.stringify(msg.reply_markup) ===
        JSON.stringify(extra.reply_markup);
    } catch (e) {
      sameMarkup = false;
    }
  }

  if (sameText && sameMarkup) {
    // Ничего не изменилось — просто выходим
    return Promise.resolve();
  }

  return ctx
    .editMessageText(text, extra)
    .catch((err) => {
      const desc =
        err?.response?.description || err?.description || err?.message || "";
      if (desc.includes("message is not modified")) {
        console.warn("[Bot] message is not modified — игнорируем");
        return;
      }
      console.error("[Bot] editMessageText error:", err);
      throw err;
    });
}
