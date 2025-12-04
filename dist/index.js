var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// _core/index.ts
import "dotenv/config";
import express2 from "express";
import { createServer } from "http";
import cookieParser from "cookie-parser";
import cors from "cors";
import { createExpressMiddleware } from "@trpc/server/adapters/express";

// ../shared/const.ts
var COOKIE_NAME = "app_session_id";
var ONE_YEAR_MS = 1e3 * 60 * 60 * 24 * 365;
var AXIOS_TIMEOUT_MS = 3e4;

// db.ts
import { eq } from "drizzle-orm";
import { drizzle } from "drizzle-orm/node-postgres";
import { Pool } from "pg";

// ../drizzle/schema.ts
var schema_exports = {};
__export(schema_exports, {
  priorityEnum: () => priorityEnum,
  projectStatusEnum: () => projectStatusEnum,
  projects: () => projects,
  roleEnum: () => roleEnum,
  statusEnum: () => statusEnum,
  tags: () => tags,
  taskTags: () => taskTags,
  tasks: () => tasks,
  userNotificationSettings: () => userNotificationSettings,
  users: () => users
});
import {
  pgTable,
  serial,
  integer,
  varchar,
  text,
  timestamp,
  pgEnum,
  primaryKey
} from "drizzle-orm/pg-core";
import { sql } from "drizzle-orm";
var roleEnum = pgEnum("role", ["user", "admin"]);
var priorityEnum = pgEnum("priority", ["low", "medium", "high"]);
var statusEnum = pgEnum("status", ["pending", "in-progress", "completed"]);
var projectStatusEnum = pgEnum("project_status", [
  "active",
  "completed",
  "archived"
]);
var users = pgTable("users", {
  id: serial("id").primaryKey(),
  openId: varchar("open_id", { length: 64 }).unique(),
  name: text("name"),
  email: varchar("email", { length: 320 }).unique().notNull(),
  password: varchar("password", { length: 255 }),
  loginMethod: varchar("login_method", { length: 64 }).default("email"),
  role: roleEnum("role").default("user").notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
  lastSignedIn: timestamp("last_signed_in").defaultNow().notNull()
});
var userNotificationSettings = pgTable("user_notification_settings", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  emailNotifications: integer("email_notifications").notNull().default(1),
  // 1 = ON, 0 = OFF
  taskDueReminder: integer("task_due_reminder").notNull().default(1),
  newTaskAssigned: integer("new_task_assigned").notNull().default(1),
  marketingEmails: integer("marketing_emails").notNull().default(0),
  // default OFF
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull().$onUpdate(() => sql`now()`)
});
var projects = pgTable("projects", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  name: varchar("name", { length: 255 }).notNull(),
  description: text("description"),
  status: projectStatusEnum("status").default("active").notNull(),
  progress: integer("progress").default(0),
  color: varchar("color", { length: 50 }).default("from-blue-500 to-blue-600"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull().$onUpdate(() => sql`now()`)
});
var tags = pgTable("tags", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  name: varchar("name", { length: 50 }).notNull(),
  description: text("description"),
  color: varchar("color", { length: 50 }).default("#3b82f6"),
  usageCount: integer("usage_count").default(0).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull()
});
var tasks = pgTable("tasks", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  projectId: integer("project_id").notNull().references(() => projects.id, { onDelete: "cascade" }),
  title: varchar("title", { length: 255 }).notNull(),
  description: text("description"),
  priority: priorityEnum("priority").notNull().default("medium"),
  status: statusEnum("status").notNull().default("pending"),
  dueDate: timestamp("due_date"),
  position: integer("position").notNull().default(0),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull().$onUpdate(() => sql`now()`)
});
var taskTags = pgTable(
  "task_tags",
  {
    taskId: integer("task_id").notNull().references(() => tasks.id, { onDelete: "cascade" }),
    tagId: integer("tag_id").notNull().references(() => tags.id, { onDelete: "cascade" })
  },
  (table) => ({
    pk: primaryKey({ columns: [table.taskId, table.tagId] })
  })
);

// _core/env.ts
var ENV = {
  appId: process.env.VITE_APP_ID ?? "",
  cookieSecret: process.env.JWT_SECRET ?? "",
  databaseUrl: process.env.DATABASE_URL ?? "",
  oAuthServerUrl: process.env.OAUTH_SERVER_URL ?? "",
  ownerOpenId: process.env.OWNER_OPEN_ID ?? "",
  isProduction: process.env.NODE_ENV === "production",
  forgeApiUrl: process.env.BUILT_IN_FORGE_API_URL ?? "",
  forgeApiKey: process.env.BUILT_IN_FORGE_API_KEY ?? "",
  resendApiKey: process.env.RESEND_API_KEY ?? "",
  emailFrom: process.env.EMAIL_FROM ?? ""
};

// db.ts
var _db = null;
async function getDb() {
  if (_db) return _db;
  if (!process.env.DATABASE_URL) {
    throw new Error("[Database] DATABASE_URL is missing.");
  }
  try {
    const pool = new Pool({
      connectionString: process.env.DATABASE_URL
    });
    _db = drizzle(pool, { schema: schema_exports });
    return _db;
  } catch (error) {
    console.error("[Database] Failed to connect:", error);
    throw error;
  }
}
async function upsertUser(user) {
  if (!user.openId) throw new Error("User openId is required for upsert");
  const db = await getDb();
  const now = /* @__PURE__ */ new Date();
  const values = {
    openId: user.openId,
    name: user.name ?? null,
    email: user.email ?? null,
    loginMethod: user.loginMethod ?? null,
    lastSignedIn: user.lastSignedIn ?? now,
    role: user.role ?? (user.openId === ENV.ownerOpenId ? "admin" : void 0)
  };
  const updateSet = {
    name: user.name ?? null,
    email: user.email ?? null,
    loginMethod: user.loginMethod ?? null,
    lastSignedIn: user.lastSignedIn ?? now,
    role: user.role ?? (user.openId === ENV.ownerOpenId ? "admin" : void 0)
  };
  await db.insert(users).values(values).onConflictDoUpdate({
    target: users.openId,
    set: updateSet
  });
}
async function getUserByOpenId(openId) {
  const db = await getDb();
  const result = await db.select().from(users).where(eq(users.openId, openId)).limit(1);
  return result[0] ?? void 0;
}

// _core/cookies.ts
function getSessionCookieOptions(req) {
  const isProd = process.env.NODE_ENV === "production";
  return {
    httpOnly: true,
    // cookie tidak bisa dibaca JS (wajib)
    secure: isProd,
    // hanya https di production
    sameSite: isProd ? "none" : "lax",
    path: "/",
    maxAge: 7 * 24 * 60 * 60 * 1e3
    // 7 hari
  };
}

// ../shared/_core/errors.ts
var HttpError = class extends Error {
  constructor(statusCode, message) {
    super(message);
    this.statusCode = statusCode;
    this.name = "HttpError";
  }
};
var ForbiddenError = (msg) => new HttpError(403, msg);

// _core/sdk.ts
import axios from "axios";
import { parse as parseCookieHeader } from "cookie";
import { SignJWT, jwtVerify } from "jose";
var isNonEmptyString = (value) => typeof value === "string" && value.length > 0;
var EXCHANGE_TOKEN_PATH = `/webdev.v1.WebDevAuthPublicService/ExchangeToken`;
var GET_USER_INFO_PATH = `/webdev.v1.WebDevAuthPublicService/GetUserInfo`;
var GET_USER_INFO_WITH_JWT_PATH = `/webdev.v1.WebDevAuthPublicService/GetUserInfoWithJwt`;
var OAuthService = class {
  constructor(client) {
    this.client = client;
    console.log("[OAuth] Initialized with baseURL:", ENV.oAuthServerUrl);
    if (!ENV.oAuthServerUrl) {
      console.error(
        "[OAuth] ERROR: OAUTH_SERVER_URL is not configured! Set OAUTH_SERVER_URL environment variable."
      );
    }
  }
  decodeState(state) {
    const redirectUri = atob(state);
    return redirectUri;
  }
  async getTokenByCode(code, state) {
    const payload = {
      clientId: ENV.appId,
      grantType: "authorization_code",
      code,
      redirectUri: this.decodeState(state)
    };
    const { data } = await this.client.post(EXCHANGE_TOKEN_PATH, payload);
    return data;
  }
  async getUserInfoByToken(token) {
    const { data } = await this.client.post(GET_USER_INFO_PATH, {
      accessToken: token.accessToken
    });
    return data;
  }
};
var createOAuthHttpClient = () => axios.create({
  baseURL: ENV.oAuthServerUrl,
  timeout: AXIOS_TIMEOUT_MS
});
var SDKServer = class {
  client;
  oauthService;
  constructor(client = createOAuthHttpClient()) {
    this.client = client;
    this.oauthService = new OAuthService(this.client);
  }
  deriveLoginMethod(platforms, fallback) {
    if (fallback && fallback.length > 0) return fallback;
    if (!Array.isArray(platforms) || platforms.length === 0) return null;
    const set = new Set(platforms.filter((p) => typeof p === "string"));
    if (set.has("REGISTERED_PLATFORM_EMAIL")) return "email";
    if (set.has("REGISTERED_PLATFORM_GOOGLE")) return "google";
    if (set.has("REGISTERED_PLATFORM_APPLE")) return "apple";
    if (set.has("REGISTERED_PLATFORM_MICROSOFT") || set.has("REGISTERED_PLATFORM_AZURE"))
      return "microsoft";
    if (set.has("REGISTERED_PLATFORM_GITHUB")) return "github";
    const first = Array.from(set)[0];
    return first ? first.toLowerCase() : null;
  }
  /**
   * Exchange OAuth authorization code for access token
   * @example
   * const tokenResponse = await sdk.exchangeCodeForToken(code, state);
   */
  async exchangeCodeForToken(code, state) {
    return this.oauthService.getTokenByCode(code, state);
  }
  /**
   * Get user information using access token
   * @example
   * const userInfo = await sdk.getUserInfo(tokenResponse.accessToken);
   */
  async getUserInfo(accessToken) {
    const data = await this.oauthService.getUserInfoByToken({
      accessToken
    });
    const loginMethod = this.deriveLoginMethod(
      data?.platforms,
      data?.platform ?? data.platform ?? null
    );
    return {
      ...data,
      platform: loginMethod,
      loginMethod
    };
  }
  parseCookies(cookieHeader) {
    if (!cookieHeader) {
      return /* @__PURE__ */ new Map();
    }
    const parsed = parseCookieHeader(cookieHeader);
    return new Map(Object.entries(parsed));
  }
  getSessionSecret() {
    const secret = ENV.cookieSecret;
    return new TextEncoder().encode(secret);
  }
  /**
   * Create a session token for a Manus user openId
   * @example
   * const sessionToken = await sdk.createSessionToken(userInfo.openId);
   */
  async createSessionToken(openId, options = {}) {
    return this.signSession(
      {
        openId,
        appId: ENV.appId,
        name: options.name || ""
      },
      options
    );
  }
  async signSession(payload, options = {}) {
    const issuedAt = Date.now();
    const expiresInMs = options.expiresInMs ?? ONE_YEAR_MS;
    const expirationSeconds = Math.floor((issuedAt + expiresInMs) / 1e3);
    const secretKey = this.getSessionSecret();
    return new SignJWT({
      openId: payload.openId,
      appId: payload.appId,
      name: payload.name
    }).setProtectedHeader({ alg: "HS256", typ: "JWT" }).setExpirationTime(expirationSeconds).sign(secretKey);
  }
  async verifySession(cookieValue) {
    if (!cookieValue) {
      console.warn("[Auth] Missing session cookie");
      return null;
    }
    try {
      const secretKey = this.getSessionSecret();
      const { payload } = await jwtVerify(cookieValue, secretKey, {
        algorithms: ["HS256"]
      });
      const { openId, appId, name } = payload;
      if (!isNonEmptyString(openId) || !isNonEmptyString(appId) || !isNonEmptyString(name)) {
        console.warn("[Auth] Session payload missing required fields");
        return null;
      }
      return {
        openId,
        appId,
        name
      };
    } catch (error) {
      console.warn("[Auth] Session verification failed", String(error));
      return null;
    }
  }
  async getUserInfoWithJwt(jwtToken) {
    const payload = {
      jwtToken,
      projectId: ENV.appId
    };
    const { data } = await this.client.post(GET_USER_INFO_WITH_JWT_PATH, payload);
    const loginMethod = this.deriveLoginMethod(
      data?.platforms,
      data?.platform ?? data.platform ?? null
    );
    return {
      ...data,
      platform: loginMethod,
      loginMethod
    };
  }
  async authenticateRequest(req) {
    const cookies = this.parseCookies(req.headers.cookie);
    const sessionCookie = cookies.get(COOKIE_NAME);
    const session = await this.verifySession(sessionCookie);
    if (!session) {
      throw ForbiddenError("Invalid session cookie");
    }
    const sessionUserId = session.openId;
    const signedInAt = /* @__PURE__ */ new Date();
    let user = await getUserByOpenId(sessionUserId);
    if (!user) {
      try {
        const userInfo = await this.getUserInfoWithJwt(sessionCookie ?? "");
        await upsertUser({
          openId: userInfo.openId,
          name: userInfo.name ?? "",
          email: userInfo.email ?? "",
          loginMethod: userInfo.loginMethod ?? userInfo.platform ?? "",
          lastSignedIn: signedInAt,
          role: "user",
          password: null
        });
        user = await getUserByOpenId(userInfo.openId);
      } catch (error) {
        console.error("[Auth] Failed to sync user from OAuth:", error);
        throw ForbiddenError("Failed to sync user info");
      }
    }
    if (!user) {
      throw ForbiddenError("User not found");
    }
    await upsertUser({
      openId: user.openId ?? null,
      email: user.email ?? "",
      name: user.name ?? "",
      loginMethod: user.loginMethod ?? "",
      lastSignedIn: signedInAt,
      role: user.role ?? "user",
      password: user.password ?? null
    });
    return user;
  }
};
var sdk = new SDKServer();

// _core/oauth.ts
function getQueryParam(req, key) {
  const value = req.query[key];
  return typeof value === "string" ? value : void 0;
}
function registerOAuthRoutes(app) {
  app.get("/api/oauth/callback", async (req, res) => {
    const code = getQueryParam(req, "code");
    const state = getQueryParam(req, "state");
    if (!code || !state) {
      res.status(400).json({ error: "code and state are required" });
      return;
    }
    try {
      const tokenResponse = await sdk.exchangeCodeForToken(code, state);
      const userInfo = await sdk.getUserInfo(tokenResponse.accessToken);
      if (!userInfo.openId) {
        res.status(400).json({ error: "openId missing from user info" });
        return;
      }
      await upsertUser({
        openId: userInfo.openId,
        name: userInfo.name ?? "",
        email: userInfo.email ?? "",
        // wajib string
        loginMethod: userInfo.loginMethod ?? userInfo.platform ?? "",
        lastSignedIn: /* @__PURE__ */ new Date()
      });
      const sessionToken = await sdk.createSessionToken(userInfo.openId, {
        name: userInfo.name ?? "",
        expiresInMs: ONE_YEAR_MS
      });
      const cookieOptions = getSessionCookieOptions(req);
      res.cookie(COOKIE_NAME, sessionToken, { ...cookieOptions, maxAge: ONE_YEAR_MS });
      res.redirect(302, "/");
    } catch (error) {
      console.error("[OAuth] Callback failed", error);
      res.status(500).json({ error: "OAuth callback failed" });
    }
  });
}

// _core/trpc.ts
import { initTRPC, TRPCError } from "@trpc/server";
import superjson from "superjson";
import { ZodError } from "zod";
import { createTRPCReact } from "@trpc/react-query";
var t = initTRPC.context().create({
  transformer: superjson,
  errorFormatter({ shape, error }) {
    return {
      ...shape,
      data: {
        ...shape.data,
        zodError: error.cause instanceof ZodError ? error.cause.flatten() : null
      }
    };
  }
});
var router = t.router;
var createTRPCRouter = t.router;
var publicProcedure = t.procedure;
var trpc = createTRPCReact();
var requireUser = t.middleware(({ ctx, next }) => {
  if (!ctx.user) {
    throw new TRPCError({ code: "UNAUTHORIZED" });
  }
  return next({
    ctx: { ...ctx, user: ctx.user }
  });
});
var protectedProcedure = t.procedure.use(requireUser);
var adminProcedure = t.procedure.use(
  t.middleware(({ ctx, next }) => {
    if (!ctx.user || ctx.user.role !== "admin") {
      throw new TRPCError({ code: "FORBIDDEN" });
    }
    return next({
      ctx: { ...ctx, user: ctx.user }
    });
  })
);

// _core/authRouter.ts
import { z } from "zod";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { eq as eq2 } from "drizzle-orm";
import { TRPCError as TRPCError2 } from "@trpc/server";
var authRouter = createTRPCRouter({
  // ===========================
  // REGISTER
  // ===========================
  register: publicProcedure.input(
    z.object({
      name: z.string().min(1),
      email: z.string().email(),
      password: z.string().min(6)
    })
  ).mutation(async ({ input, ctx }) => {
    const db = ctx.db;
    if (!db) throw new TRPCError2({ code: "INTERNAL_SERVER_ERROR", message: "DB not available" });
    if (!process.env.JWT_SECRET) {
      throw new TRPCError2({ code: "INTERNAL_SERVER_ERROR", message: "JWT_SECRET not configured" });
    }
    const email = input.email.toLowerCase().trim();
    const [existing] = await db.select().from(users).where(eq2(users.email, email)).limit(1);
    if (existing) {
      throw new TRPCError2({ code: "CONFLICT", message: "Email already in use" });
    }
    const hashed = await bcrypt.hash(input.password, 12);
    const [newUser] = await db.insert(users).values({
      name: input.name.trim(),
      email,
      password: hashed
    }).returning();
    const token = jwt.sign({ id: newUser.id }, process.env.JWT_SECRET, {
      expiresIn: "7d"
    });
    ctx.res.cookie(COOKIE_NAME, token, getSessionCookieOptions(ctx.req));
    const { password, ...safeUser } = newUser;
    return { success: true, user: safeUser };
  }),
  // ===========================
  // LOGIN
  // ===========================
  login: publicProcedure.input(z.object({ email: z.string().email(), password: z.string() })).mutation(async ({ input, ctx }) => {
    const db = ctx.db;
    if (!db) throw new TRPCError2({ code: "INTERNAL_SERVER_ERROR", message: "DB not available" });
    if (!process.env.JWT_SECRET) {
      throw new TRPCError2({ code: "INTERNAL_SERVER_ERROR", message: "JWT_SECRET not configured" });
    }
    const email = input.email.toLowerCase().trim();
    const [user] = await db.select().from(users).where(eq2(users.email, email)).limit(1);
    if (!user || !user.password) {
      throw new TRPCError2({ code: "UNAUTHORIZED", message: "Invalid email or password" });
    }
    const valid = await bcrypt.compare(input.password, user.password);
    if (!valid) throw new TRPCError2({ code: "UNAUTHORIZED", message: "Invalid email or password" });
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
      expiresIn: "7d"
    });
    ctx.res.cookie(COOKIE_NAME, token, getSessionCookieOptions(ctx.req));
    const { password, ...safeUser } = user;
    return { success: true, user: safeUser };
  }),
  // ===========================
  // GET CURRENT USER
  // ===========================
  me: publicProcedure.query(({ ctx }) => {
    return ctx.user ?? null;
  }),
  // ===========================
  // LOGOUT
  // ===========================
  logout: publicProcedure.mutation(({ ctx }) => {
    ctx.res.clearCookie(COOKIE_NAME, {
      ...getSessionCookieOptions(ctx.req),
      maxAge: 0
    });
    return { success: true };
  }),
  // ===========================
  // UPDATE PROFILE (name)
  // ===========================
  updateProfile: protectedProcedure.input(
    z.object({
      name: z.string().min(1, "Name is required")
    })
  ).mutation(async ({ ctx, input }) => {
    const db = ctx.db;
    const user = ctx.user;
    if (!db || !user) throw new TRPCError2({ code: "UNAUTHORIZED" });
    const [updated] = await db.update(users).set({ name: input.name }).where(eq2(users.id, user.id)).returning();
    const { password, ...safeUser } = updated;
    return { success: true, user: safeUser };
  }),
  // ===========================
  // CHANGE PASSWORD
  // ===========================
  changePassword: protectedProcedure.input(
    z.object({
      currentPassword: z.string(),
      newPassword: z.string().min(6)
    })
  ).mutation(async ({ ctx, input }) => {
    const { db, user } = ctx;
    if (!db || !user) throw new TRPCError2({ code: "UNAUTHORIZED" });
    const [fullUser] = await db.select().from(users).where(eq2(users.id, user.id)).limit(1);
    if (!fullUser || !fullUser.password) {
      throw new TRPCError2({ code: "UNAUTHORIZED", message: "User not found" });
    }
    const valid = await bcrypt.compare(input.currentPassword, fullUser.password);
    if (!valid) {
      throw new TRPCError2({ code: "BAD_REQUEST", message: "Current password is incorrect" });
    }
    const hashed = await bcrypt.hash(input.newPassword, 12);
    await db.update(users).set({ password: hashed }).where(eq2(users.id, user.id));
    return { success: true, message: "Password updated successfully" };
  })
});

// _core/projectRouter.ts
import { z as z3 } from "zod";

// _core/progress.ts
import { eq as eq3, and } from "drizzle-orm";
var STATUS_VALUE = {
  pending: 0,
  "in-progress": 50,
  completed: 100
};
async function recalcProjectProgress(dbOrTx, projectId, userId) {
  const taskList = await dbOrTx.select({
    id: tasks.id,
    status: tasks.status
  }).from(tasks).where(and(eq3(tasks.projectId, projectId), eq3(tasks.userId, userId)));
  if (taskList.length === 0) {
    await dbOrTx.update(projects).set({
      progress: 0,
      status: "active",
      updatedAt: /* @__PURE__ */ new Date()
    }).where(and(eq3(projects.id, projectId), eq3(projects.userId, userId)));
    return 0;
  }
  const totalScore = taskList.reduce((sum, t2) => {
    return sum + (STATUS_VALUE[t2.status] ?? 0);
  }, 0);
  const progress = Math.round(totalScore / taskList.length);
  let projectStatus;
  if (progress === 100) {
    projectStatus = "completed";
  } else {
    projectStatus = "active";
  }
  await dbOrTx.update(projects).set({
    progress,
    status: projectStatus,
    updatedAt: /* @__PURE__ */ new Date()
  }).where(and(eq3(projects.id, projectId), eq3(projects.userId, userId)));
  return progress;
}

// _core/email.ts
import { Resend } from "resend";
var resend = new Resend(process.env.RESEND_API_KEY);
async function sendEmail(to, subject, html) {
  try {
    await resend.emails.send({
      from: "kholis.is26@gmail.com",
      // ganti domain jika punya domain verified di Resend
      to,
      subject,
      html
    });
    console.log("Email terkirim ke:", to);
  } catch (err) {
    console.error("Gagal mengirim email:", err);
  }
}

// _core/taskRouter.ts
import { z as z2 } from "zod";
import { eq as eq4, and as and2, asc, sql as sql3 } from "drizzle-orm";
import { TRPCError as TRPCError3 } from "@trpc/server";
async function getFullTagsForTask(db, taskId) {
  return db.select({
    id: tags.id,
    name: tags.name,
    color: tags.color,
    description: tags.description
  }).from(taskTags).innerJoin(tags, eq4(taskTags.tagId, tags.id)).where(eq4(taskTags.taskId, taskId));
}
var createTaskSchema = z2.object({
  projectId: z2.number(),
  title: z2.string().min(1),
  description: z2.string().nullable().optional(),
  priority: z2.enum(["low", "medium", "high"]).default("medium"),
  status: z2.enum(["pending", "in-progress", "completed"]).default("pending"),
  dueDate: z2.string().datetime().nullable().optional(),
  tagIds: z2.array(z2.number()).optional()
});
var updateTaskSchema = z2.object({
  id: z2.number(),
  projectId: z2.number().optional(),
  title: z2.string().optional(),
  description: z2.string().nullable().optional(),
  priority: z2.enum(["low", "medium", "high"]).optional(),
  status: z2.enum(["pending", "in-progress", "completed"]).optional(),
  dueDate: z2.string().nullable().optional(),
  tagIds: z2.array(z2.number()).optional()
});
var reorderSchema = z2.object({
  projectId: z2.number(),
  items: z2.array(
    z2.object({
      id: z2.number(),
      status: z2.enum(["pending", "in-progress", "completed"]),
      position: z2.number()
    })
  )
});
var taskRouter = createTRPCRouter({
  /* ---------------------------------------------
     LIST ALL TASKS
  --------------------------------------------- */
  listAll: protectedProcedure.query(async ({ ctx }) => {
    const all = await ctx.db.select().from(tasks).where(eq4(tasks.userId, ctx.user.id)).orderBy(asc(tasks.createdAt));
    const result = [];
    for (const t2 of all) {
      const tTags = await getFullTagsForTask(ctx.db, t2.id);
      result.push({ ...t2, tags: tTags });
    }
    return result;
  }),
  /* ---------------------------------------------
     LIST BY PROJECT
  --------------------------------------------- */
  listByProject: protectedProcedure.input(z2.object({ projectId: z2.number() })).query(async ({ ctx, input }) => {
    const taskList = await ctx.db.select().from(tasks).where(and2(eq4(tasks.projectId, input.projectId), eq4(tasks.userId, ctx.user.id))).orderBy(asc(tasks.position));
    const result = [];
    for (const t2 of taskList) {
      const tTags = await getFullTagsForTask(ctx.db, t2.id);
      result.push({ ...t2, tags: tTags });
    }
    return result;
  }),
  /* ---------------------------------------------
     GET ONE
  --------------------------------------------- */
  getOne: protectedProcedure.input(z2.object({ id: z2.number() })).query(async ({ ctx, input }) => {
    const [task] = await ctx.db.select().from(tasks).where(and2(eq4(tasks.id, input.id), eq4(tasks.userId, ctx.user.id)));
    if (!task) {
      throw new TRPCError3({ code: "NOT_FOUND", message: "Task not found" });
    }
    const tTags = await getFullTagsForTask(ctx.db, task.id);
    return { ...task, tags: tTags };
  }),
  /* ---------------------------------------------
     CREATE TASK
  --------------------------------------------- */
  create: protectedProcedure.input(createTaskSchema).mutation(async ({ ctx, input }) => {
    const [projectExists] = await ctx.db.select().from(projects).where(and2(eq4(projects.id, input.projectId), eq4(projects.userId, ctx.user.id)));
    if (!projectExists) throw new TRPCError3({ code: "NOT_FOUND" });
    const due = input.dueDate ? new Date(input.dueDate) : null;
    const last = await ctx.db.select({ max: sql3`max(${tasks.position})` }).from(tasks).where(and2(eq4(tasks.projectId, input.projectId), eq4(tasks.status, input.status)));
    const nextPos = (last[0]?.max ?? -1) + 1;
    const [created] = await ctx.db.insert(tasks).values({
      projectId: input.projectId,
      userId: ctx.user.id,
      title: input.title,
      description: input.description ?? null,
      priority: input.priority,
      status: input.status,
      dueDate: due,
      position: nextPos
    }).returning();
    if (input.tagIds?.length) {
      await ctx.db.insert(taskTags).values(
        input.tagIds.map((tagId) => ({ taskId: created.id, tagId }))
      );
    }
    await recalcProjectProgress(ctx.db, input.projectId, ctx.user.id);
    sendEmail(
      ctx.user.email,
      "Task Baru Dibuat",
      `<p>Task <b>${input.title}</b> berhasil dibuat.</p>`
    );
    const fullTags = await getFullTagsForTask(ctx.db, created.id);
    return { ...created, tags: fullTags };
  }),
  /* ---------------------------------------------
     UPDATE TASK
  --------------------------------------------- */
  update: protectedProcedure.input(updateTaskSchema).mutation(async ({ ctx, input }) => {
    const [existing] = await ctx.db.select().from(tasks).where(and2(eq4(tasks.id, input.id), eq4(tasks.userId, ctx.user.id)));
    if (!existing) throw new TRPCError3({ code: "NOT_FOUND" });
    await ctx.db.transaction(async (tx) => {
      const updateData = { updatedAt: /* @__PURE__ */ new Date() };
      if (input.title !== void 0) updateData.title = input.title;
      if (input.description !== void 0) updateData.description = input.description ?? null;
      if (input.priority !== void 0) updateData.priority = input.priority;
      let targetProjectId = existing.projectId;
      let targetStatus = existing.status;
      if (input.projectId !== void 0 && input.projectId !== existing.projectId) {
        const [projExists] = await tx.select().from(projects).where(and2(eq4(projects.id, input.projectId), eq4(projects.userId, ctx.user.id)));
        if (!projExists) {
          throw new TRPCError3({ code: "NOT_FOUND", message: "Target project not found" });
        }
        targetProjectId = input.projectId;
        updateData.projectId = input.projectId;
      }
      if (input.status !== void 0) {
        targetStatus = input.status;
      }
      const movingBetweenProjects = targetProjectId !== existing.projectId;
      const changingStatus = input.status !== void 0 && input.status !== existing.status;
      if (movingBetweenProjects || changingStatus) {
        const last = await tx.select({ max: sql3`max(${tasks.position})` }).from(tasks).where(and2(eq4(tasks.projectId, targetProjectId), eq4(tasks.status, targetStatus)));
        updateData.status = targetStatus;
        updateData.position = (last[0]?.max ?? -1) + 1;
      } else if (input.status !== void 0) {
        updateData.status = input.status;
      }
      if (input.dueDate !== void 0) {
        updateData.dueDate = input.dueDate ? new Date(input.dueDate) : null;
      }
      await tx.update(tasks).set(updateData).where(eq4(tasks.id, input.id));
      if (input.tagIds !== void 0) {
        await tx.delete(taskTags).where(eq4(taskTags.taskId, input.id));
        if (input.tagIds.length > 0) {
          await tx.insert(taskTags).values(
            input.tagIds.map((tagId) => ({ taskId: input.id, tagId }))
          );
        }
      }
    });
    try {
      await recalcProjectProgress(ctx.db, existing.projectId, ctx.user.id);
      if (input.projectId !== void 0 && input.projectId !== existing.projectId) {
        await recalcProjectProgress(ctx.db, input.projectId, ctx.user.id);
      }
    } catch (err) {
      console.error("recalcProjectProgress failed after update:", err);
    }
    sendEmail(
      ctx.user.email,
      "Task Diperbarui",
      `<p>Task <b>${existing.title}</b> telah diperbarui.</p>`
    );
    const fullTags = await getFullTagsForTask(ctx.db, input.id);
    return { success: true, tags: fullTags };
  }),
  /* ---------------------------------------------
     DELETE TASK
  --------------------------------------------- */
  delete: protectedProcedure.input(z2.object({ id: z2.number() })).mutation(async ({ ctx, input }) => {
    const [task] = await ctx.db.select().from(tasks).where(and2(eq4(tasks.id, input.id), eq4(tasks.userId, ctx.user.id)));
    if (!task) throw new TRPCError3({ code: "NOT_FOUND" });
    const projectId = task.projectId;
    await ctx.db.delete(taskTags).where(eq4(taskTags.taskId, input.id));
    await ctx.db.delete(tasks).where(eq4(tasks.id, input.id));
    await recalcProjectProgress(ctx.db, projectId, ctx.user.id);
    sendEmail(
      ctx.user.email,
      "Task Dihapus",
      `<p>Task <b>${task.title}</b> telah dihapus.</p>`
    );
    return { success: true };
  }),
  /* ---------------------------------------------
     GET BY TAG
  --------------------------------------------- */
  getByTagId: protectedProcedure.input(z2.object({ tagId: z2.number() })).query(async ({ ctx, input }) => {
    const { tagId } = input;
    const rows = await ctx.db.select({
      id: tasks.id,
      title: tasks.title,
      description: tasks.description,
      status: tasks.status,
      priority: tasks.priority,
      projectId: tasks.projectId
    }).from(taskTags).innerJoin(tasks, eq4(taskTags.taskId, tasks.id)).where(
      and2(eq4(taskTags.tagId, tagId), eq4(tasks.userId, ctx.user.id))
    );
    return rows;
  }),
  /* ---------------------------------------------
     REORDER (KANBAN)
  --------------------------------------------- */
  reorder: protectedProcedure.input(reorderSchema).mutation(async ({ ctx, input }) => {
    try {
      const { projectId, items } = input;
      const [projectExists] = await ctx.db.select().from(projects).where(and2(eq4(projects.id, projectId), eq4(projects.userId, ctx.user.id)));
      if (!projectExists) {
        throw new TRPCError3({ code: "NOT_FOUND" });
      }
      const ids = items.map((i) => i.id);
      const dbTasks = await ctx.db.select().from(tasks).where(
        and2(
          sql3`${tasks.id} IN (${sql3.join(ids, sql3`,`)})`,
          eq4(tasks.userId, ctx.user.id),
          eq4(tasks.projectId, projectId)
        )
      );
      if (dbTasks.length !== items.length) {
        throw new TRPCError3({ code: "FORBIDDEN" });
      }
      await ctx.db.transaction(async (tx) => {
        for (const item of items) {
          await tx.update(tasks).set({
            status: item.status,
            position: item.position,
            updatedAt: /* @__PURE__ */ new Date()
          }).where(eq4(tasks.id, item.id));
        }
        await recalcProjectProgress(tx, projectId, ctx.user.id);
      });
      return { success: true };
    } catch (error) {
      throw new TRPCError3({
        code: "INTERNAL_SERVER_ERROR",
        message: "Failed to reorder tasks",
        cause: error
      });
    }
  })
});

// _core/projectRouter.ts
import { eq as eq5, and as and3, desc, asc as asc2, sql as sql4, inArray } from "drizzle-orm";
import { TRPCError as TRPCError4 } from "@trpc/server";
var projectRouter = createTRPCRouter({
  // Mount task router
  task: taskRouter,
  /* ---------------------- GET ALL PROJECTS + ownerName + taskCount ---------------------- */
  getAll: protectedProcedure.query(async ({ ctx }) => {
    const data = await ctx.db.select({
      id: projects.id,
      name: projects.name,
      description: projects.description,
      status: projects.status,
      progress: projects.progress,
      color: projects.color,
      createdAt: projects.createdAt,
      // 👇 owner name
      ownerName: users.name,
      // 👇 task count
      taskCount: sql4`COUNT(${tasks.id})`.mapWith(Number)
    }).from(projects).leftJoin(users, eq5(projects.userId, users.id)).leftJoin(tasks, eq5(tasks.projectId, projects.id)).where(eq5(projects.userId, ctx.user.id)).groupBy(projects.id, users.name).orderBy(desc(projects.createdAt));
    return data;
  }),
  /* ---------------------- GET PROJECT BY ID ---------------------- */
  getById: protectedProcedure.input(z3.object({ id: z3.number() })).query(async ({ ctx, input }) => {
    const [project] = await ctx.db.select({
      id: projects.id,
      userId: projects.userId,
      name: projects.name,
      description: projects.description,
      status: projects.status,
      progress: projects.progress,
      color: projects.color,
      createdAt: projects.createdAt,
      updatedAt: projects.updatedAt,
      // ➜ Ambil nama owner dari table users
      ownerName: sql4`(
          SELECT name FROM users WHERE users.id = ${projects.userId}
        )`
    }).from(projects).where(
      and3(eq5(projects.id, input.id), eq5(projects.userId, ctx.user.id))
    ).limit(1);
    if (!project) {
      throw new TRPCError4({
        code: "NOT_FOUND",
        message: "Project not found"
      });
    }
    return project;
  }),
  /* ---------------------- DASHBOARD STATS ---------------------- */
  getStats: protectedProcedure.query(async ({ ctx }) => {
    const userId = ctx.user.id;
    const [{ count: totalProjects }] = await ctx.db.select({ count: sql4`COUNT(*)` }).from(projects).where(eq5(projects.userId, userId));
    const [{ count: totalTasks }] = await ctx.db.select({ count: sql4`COUNT(*)` }).from(tasks).where(eq5(tasks.userId, userId));
    const [{ count: completedTasks }] = await ctx.db.select({ count: sql4`COUNT(*)` }).from(tasks).where(and3(eq5(tasks.userId, userId), eq5(tasks.status, "completed")));
    return {
      projects: totalProjects,
      tasks: totalTasks,
      completedTasks
    };
  }),
  /* ---------------------- GET TASKS OF PROJECT ---------------------- */
  getTasks: protectedProcedure.input(z3.object({ projectId: z3.number() })).query(async ({ ctx, input }) => {
    const list = await ctx.db.select().from(tasks).where(
      and3(
        eq5(tasks.projectId, input.projectId),
        eq5(tasks.userId, ctx.user.id)
      )
    ).orderBy(asc2(tasks.position));
    const ids = list.map((t2) => t2.id);
    if (ids.length === 0) return [];
    const tagRows = await ctx.db.select({
      taskId: taskTags.taskId,
      id: tags.id,
      name: tags.name,
      color: tags.color
    }).from(taskTags).innerJoin(tags, eq5(tags.id, taskTags.tagId)).where(inArray(taskTags.taskId, ids));
    const grouped = {};
    tagRows.forEach((t2) => {
      if (!grouped[t2.taskId]) grouped[t2.taskId] = [];
      grouped[t2.taskId].push({
        id: t2.id,
        name: t2.name,
        color: t2.color
      });
    });
    return list.map((t2) => ({
      ...t2,
      tags: grouped[t2.id] ?? []
    }));
  }),
  /* ---------------------- ALL TASKS OF USER ---------------------- */
  getAllTasks: protectedProcedure.query(async ({ ctx }) => {
    return ctx.db.select().from(tasks).where(eq5(tasks.userId, ctx.user.id)).orderBy(desc(tasks.createdAt));
  }),
  /* ---------------------- CREATE PROJECT ---------------------- */
  create: protectedProcedure.input(
    z3.object({
      name: z3.string().min(1),
      description: z3.string().optional(),
      status: z3.enum(["active", "completed", "archived"]).optional(),
      color: z3.string().optional()
    })
  ).mutation(async ({ ctx, input }) => {
    const [project] = await ctx.db.insert(projects).values({
      userId: ctx.user.id,
      name: input.name,
      description: input.description ?? null,
      status: input.status ?? "active",
      progress: 0,
      color: input.color ?? "from-blue-500 to-blue-600"
    }).returning();
    return project;
  }),
  /* ---------------------- UPDATE PROJECT ---------------------- */
  update: protectedProcedure.input(
    z3.object({
      id: z3.number(),
      name: z3.string().min(1),
      description: z3.string().optional(),
      status: z3.enum(["active", "completed", "archived"]),
      progress: z3.number().min(0).max(100),
      color: z3.string()
    })
  ).mutation(async ({ ctx, input }) => {
    await ctx.db.update(projects).set({
      name: input.name,
      description: input.description ?? "",
      status: input.status,
      progress: input.progress,
      color: input.color,
      updatedAt: /* @__PURE__ */ new Date()
    }).where(
      and3(
        eq5(projects.id, input.id),
        eq5(projects.userId, ctx.user.id)
      )
    );
    return { success: true };
  }),
  /* ---------------------- DELETE PROJECT ---------------------- */
  delete: protectedProcedure.input(z3.object({ id: z3.number() })).mutation(async ({ ctx, input }) => {
    const [deleted] = await ctx.db.delete(projects).where(and3(eq5(projects.id, input.id), eq5(projects.userId, ctx.user.id))).returning();
    if (!deleted) {
      throw new TRPCError4({
        code: "NOT_FOUND",
        message: "Project not found"
      });
    }
    return deleted;
  })
});

// _core/systemRouter.ts
import { z as z4 } from "zod";

// _core/notification.ts
import { TRPCError as TRPCError5 } from "@trpc/server";
import { Resend as Resend2 } from "resend";
var TITLE_MAX_LENGTH = 1200;
var CONTENT_MAX_LENGTH = 2e4;
var trimValue = (value) => value.trim();
var isNonEmptyString2 = (value) => typeof value === "string" && value.trim().length > 0;
var buildEndpointUrl = (baseUrl) => {
  const normalizedBase = baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`;
  return new URL(
    "webdevtoken.v1.WebDevService/SendNotification",
    normalizedBase
  ).toString();
};
var validatePayload = (input) => {
  if (!isNonEmptyString2(input.title)) {
    throw new TRPCError5({
      code: "BAD_REQUEST",
      message: "Notification title is required."
    });
  }
  if (!isNonEmptyString2(input.content)) {
    throw new TRPCError5({
      code: "BAD_REQUEST",
      message: "Notification content is required."
    });
  }
  const title = trimValue(input.title);
  const content = trimValue(input.content);
  if (title.length > TITLE_MAX_LENGTH) {
    throw new TRPCError5({
      code: "BAD_REQUEST",
      message: `Notification title must be at most ${TITLE_MAX_LENGTH} characters.`
    });
  }
  if (content.length > CONTENT_MAX_LENGTH) {
    throw new TRPCError5({
      code: "BAD_REQUEST",
      message: `Notification content must be at most ${CONTENT_MAX_LENGTH} characters.`
    });
  }
  return { title, content };
};
async function notifyOwner(payload) {
  const { title, content } = validatePayload(payload);
  if (!ENV.forgeApiUrl || !ENV.forgeApiKey) {
    console.warn("[Notification] Forge API not configured, switching to email fallback.");
    return await sendEmailFallback({ title, content });
  }
  const endpoint = buildEndpointUrl(ENV.forgeApiUrl);
  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        accept: "application/json",
        authorization: `Bearer ${ENV.forgeApiKey}`,
        "content-type": "application/json",
        "connect-protocol-version": "1"
      },
      body: JSON.stringify({ title, content })
    });
    if (!response.ok) {
      console.warn("[Notification] Forge failed \u2192 using email fallback.");
      return await sendEmailFallback({ title, content });
    }
    console.log("[Notification] Forge delivered successfully.");
    return true;
  } catch (error) {
    console.warn("[Notification] Forge error \u2192 using email fallback:", error);
    return await sendEmailFallback({ title, content });
  }
}
async function sendEmailFallback(payload) {
  if (!ENV.resendApiKey || !ENV.emailFrom) {
    console.error("[Email] Resend not configured. Email fallback disabled.");
    return false;
  }
  try {
    const resend2 = new Resend2(ENV.resendApiKey);
    await resend2.emails.send({
      from: ENV.emailFrom,
      to: ENV.ownerOpenId || "owner@example.com",
      subject: payload.title,
      html: `
        <div>
          <h2>${payload.title}</h2>
          <p>${payload.content}</p>
        </div>
      `
    });
    console.log("[Email] Fallback email sent successfully.");
    return true;
  } catch (err) {
    console.error("[Email] Failed to send fallback email:", err);
    return false;
  }
}

// _core/systemRouter.ts
var systemRouter = router({
  // --------------------------------------------------
  // HEALTH CHECK
  // --------------------------------------------------
  health: publicProcedure.input(
    z4.object({
      timestamp: z4.number().min(0, "timestamp cannot be negative")
    })
  ).query(({ input }) => {
    return {
      ok: true,
      receivedAt: input.timestamp
    };
  }),
  // --------------------------------------------------
  // SEND NOTIFICATION TO OWNER (ADMIN ONLY)
  // --------------------------------------------------
  notifyOwner: adminProcedure.input(
    z4.object({
      title: z4.string().min(1, "title is required"),
      content: z4.string().min(1, "content is required")
    })
  ).mutation(async ({ input }) => {
    try {
      const delivered = await notifyOwner(input);
      return {
        success: true,
        delivered
      };
    } catch (err) {
      return {
        success: false,
        delivered: false,
        error: err instanceof Error ? err.message : "Unknown error"
      };
    }
  })
});

// _core/tagRouter.ts
import { z as z5 } from "zod";
import { eq as eq6, and as and4, desc as desc2, sql as sql5 } from "drizzle-orm";
import { TRPCError as TRPCError6 } from "@trpc/server";
var tagRouter = createTRPCRouter({
  // -----------------------------------------------------
  // GET ALL TAGS + USAGE COUNT (REAL)
  // -----------------------------------------------------
  getAll: protectedProcedure.query(async ({ ctx }) => {
    return ctx.db.select({
      id: tags.id,
      userId: tags.userId,
      name: tags.name,
      description: tags.description,
      color: tags.color,
      createdAt: tags.createdAt,
      // hitung jumlah task yang pakai tag ini
      usageCount: sql5`
          (SELECT COUNT(*)
           FROM ${taskTags}
           WHERE ${taskTags.tagId} = ${tags.id})
        `.as("usageCount")
    }).from(tags).where(eq6(tags.userId, ctx.user.id)).orderBy(desc2(tags.createdAt));
  }),
  getById: protectedProcedure.input(z5.object({ id: z5.number() })).query(async ({ ctx, input }) => {
    const { id } = input;
    const [tag] = await ctx.db.select().from(tags).where(and4(eq6(tags.id, id), eq6(tags.userId, ctx.user.id))).limit(1);
    if (!tag) throw new TRPCError6({ code: "NOT_FOUND" });
    return tag;
  }),
  // -----------------------------------------------------
  // CREATE TAG
  // -----------------------------------------------------
  create: protectedProcedure.input(
    z5.object({
      name: z5.string().min(1),
      description: z5.string().optional(),
      color: z5.string().optional()
    })
  ).mutation(async ({ ctx, input }) => {
    const { name, description, color } = input;
    const [already] = await ctx.db.select().from(tags).where(and4(eq6(tags.userId, ctx.user.id), eq6(tags.name, name))).limit(1);
    if (already)
      throw new TRPCError6({
        code: "CONFLICT",
        message: "Tag name already exists"
      });
    const [tag] = await ctx.db.insert(tags).values({
      userId: ctx.user.id,
      name,
      description: description ?? null,
      color: color ?? "#3b82f6"
    }).returning();
    return tag;
  }),
  // -----------------------------------------------------
  // UPDATE TAG
  // -----------------------------------------------------
  update: protectedProcedure.input(
    z5.object({
      id: z5.number(),
      name: z5.string().optional(),
      description: z5.string().optional(),
      color: z5.string().optional()
    })
  ).mutation(async ({ ctx, input }) => {
    const { id } = input;
    const [old] = await ctx.db.select().from(tags).where(and4(eq6(tags.id, id), eq6(tags.userId, ctx.user.id))).limit(1);
    if (!old) throw new TRPCError6({ code: "NOT_FOUND" });
    const [updated] = await ctx.db.update(tags).set({
      name: input.name ?? old.name,
      description: input.description ?? old.description,
      color: input.color ?? old.color
    }).where(eq6(tags.id, id)).returning();
    return updated;
  }),
  // -----------------------------------------------------
  // DELETE TAG
  // -----------------------------------------------------
  delete: protectedProcedure.input(z5.object({ id: z5.number() })).mutation(async ({ ctx, input }) => {
    const { id } = input;
    const [tag] = await ctx.db.select().from(tags).where(and4(eq6(tags.id, id), eq6(tags.userId, ctx.user.id))).limit(1);
    if (!tag) throw new TRPCError6({ code: "NOT_FOUND" });
    await ctx.db.delete(taskTags).where(eq6(taskTags.tagId, id));
    const [deleted] = await ctx.db.delete(tags).where(eq6(tags.id, id)).returning();
    return deleted;
  }),
  // -----------------------------------------------------
  // ASSIGN TAG TO TASK
  // -----------------------------------------------------
  assignToTask: protectedProcedure.input(
    z5.object({
      taskId: z5.number(),
      tagId: z5.number()
    })
  ).mutation(async ({ ctx, input }) => {
    const { taskId, tagId } = input;
    const [task] = await ctx.db.select().from(tasks).where(and4(eq6(tasks.id, taskId), eq6(tasks.userId, ctx.user.id))).limit(1);
    if (!task) throw new TRPCError6({ code: "FORBIDDEN" });
    const [tag] = await ctx.db.select().from(tags).where(and4(eq6(tags.id, tagId), eq6(tags.userId, ctx.user.id))).limit(1);
    if (!tag) throw new TRPCError6({ code: "FORBIDDEN" });
    const [existing] = await ctx.db.select().from(taskTags).where(and4(eq6(taskTags.taskId, taskId), eq6(taskTags.tagId, tagId))).limit(1);
    if (existing) return { success: true };
    await ctx.db.transaction(async (tx) => {
      await tx.insert(taskTags).values({ taskId, tagId });
      await tx.update(tags).set({ usageCount: sql5`usage_count + 1` }).where(eq6(tags.id, tagId));
    });
    return { success: true };
  }),
  // -----------------------------------------------------
  // REMOVE TAG FROM TASK
  // -----------------------------------------------------
  removeFromTask: protectedProcedure.input(
    z5.object({
      taskId: z5.number(),
      tagId: z5.number()
    })
  ).mutation(async ({ ctx, input }) => {
    const { taskId, tagId } = input;
    const [existing] = await ctx.db.select().from(taskTags).where(and4(eq6(taskTags.taskId, taskId), eq6(taskTags.tagId, tagId))).limit(1);
    if (!existing) return { success: true };
    await ctx.db.transaction(async (tx) => {
      await tx.delete(taskTags).where(and4(eq6(taskTags.taskId, taskId), eq6(taskTags.tagId, tagId)));
      await tx.update(tags).set({ usageCount: sql5`GREATEST(usage_count - 1, 0)` }).where(eq6(tags.id, tagId));
    });
    return { success: true };
  })
});

// _core/notificationRouter.ts
import { z as z6 } from "zod";
import { eq as eq7 } from "drizzle-orm";
var notificationRouter = createTRPCRouter({
  // ----------------------------------------------------
  // GET USER NOTIFICATION SETTINGS
  // ----------------------------------------------------
  get: protectedProcedure.query(async ({ ctx }) => {
    const db = ctx.db;
    const [settings] = await db.select().from(userNotificationSettings).where(eq7(userNotificationSettings.userId, ctx.user.id)).limit(1);
    if (!settings) {
      const [created] = await db.insert(userNotificationSettings).values({
        userId: ctx.user.id
      }).returning();
      return {
        ...created,
        emailNotifications: !!created.emailNotifications,
        taskDueReminder: !!created.taskDueReminder,
        newTaskAssigned: !!created.newTaskAssigned,
        marketingEmails: !!created.marketingEmails
      };
    }
    return {
      ...settings,
      emailNotifications: !!settings.emailNotifications,
      taskDueReminder: !!settings.taskDueReminder,
      newTaskAssigned: !!settings.newTaskAssigned,
      marketingEmails: !!settings.marketingEmails
    };
  }),
  // ----------------------------------------------------
  // UPDATE SETTINGS
  // ----------------------------------------------------
  update: protectedProcedure.input(
    z6.object({
      emailNotifications: z6.boolean(),
      taskDueReminder: z6.boolean(),
      newTaskAssigned: z6.boolean(),
      marketingEmails: z6.boolean()
    })
  ).mutation(async ({ input, ctx }) => {
    const db = ctx.db;
    const payload = {
      emailNotifications: input.emailNotifications ? 1 : 0,
      taskDueReminder: input.taskDueReminder ? 1 : 0,
      newTaskAssigned: input.newTaskAssigned ? 1 : 0,
      marketingEmails: input.marketingEmails ? 1 : 0,
      updatedAt: /* @__PURE__ */ new Date()
    };
    const [updated] = await db.update(userNotificationSettings).set(payload).where(eq7(userNotificationSettings.userId, ctx.user.id)).returning();
    return {
      success: true,
      settings: {
        ...updated,
        emailNotifications: !!updated.emailNotifications,
        taskDueReminder: !!updated.taskDueReminder,
        newTaskAssigned: !!updated.newTaskAssigned,
        marketingEmails: !!updated.marketingEmails
      }
    };
  })
});

// routers.ts
var appRouter = router({
  auth: authRouter,
  project: projectRouter,
  system: systemRouter,
  tag: tagRouter,
  task: taskRouter,
  notification: notificationRouter
});

// _core/context.ts
import jwt2 from "jsonwebtoken";
async function createContext(opts) {
  const { req, res } = opts;
  const db = await getDb();
  if (!db) throw new Error("Database not initialized");
  let user = null;
  const token = req.cookies?.app_session_id || req.headers["x-session-token"] || req.headers["authorization"]?.replace("Bearer ", "") || null;
  if (token) {
    try {
      const decoded = jwt2.verify(
        token,
        process.env.JWT_SECRET || "change-me"
      );
      const found = await db.query.users.findFirst({
        where: (tbl, { eq: eq8 }) => eq8(tbl.id, decoded.id)
      });
      user = found ?? null;
    } catch {
      user = null;
    }
  }
  return {
    req,
    res,
    user,
    db
  };
}

// _core/vite.ts
import express from "express";
import fs from "fs";
import { nanoid } from "nanoid";
import path2 from "path";
import { createServer as createViteServer } from "vite";

// ../vite.config.ts
import { jsxLocPlugin } from "@builder.io/vite-plugin-jsx-loc";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import path from "path";
import { defineConfig } from "vite";
import { vitePluginManusRuntime } from "vite-plugin-manus-runtime";
var plugins = [react(), tailwindcss(), jsxLocPlugin(), vitePluginManusRuntime()];
var vite_config_default = defineConfig({
  plugins,
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "client", "src"),
      "@shared": path.resolve(import.meta.dirname, "shared"),
      "@assets": path.resolve(import.meta.dirname, "attached_assets"),
      "@schema": path.resolve(import.meta.dirname, "drizzle")
    }
  },
  envDir: path.resolve(import.meta.dirname),
  root: path.resolve(import.meta.dirname, "client"),
  publicDir: path.resolve(import.meta.dirname, "client", "public"),
  build: {
    outDir: path.resolve(import.meta.dirname, "dist/public"),
    emptyOutDir: true
  },
  server: {
    host: true,
    allowedHosts: [
      ".manuspre.computer",
      ".manus.computer",
      ".manus-asia.computer",
      ".manuscomputer.ai",
      ".manusvm.computer",
      "localhost",
      "127.0.0.1"
    ],
    fs: {
      strict: true,
      deny: ["**/.*"]
    }
  }
});

// _core/vite.ts
function serveStatic(app) {
  const distPath = process.env.NODE_ENV === "development" ? path2.resolve(import.meta.dirname, "../..", "dist", "public") : path2.resolve(import.meta.dirname, "public");
  if (!fs.existsSync(distPath)) {
    console.error(
      `Could not find the build directory: ${distPath}, make sure to build the client first`
    );
  }
  app.use(express.static(distPath));
  app.use("*", (_req, res) => {
    res.sendFile(path2.resolve(distPath, "index.html"));
  });
}

// _core/index.ts
async function startServer() {
  const app = express2();
  const server = createServer(app);
  app.use(cors({
    origin: "http://localhost:5173",
    credentials: true
  }));
  app.use(express2.json({ limit: "50mb" }));
  app.use(express2.urlencoded({ limit: "50mb", extended: true }));
  registerOAuthRoutes(app);
  app.use(cookieParser());
  app.use(
    "/api/trpc",
    createExpressMiddleware({
      router: appRouter,
      createContext,
      allowBatching: false
    })
  );
  if (process.env.NODE_ENV === "production") {
    serveStatic(app);
  }
  const port = 3e3;
  server.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
  });
}
startServer().catch(console.error);
