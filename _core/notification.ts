import { TRPCError } from "@trpc/server";
import { ENV } from "./env";
import { Resend } from "resend";

export type NotificationPayload = {
  title: string;
  content: string;
};

// ----------------------------------
// CONSTANTS
// ----------------------------------
const TITLE_MAX_LENGTH = 1200;
const CONTENT_MAX_LENGTH = 20000;

const trimValue = (value: string): string => value.trim();
const isNonEmptyString = (value: unknown): value is string =>
  typeof value === "string" && value.trim().length > 0;

// ----------------------------------
// FORGE API URL BUILDER
// ----------------------------------
const buildEndpointUrl = (baseUrl: string): string => {
  const normalizedBase = baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`;
  return new URL(
    "webdevtoken.v1.WebDevService/SendNotification",
    normalizedBase
  ).toString();
};

// ----------------------------------
// PAYLOAD VALIDATION
// ----------------------------------
const validatePayload = (input: NotificationPayload): NotificationPayload => {
  if (!isNonEmptyString(input.title)) {
    throw new TRPCError({
      code: "BAD_REQUEST",
      message: "Notification title is required.",
    });
  }
  if (!isNonEmptyString(input.content)) {
    throw new TRPCError({
      code: "BAD_REQUEST",
      message: "Notification content is required.",
    });
  }

  const title = trimValue(input.title);
  const content = trimValue(input.content);

  if (title.length > TITLE_MAX_LENGTH) {
    throw new TRPCError({
      code: "BAD_REQUEST",
      message: `Notification title must be at most ${TITLE_MAX_LENGTH} characters.`,
    });
  }

  if (content.length > CONTENT_MAX_LENGTH) {
    throw new TRPCError({
      code: "BAD_REQUEST",
      message: `Notification content must be at most ${CONTENT_MAX_LENGTH} characters.`,
    });
  }

  return { title, content };
};

// ======================================================================
// 🟦 1. NOTIFIKASI UTAMA → Forge Service
// 🟥 2. FALLBACK → Resend Email (jika Forge gagal)
// ======================================================================
export async function notifyOwner(
  payload: NotificationPayload
): Promise<boolean> {
  const { title, content } = validatePayload(payload);

  // ----------------------------------
  // CEK KONFIG
  // ----------------------------------
  if (!ENV.forgeApiUrl || !ENV.forgeApiKey) {
    console.warn("[Notification] Forge API not configured, switching to email fallback.");
    return await sendEmailFallback({ title, content });
  }

  const endpoint = buildEndpointUrl(ENV.forgeApiUrl);

  try {
    // ----------------------------------
    // 🔵 KIRIM KE FORGE
    // ----------------------------------
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        accept: "application/json",
        authorization: `Bearer ${ENV.forgeApiKey}`,
        "content-type": "application/json",
        "connect-protocol-version": "1",
      },
      body: JSON.stringify({ title, content }),
    });

    if (!response.ok) {
      console.warn("[Notification] Forge failed → using email fallback.");
      return await sendEmailFallback({ title, content });
    }

    console.log("[Notification] Forge delivered successfully.");
    return true;
  } catch (error) {
    console.warn("[Notification] Forge error → using email fallback:", error);
    return await sendEmailFallback({ title, content });
  }
}

// ======================================================================
// 📧 RESEND FALLBACK EMAIL
// ======================================================================
async function sendEmailFallback(payload: NotificationPayload): Promise<boolean> {
  if (!ENV.resendApiKey || !ENV.emailFrom) {
    console.error("[Email] Resend not configured. Email fallback disabled.");
    return false;
  }

  try {
    const resend = new Resend(ENV.resendApiKey);

    await resend.emails.send({
      from: ENV.emailFrom,
      to: ENV.ownerOpenId || "owner@example.com",
      subject: payload.title,
      html: `
        <div>
          <h2>${payload.title}</h2>
          <p>${payload.content}</p>
        </div>
      `,
    });

    console.log("[Email] Fallback email sent successfully.");
    return true;
  } catch (err) {
    console.error("[Email] Failed to send fallback email:", err);
    return false;
  }
}
