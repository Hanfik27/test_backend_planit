// _core/email.ts

import { Resend } from "resend";

const resend = new Resend(process.env.RESEND_API_KEY);

/**
 * Mengirim email ke user login
 * @param to email penerima
 * @param subject judul email
 * @param html konten HTML
 */
export async function sendEmail(to: string, subject: string, html: string) {
  try {
    await resend.emails.send({
      from: "kholis.is26@gmail.com", // ganti domain jika punya domain verified di Resend
      to,
      subject,
      html,
    });
    console.log("Email terkirim ke:", to);
  } catch (err) {
    console.error("Gagal mengirim email:", err);
  }
}
