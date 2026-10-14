/**
 * 认证：固定密码 + 签名 Cookie 会话
 *
 * 设计：
 *   - 密码存环境变量 ADMIN_PASSWORD
 *   - 登录成功后写 HttpOnly Cookie，值为 HMAC 签名的时间戳
 *   - Cookie 有效期 7 天
 *   - 用 SESSION_SECRET 签名，防止伪造
 *
 * 不依赖任何外部库（Web Crypto API）
 */

import type { Env } from "./types";

const COOKIE_NAME = "pp_session";
const SESSION_TTL = 7 * 24 * 3600; // 秒

/** HMAC-SHA256 签名 */
async function sign(secret: string, data: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  // base64url
  const bytes = new Uint8Array(sig);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** 恒定时间比较（防时序攻击） */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/** 解析 Cookie */
export function parseCookies(req: Request): Record<string, string> {
  const out: Record<string, string> = {};
  const raw = req.headers.get("cookie") || "";
  for (const part of raw.split(";")) {
    const idx = part.indexOf("=");
    if (idx < 0) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  }
  return out;
}

/** 生成会话 token */
export async function createSession(env: Env): Promise<string> {
  const secret = env.SESSION_SECRET || "insecure-default-change-me";
  const issued = Math.floor(Date.now() / 1000).toString();
  const sig = await sign(secret, issued);
  return `${issued}.${sig}`;
}

/** 验证会话 token */
export async function verifySession(env: Env, token: string): Promise<boolean> {
  if (!token || !token.includes(".")) return false;
  const [issued, sig] = token.split(".", 2);
  if (!issued || !sig) return false;

  const secret = env.SESSION_SECRET || "insecure-default-change-me";
  const expect = await sign(secret, issued);
  if (!timingSafeEqual(sig, expect)) return false;

  // 检查过期
  const ts = parseInt(issued, 10);
  if (!Number.isFinite(ts)) return false;
  const age = Math.floor(Date.now() / 1000) - ts;
  return age >= 0 && age < SESSION_TTL;
}

/** 检查请求是否已登录 */
export async function isAuthed(req: Request, env: Env): Promise<boolean> {
  const cookies = parseCookies(req);
  return verifySession(env, cookies[COOKIE_NAME] || "");
}

/** 验证密码（恒定时间比较） */
export function checkPassword(env: Env, input: string): boolean {
  const expected = env.ADMIN_PASSWORD;
  if (!expected) return false;   // 未配置密码 = 拒绝所有登录
  return timingSafeEqual(input, expected);
}

/** 构造 Set-Cookie 头 */
export function sessionCookie(token: string, maxAge = SESSION_TTL): string {
  return [
    `${COOKIE_NAME}=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${maxAge}`,
  ].join("; ");
}

export function clearCookie(): string {
  return `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

/** 是否需要认证（未配置密码时跳过，便于本地开发） */
export function authRequired(env: Env): boolean {
  return Boolean(env.ADMIN_PASSWORD);
}
