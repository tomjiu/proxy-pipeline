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

/**
 * 获取会话签名密钥
 *
 * ⚠️ 安全：**不回退到硬编码密钥**（fail-closed）
 *    若 SESSION_SECRET 未配置，返回 null，调用方拒绝签发/校验会话。
 *    旧实现 `env.SESSION_SECRET || "insecure-default-change-me"` 会让
 *    任何人用源码里的公开常量离线伪造会话 Cookie 绕过登录。
 */
function getSecret(env: Env): string | null {
  const s = env.SESSION_SECRET;
  if (!s || s.length < 16) {
    console.error("[auth] SESSION_SECRET 未配置或过短（需 ≥16 字符），会话功能已禁用");
    return null;
  }
  return s;
}

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

/**
 * 恒定时间比较（长度无关）
 * 用 HMAC 把两侧都归一到固定长度，消除长度分支
 */
async function constantTimeEqual(a: string, b: string): Promise<boolean> {
  const enc = new TextEncoder();
  // 固定密钥做 HMAC，输出定长 32 字节
  const key = await crypto.subtle.importKey(
    "raw", enc.encode("ct-compare-key"),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const [ha, hb] = await Promise.all([
    crypto.subtle.sign("HMAC", key, enc.encode(a)),
    crypto.subtle.sign("HMAC", key, enc.encode(b)),
  ]);
  const va = new Uint8Array(ha);
  const vb = new Uint8Array(hb);
  let diff = 0;
  for (let i = 0; i < va.length; i++) diff |= va[i] ^ vb[i];
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
  const secret = getSecret(env);
  if (!secret) throw new Error("SESSION_SECRET not configured");
  const issued = Math.floor(Date.now() / 1000).toString();
  const sig = await sign(secret, issued);
  return `${issued}.${sig}`;
}

/** 验证会话 token */
export async function verifySession(env: Env, token: string): Promise<boolean> {
  if (!token || !token.includes(".")) return false;
  const [issued, sig] = token.split(".", 2);
  if (!issued || !sig) return false;

  const secret = getSecret(env);
  if (!secret) return false;   // fail-closed：无密钥则不认任何会话

  const expect = await sign(secret, issued);
  if (!(await constantTimeEqual(sig, expect))) return false;

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

/** 验证密码（恒定时间比较，长度无关） */
export async function checkPassword(env: Env, input: string): Promise<boolean> {
  const expected = env.ADMIN_PASSWORD;
  if (!expected) return false;   // 未配置密码 = 拒绝所有登录
  return constantTimeEqual(input, expected);
}

/** 恒定时间比较（导出给 API_TOKEN 校验复用） */
export { constantTimeEqual };

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
