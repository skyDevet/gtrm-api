import { getCookie } from 'hono/cookie';
import { jwtVerify, SignJWT } from 'jose';

export async function signSession(payload, secret) {
  const key = new TextEncoder().encode(secret);
  return new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .setExpirationTime('30d')
    .sign(key);
}

export async function verifySession(token, secret) {
  const key = new TextEncoder().encode(secret);
  const { payload } = await jwtVerify(token, key);
  return payload;
}

export async function requireAuth(c, next) {
  const token = getCookie(c, 'session');
  if (!token) return c.json({ error: 'Not authenticated' }, 401);
  try {
    c.set('user', await verifySession(token, c.env.SESSION_SECRET));
    await next();
  } catch {
    return c.json({ error: 'Invalid session' }, 401);
  }
}
