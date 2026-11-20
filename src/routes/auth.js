import { Hono } from 'hono';
import { setCookie, getCookie, deleteCookie } from 'hono/cookie';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { buildAuthUrl, exchangeCode, setupUserFolders } from '../drive.js';
import { saveTokens, getTokens } from '../tokens.js';
import { ensureProfile, getProfile } from '../profiles.js';
import { getSupabase } from '../supabase.js';
import { requireAuth, signSession, verifySession } from '../middleware.js';

const auth = new Hono();
const GOOGLE_JWKS = createRemoteJWKSet(new URL('https://www.googleapis.com/oauth2/v3/certs'));

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const hashBuffer = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    256
  );
  const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
  const hashHex = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
  return `${saltHex}:${hashHex}`;
}

async function verifyPassword(password, storedHash) {
  try {
    const [saltHex, originalHashHex] = storedHash.split(':');
    const salt = new Uint8Array(saltHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const keyMaterial = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']
    );
    const hashBuffer = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
      keyMaterial,
      256
    );
    const hashHex = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex === originalHashHex;
  } catch {
    return false;
  }
}

function setSessionCookie(c, jwtToken) {
  setCookie(c, 'session', jwtToken, {
    httpOnly: true,
    sameSite: 'Lax',
    secure: c.env.NODE_ENV === 'production',
    path: '/',
    maxAge: 30 * 24 * 60 * 60
  });
}

auth.post('/signup', async (c) => {
  try {
    const supabase = getSupabase(c.env);
    const { email, password, name } = await c.req.json();
    if (!email || !password) return c.json({ error: 'Email and password required' }, 400);

    const { data: existing } = await supabase
      .from('profiles')
      .select('user_id')
      .eq('email', email)
      .maybeSingle();
    if (existing) return c.json({ error: 'Email already in use' }, 400);

    const userId = crypto.randomUUID();
    const passwordHash = await hashPassword(password);
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

    const { error: dbErr } = await supabase.from('profiles').insert({
      user_id: userId,
      email,
      name: name || email.split('@')[0],
      password_hash: passwordHash,
      onboarding_completed: false,
      email_verified: false,
      verification_code: verificationCode,
      verification_expires: expiresAt
    });
    if (dbErr) throw new Error(dbErr.message);

    console.log(`VERIFICATION CODE FOR ${email}: ${verificationCode}`);
    return c.json({
      success: true,
      requiresVerification: true,
      message: 'Check logs (or email) for the 6-digit code'
    });
  } catch (e) {
    return c.json({ error: e.message }, 500);
  }
});

auth.post('/verify-email', async (c) => {
  try {
    const supabase = getSupabase(c.env);
    const { email, code } = await c.req.json();
    const { data: profile, error } = await supabase
      .from('profiles')
      .select('user_id, verification_code, verification_expires, name')
      .eq('email', email)
      .maybeSingle();
    if (error || !profile) return c.json({ error: 'User not found' }, 404);
    if (profile.verification_code !== code) return c.json({ error: 'Invalid verification code' }, 400);
    if (new Date(profile.verification_expires) < new Date()) return c.json({ error: 'Verification code expired' }, 400);

    await supabase
      .from('profiles')
      .update({ email_verified: true, verification_code: null, verification_expires: null })
      .eq('user_id', profile.user_id);

    const sessionJwt = await signSession(
      { sub: profile.user_id, email, name: profile.name },
      c.env.SESSION_SECRET
    );
    setSessionCookie(c, sessionJwt);
    return c.json({ success: true, user: { id: profile.user_id, email, name: profile.name } });
  } catch (e) {
    return c.json({ error: e.message }, 500);
  }
});

auth.post('/login', async (c) => {
  try {
    const supabase = getSupabase(c.env);
    const { email, password } = await c.req.json();
    if (!email || !password) return c.json({ error: 'Email and password required' }, 400);

    const { data: profile, error } = await supabase
      .from('profiles')
      .select('*')
      .eq('email', email)
      .maybeSingle();
    if (error || !profile || !profile.password_hash) {
      return c.json({ error: 'Invalid email or password' }, 401);
    }
    if (!(await verifyPassword(password, profile.password_hash))) {
      return c.json({ error: 'Invalid email or password' }, 401);
    }

    const sessionJwt = await signSession(
      { sub: profile.user_id, email: profile.email, name: profile.name },
      c.env.SESSION_SECRET
    );
    setSessionCookie(c, sessionJwt);
    return c.json({ success: true, user: { id: profile.user_id, email: profile.email, name: profile.name } });
  } catch (e) {
    return c.json({ error: e.message }, 500);
  }
});

auth.post('/change-password', requireAuth, async (c) => {
  try {
    const supabase = getSupabase(c.env);
    const user = c.get('user');
    const { oldPassword, newPassword } = await c.req.json();
    if (!newPassword) return c.json({ error: 'New password required' }, 400);
    if (newPassword.length < 6) return c.json({ error: 'New password must be at least 6 characters' }, 400);

    const { data: profile, error } = await supabase
      .from('profiles')
      .select('password_hash')
      .eq('user_id', user.sub)
      .maybeSingle();
    if (error || !profile) return c.json({ error: 'User not found' }, 404);

    if (profile.password_hash) {
      if (!oldPassword) return c.json({ error: 'Current password required' }, 400);
      if (!(await verifyPassword(oldPassword, profile.password_hash))) {
        return c.json({ error: 'Incorrect current password' }, 401);
      }
    }

    const newHash = await hashPassword(newPassword);
    const { error: updateErr } = await supabase
      .from('profiles')
      .update({ password_hash: newHash })
      .eq('user_id', user.sub);
    if (updateErr) throw new Error(updateErr.message);
    return c.json({ success: true });
  } catch (e) {
    return c.json({ error: e.message }, 500);
  }
});

auth.get('/google', (c) => {
  return c.redirect(buildAuthUrl(c.env));
});

auth.get('/callback', async (c) => {
  try {
    const code = c.req.query('code');
    if (!code) return c.text('Missing code', 400);
    const tokens = await exchangeCode(c.env, code);
    const { payload } = await jwtVerify(tokens.id_token, GOOGLE_JWKS, {
      issuer: ['https://accounts.google.com', 'accounts.google.com'],
      audience: c.env.GOOGLE_CLIENT_ID
    });
    const user = {
      id: payload.sub,
      email: payload.email,
      name: payload.name,
      picture: payload.picture
    };
    if (!tokens.refresh_token) {
      const existing = await getTokens(c.env, user.id);
      if (!existing) {
        return c.text('No refresh token. Revoke app access at myaccount.google.com/permissions and try again.', 400);
      }
    } else {
      await saveTokens(c.env, user, tokens);
      await ensureProfile(c.env, user);
      await setupUserFolders(c.env, user.id);
    }

    const sessionJwt = await signSession(
      { sub: user.id, email: user.email, name: user.name, picture: user.picture },
      c.env.SESSION_SECRET
    );
    setSessionCookie(c, sessionJwt);
    return c.redirect(c.env.APP_REDIRECT_URL || '/');
  } catch (e) {
    return c.text('Auth failed: ' + e.message, 500);
  }
});

auth.get('/me', async (c) => {
  const token = getCookie(c, 'session');
  if (!token) return c.json({ user: null, hasDrive: false });
  try {
    const payload = await verifySession(token, c.env.SESSION_SECRET);
    let profile = null;
    try { profile = await getProfile(c.env, payload.sub); } catch {}
    const tokensRow = await getTokens(c.env, payload.sub);
    return c.json({
      user: {
        id: payload.sub,
        email: payload.email,
        name: payload.name,
        picture: payload.picture
      },
      profile,
      hasDrive: !!tokensRow?.refresh_token_encrypted
    });
  } catch {
    return c.json({ user: null, hasDrive: false });
  }
});

auth.post('/logout', (c) => {
  deleteCookie(c, 'session', { path: '/' });
  return c.json({ ok: true });
});

export default auth;
