import { Hono } from 'hono';
import { getProfile, updateProfile, uploadAvatar } from '../profiles.js';
import { uploadBase64ToDrive } from '../drive.js';
import { getSupabase } from '../supabase.js';
import { requireAuth } from '../middleware.js';

const profile = new Hono();

profile.get('/me', requireAuth, async (c) => {
  try {
    const user = c.get('user');
    return c.json({ profile: await getProfile(c.env, user.sub) });
  } catch (e) {
    return c.json({ error: e.message }, 500);
  }
});

profile.patch('/me', requireAuth, async (c) => {
  try {
    const user = c.get('user');
    const body = await c.req.json();
    return c.json({ profile: await updateProfile(c.env, user.sub, body || {}) });
  } catch (e) {
    return c.json({ error: e.message }, 500);
  }
});

profile.post('/avatar', requireAuth, async (c) => {
  try {
    const user = c.get('user');
    const { image } = await c.req.json();
    if (!image) return c.json({ error: 'Missing image' }, 400);
    return c.json({ profile: await uploadAvatar(c.env, user.sub, image) });
  } catch (e) {
    return c.json({ error: e.message }, 500);
  }
});

profile.post('/cover', requireAuth, async (c) => {
  try {
    const supabase = getSupabase(c.env);
    const user = c.get('user');
    const { image } = await c.req.json();
    if (!image) return c.json({ error: 'Missing image' }, 400);

    const fileName = `cover-${user.sub}-${Date.now()}.jpg`;
    const { publicUrl } = await uploadBase64ToDrive(c.env, user.sub, image, fileName);

    const { data, error } = await supabase
      .from('profiles')
      .upsert(
        { user_id: user.sub, cover_url: publicUrl, updated_at: new Date().toISOString() },
        { onConflict: 'user_id' }
      )
      .select()
      .single();
    if (error) throw new Error(error.message);

    return c.json({ profile: data });
  } catch (e) {
    return c.json({ error: e.message }, 500);
  }
});

export default profile;
