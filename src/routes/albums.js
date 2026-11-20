import { Hono } from 'hono';
import { getSupabase } from '../supabase.js';
import { requireAuth } from '../middleware.js';

const albums = new Hono();

albums.get('/', requireAuth, async (c) => {
  try {
    const supabase = getSupabase(c.env);
    const user = c.get('user');
    const { data, error } = await supabase
      .from('albums').select('*').eq('user_id', user.sub)
      .order('created_at', { ascending: false });
    if (error) throw new Error(error.message);
    return c.json({ albums: data || [] });
  } catch (e) {
    return c.json({ error: e.message }, 500);
  }
});

albums.post('/', requireAuth, async (c) => {
  try {
    const supabase = getSupabase(c.env);
    const user = c.get('user');
    const { name } = await c.req.json();
    if (!name || !name.trim()) return c.json({ error: 'Album name required' }, 400);

    const { data: existing } = await supabase
      .from('albums').select('*')
      .eq('user_id', user.sub).eq('name', name.trim()).maybeSingle();
    if (existing) return c.json({ album: existing });

    const { data, error } = await supabase
      .from('albums')
      .insert({ user_id: user.sub, name: name.trim() })
      .select().single();
    if (error) throw new Error(error.message);
    return c.json({ album: data });
  } catch (e) {
    return c.json({ error: e.message }, 500);
  }
});

export default albums;
