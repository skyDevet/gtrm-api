import { Hono } from 'hono';
import { getSupabase } from '../supabase.js';
import { uploadBase64ToDrive, uploadVideoWithThumb, deleteDriveFile, verifyPublicUrl } from '../drive.js';
import { requireAuth } from '../middleware.js';

const pins = new Hono();

pins.post('/', requireAuth, async (c) => {
  try {
    const supabase = getSupabase(c.env);
    const user = c.get('user');
    const {
      image, thumbnail, title, description, category, class: className,
      imageWidth, imageHeight, features, pose, isVideo, embedding
    } = await c.req.json();
    if (!image) return c.json({ error: 'Missing image' }, 400);

    const ext = isVideo ? 'mp4' : 'jpg';
    const fileName = `${(title || 'pin').slice(0, 60).replace(/[^a-z0-9_-]/gi, '_')}-${Date.now()}.${ext}`;

    let fileId, publicUrl, viewUrl, thumbnailUrl;
    if (isVideo) {
      const result = await uploadVideoWithThumb(c.env, user.sub, image, fileName, thumbnail);
      fileId = result.fileId;
      publicUrl = result.publicUrl;
      viewUrl = result.viewUrl;
      thumbnailUrl = result.thumbnailUrl;
      await verifyPublicUrl(publicUrl);
      if (thumbnailUrl !== publicUrl) await verifyPublicUrl(thumbnailUrl);
    } else {
      const main = await uploadBase64ToDrive(c.env, user.sub, image, fileName, { toThumbnail: false });
      fileId = main.fileId;
      publicUrl = main.publicUrl;
      viewUrl = main.viewUrl;
      await verifyPublicUrl(publicUrl);
      if (thumbnail && thumbnail !== image) {
        try {
          const { publicUrl: thumbUrl } = await uploadBase64ToDrive(
            c.env, user.sub, thumbnail, `${fileName}-thumb.jpg`, { toThumbnail: true }
          );
          await verifyPublicUrl(thumbUrl);
          thumbnailUrl = thumbUrl;
        } catch {
          thumbnailUrl = publicUrl;
        }
      } else {
        thumbnailUrl = publicUrl;
      }
    }

    const row = {
      user_id: user.sub,
      user_email: user.email || null,
      user_name: user.name || null,
      user_picture: user.picture || null,
      drive_file_id: fileId,
      drive_url: publicUrl,
      drive_view_url: viewUrl,
      thumbnail_url: thumbnailUrl,
      title: title || 'Untitled',
      description: description || '',
      category: category || 'Uncategorized',
      class: className || '',
      image_width: imageWidth || 0,
      image_height: imageHeight || 0,
      features: features || null,
      pose: pose || null,
      is_video: isVideo || false,
      embedding: embedding || null
    };

    const { data, error } = await supabase.from('pins').insert(row).select().single();
    if (error) throw new Error('Supabase insert: ' + error.message);
    return c.json({ success: true, pin: data });
  } catch (e) {
    return c.json({ error: e.message }, 500);
  }
});

pins.get('/', async (c) => {
  try {
    const supabase = getSupabase(c.env);
    const category = c.req.query('category');
    const className = c.req.query('class');
    const q = c.req.query('q');
    const limit = Number(c.req.query('limit') || 200);

    let query = supabase
      .from('pins')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(limit);

    if (category && category !== 'all') query = query.eq('category', category);
    if (className) query = query.eq('class', className);
    if (q) query = query.ilike('title', `%${q}%`);

    const { data, error } = await query;
    if (error) throw new Error(error.message);

    const formatted = (data || []).map(row => ({
      id: row.id,
      driveFileId: row.drive_file_id,
      driveUrl: row.drive_url,
      image: row.drive_url,
      thumbnail: row.thumbnail_url || row.drive_url,
      title: row.title,
      description: row.description,
      category: row.category,
      class: row.class,
      imageWidth: row.image_width,
      imageHeight: row.image_height,
      features: row.features,
      pose: row.pose,
      likes: row.likes,
      saved: row.saved,
      comments: row.comments,
      isVideo: row.is_video,
      albumId: row.album_id,
      embedding: row.embedding,
      createdAt: new Date(row.created_at).getTime(),
      owner: {
        id: row.user_id,
        name: row.user_name,
        email: row.user_email,
        picture: row.user_picture
      }
    }));

    return c.json({ pins: formatted });
  } catch (e) {
    return c.json({ error: e.message }, 500);
  }
});

pins.patch('/:id', async (c) => {
  try {
    const supabase = getSupabase(c.env);
    const id = c.req.param('id');
    const { likes, saved, comments, albumId } = await c.req.json();
    const update = {};
    if (likes !== undefined) update.likes = likes;
    if (saved !== undefined) update.saved = saved;
    if (comments !== undefined) update.comments = comments;
    if (albumId !== undefined) update.album_id = albumId;

    if (Object.keys(update).length === 0) {
      return c.json({ error: 'No valid fields to update' }, 400);
    }

    const { data, error } = await supabase
      .from('pins').update(update).eq('id', id).select().single();
    if (error) throw new Error(error.message);
    return c.json({ success: true, pin: data });
  } catch (e) {
    return c.json({ error: e.message }, 500);
  }
});

pins.delete('/:id', requireAuth, async (c) => {
  try {
    const supabase = getSupabase(c.env);
    const user = c.get('user');
    const id = c.req.param('id');

    const { data: row, error: fetchErr } = await supabase
      .from('pins').select('*').eq('id', id).single();
    if (fetchErr) throw new Error(fetchErr.message);
    if (row.user_id !== user.sub) return c.json({ error: 'Not owner' }, 403);

    await deleteDriveFile(c.env, user.sub, row.drive_file_id);
    const { error: delErr } = await supabase.from('pins').delete().eq('id', id);
    if (delErr) throw new Error(delErr.message);

    return c.json({ success: true });
  } catch (e) {
    return c.json({ error: e.message }, 500);
  }
});

export default pins;
