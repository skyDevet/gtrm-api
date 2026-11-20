import { getSupabase } from './supabase.js';
import { uploadBase64ToDrive } from './drive.js';

const EDITABLE = [
  'name', 'bio', 'age', 'location', 'occupation',
  'relationship_status', 'languages', 'interests', 'avatar_url',
  'gender', 'interested_in', 'username', 'cover_url',
  'onboarding_completed', 'interested_topics', 'nsfw_allowed',
  'sexual_orientation', 'sexual_role', 'dating_enabled', 'ideal_partner'
];

export async function ensureProfile(env, user) {
  const supabase = getSupabase(env);
  const row = {
    user_id: user.id,
    email: user.email || null,
    name: user.name || null,
    avatar_url: user.picture || null
  };
  const { error } = await supabase
    .from('profiles')
    .upsert(row, { onConflict: 'user_id', ignoreDuplicates: true });
  if (error) throw new Error('ensureProfile: ' + error.message);
}

export async function getProfile(env, userId) {
  const supabase = getSupabase(env);
  const { data, error } = await supabase
    .from('profiles')
    .select('*')
    .eq('user_id', userId)
    .maybeSingle();
  if (error) throw new Error('getProfile: ' + error.message);
  return data;
}

export async function updateProfile(env, userId, patch) {
  const supabase = getSupabase(env);
  const clean = {};
  for (const k of EDITABLE) if (patch[k] !== undefined) clean[k] = patch[k];
  clean.updated_at = new Date().toISOString();

  const { error: upErr } = await supabase
    .from('profiles')
    .upsert({ user_id: userId, ...clean }, { onConflict: 'user_id' });
  if (upErr) throw new Error('updateProfile upsert: ' + upErr.message);

  const { data, error } = await supabase
    .from('profiles')
    .select('*')
    .eq('user_id', userId)
    .single();
  if (error) throw new Error('updateProfile read: ' + error.message);
  return data;
}

export async function uploadAvatar(env, userId, dataUrl) {
  const supabase = getSupabase(env);
  const fileName = `avatar-${userId}-${Date.now()}.jpg`;
  const { publicUrl } = await uploadBase64ToDrive(env, userId, dataUrl, fileName);

  const { error: upErr } = await supabase
    .from('profiles')
    .upsert(
      { user_id: userId, avatar_url: publicUrl, updated_at: new Date().toISOString() },
      { onConflict: 'user_id' }
    );
  if (upErr) throw new Error('uploadAvatar upsert: ' + upErr.message);

  const { data, error } = await supabase
    .from('profiles')
    .select('*')
    .eq('user_id', userId)
    .single();
  if (error) throw new Error('uploadAvatar read: ' + error.message);
  return data;
}
