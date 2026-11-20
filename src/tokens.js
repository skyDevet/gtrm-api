import { getSupabase } from './supabase.js';

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function importAesKey(hexKey) {
  if (!hexKey || hexKey.length !== 64) {
    throw new Error('TOKEN_ENCRYPTION_KEY must be 64 hex chars (32 bytes)');
  }
  return crypto.subtle.importKey(
    'raw',
    hexToBytes(hexKey),
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function encrypt(plaintext, hexKey) {
  const key = await importAesKey(hexKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);

  const cipherBytes = new Uint8Array(ciphertext);
  const enc = cipherBytes.slice(0, cipherBytes.length - 16);
  const tag = cipherBytes.slice(cipherBytes.length - 16);

  return `${bytesToHex(iv)}:${bytesToHex(tag)}:${bytesToHex(enc)}`;
}

export async function decrypt(payload, hexKey) {
  const [ivHex, tagHex, encHex] = payload.split(':');
  const key = await importAesKey(hexKey);
  const iv = hexToBytes(ivHex);
  const tag = hexToBytes(tagHex);
  const enc = hexToBytes(encHex);

  const combined = new Uint8Array(enc.length + tag.length);
  combined.set(enc);
  combined.set(tag, enc.length);

  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, combined);
  return new TextDecoder().decode(decrypted);
}

export async function saveTokens(env, user, tokens) {
  const supabase = getSupabase(env);
  const row = {
    user_id: user.id,
    email: user.email || null,
    name: user.name || null,
    picture: user.picture || null,
    refresh_token_encrypted: tokens.refresh_token
      ? await encrypt(tokens.refresh_token, env.TOKEN_ENCRYPTION_KEY)
      : undefined,
    access_token_encrypted: tokens.access_token
      ? await encrypt(tokens.access_token, env.TOKEN_ENCRYPTION_KEY)
      : null,
    access_token_expires_at: tokens.expiry_date ? new Date(tokens.expiry_date).toISOString() : null,
    scope: tokens.scope || null,
    updated_at: new Date().toISOString()
  };
  if (row.refresh_token_encrypted === undefined) delete row.refresh_token_encrypted;

  const { error } = await supabase.from('user_tokens').upsert(row, { onConflict: 'user_id' });
  if (error) throw new Error('saveTokens: ' + error.message);
}

export async function getTokens(env, userId) {
  const supabase = getSupabase(env);
  const { data, error } = await supabase
    .from('user_tokens').select('*').eq('user_id', userId).single();
  if (error) return null;
  return data;
}

export async function updateAccessToken(env, userId, accessToken, expiryDate) {
  const supabase = getSupabase(env);
  const { error } = await supabase
    .from('user_tokens')
    .update({
      access_token_encrypted: await encrypt(accessToken, env.TOKEN_ENCRYPTION_KEY),
      access_token_expires_at: expiryDate ? new Date(expiryDate).toISOString() : null,
      updated_at: new Date().toISOString()
    })
    .eq('user_id', userId);
  if (error) throw new Error('updateAccessToken: ' + error.message);
}

export async function getFolderIds(env, userId) {
  const supabase = getSupabase(env);
  const { data } = await supabase
    .from('user_tokens')
    .select('gtrm_folder_id, gtrm_thumb_folder_id')
    .eq('user_id', userId)
    .single();
  return {
    gtrmFolderId: data?.gtrm_folder_id || null,
    gtrmThumbFolderId: data?.gtrm_thumb_folder_id || null
  };
}

export async function saveFolderIds(env, userId, gtrmFolderId, gtrmThumbFolderId) {
  const supabase = getSupabase(env);
  await supabase
    .from('user_tokens')
    .update({ gtrm_folder_id: gtrmFolderId, gtrm_thumb_folder_id: gtrmThumbFolderId })
    .eq('user_id', userId);
}
