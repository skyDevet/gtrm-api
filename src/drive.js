import { decrypt, getTokens, updateAccessToken, getFolderIds, saveFolderIds } from './tokens.js';

export function buildAuthUrl(env) {
  const params = new URLSearchParams({
    client_id: env.GOOGLE_CLIENT_ID,
    redirect_uri: env.GOOGLE_REDIRECT_URI,
    response_type: 'code',
    access_type: 'offline',
    prompt: 'consent',
    scope: [
      'openid',
      'email',
      'profile',
      'https://www.googleapis.com/auth/drive.file'
    ].join(' ')
  });
  return `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
}

export async function exchangeCode(env, code) {
  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      redirect_uri: env.GOOGLE_REDIRECT_URI,
      grant_type: 'authorization_code'
    })
  });
  if (!res.ok) throw new Error(`Token exchange failed: ${await res.text()}`);
  const data = await res.json();
  if (data.expires_in) data.expiry_date = Date.now() + data.expires_in * 1000;
  return data;
}

async function getAccessToken(env, userId) {
  const row = await getTokens(env, userId);
  if (!row) throw new Error('No Google tokens for user — please sign in again');

  const refreshToken = await decrypt(row.refresh_token_encrypted, env.TOKEN_ENCRYPTION_KEY);

  try {
    const res = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: env.GOOGLE_CLIENT_ID,
        client_secret: env.GOOGLE_CLIENT_SECRET,
        refresh_token: refreshToken,
        grant_type: 'refresh_token'
      })
    });
    if (!res.ok) throw new Error(await res.text());
    const creds = await res.json();
    if (creds.access_token) {
      const expiry = creds.expires_in ? Date.now() + creds.expires_in * 1000 : null;
      await updateAccessToken(env, userId, creds.access_token, expiry);
      return creds.access_token;
    }
  } catch (e) {
    if (row.access_token_encrypted) {
      return await decrypt(row.access_token_encrypted, env.TOKEN_ENCRYPTION_KEY);
    }
    throw e;
  }
}

async function findOrCreateFolder(accessToken, name) {
  const escaped = name.replace(/'/g, "\\'");
  const q = encodeURIComponent(
    `mimeType='application/vnd.google-apps.folder' and name='${escaped}' and trashed=false`
  );
  const listRes = await fetch(
    `https://www.googleapis.com/drive/v3/files?q=${q}&fields=files(id,name)&spaces=drive&pageSize=5`,
    { headers: { Authorization: `Bearer ${accessToken}` } }
  );
  const listData = await listRes.json();
  if (listData.files && listData.files.length > 0) {
    return listData.files[0].id;
  }

  const createRes = await fetch('https://www.googleapis.com/drive/v3/files', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ name, mimeType: 'application/vnd.google-apps.folder' })
  });
  const created = await createRes.json();
  return created.id;
}

async function ensureFolders(env, userId, accessToken) {
  let { gtrmFolderId, gtrmThumbFolderId } = await getFolderIds(env, userId);
  let changed = false;

  if (!gtrmFolderId) {
    gtrmFolderId = await findOrCreateFolder(accessToken, 'gtrm');
    changed = true;
  }
  if (!gtrmThumbFolderId) {
    gtrmThumbFolderId = await findOrCreateFolder(accessToken, 'gtrm thumb');
    changed = true;
  }
  if (changed) {
    await saveFolderIds(env, userId, gtrmFolderId, gtrmThumbFolderId);
  }
  return { gtrmFolderId, gtrmThumbFolderId };
}

function base64ToUint8Array(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export async function uploadBase64ToDrive(env, userId, dataUrl, fileName, opts = {}) {
  const accessToken = await getAccessToken(env, userId);

  const match = dataUrl.match(/^data:((?:image|video)\/[a-zA-Z0-9+.-]+);base64,(.+)$/);
  if (!match) throw new Error('Invalid image or video data URL');
  const mimeType = match[1];
  const fileBytes = base64ToUint8Array(match[2]);

  const folders = await ensureFolders(env, userId, accessToken);
  const targetFolder = opts.toThumbnail ? folders.gtrmThumbFolderId : folders.gtrmFolderId;
  const name = fileName || `pin-${Date.now()}.${mimeType.startsWith('video/') ? 'mp4' : 'jpg'}`;

  const boundary = '-------314159265358979323846';
  const encoder = new TextEncoder();
  const part1 = encoder.encode(
    `\r\n--${boundary}\r\nContent-Type: application/json\r\n\r\n` +
    JSON.stringify({ name, mimeType, parents: [targetFolder] }) +
    `\r\n--${boundary}\r\nContent-Type: ${mimeType}\r\n\r\n`
  );
  const part3 = encoder.encode(`\r\n--${boundary}--`);

  const body = new Uint8Array(part1.length + fileBytes.length + part3.length);
  body.set(part1, 0);
  body.set(fileBytes, part1.length);
  body.set(part3, part1.length + fileBytes.length);

  const uploadRes = await fetch(
    'https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id',
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': `multipart/related; boundary=${boundary}`
      },
      body
    }
  );
  if (!uploadRes.ok) {
    throw new Error(`Drive upload failed: ${uploadRes.status} ${await uploadRes.text()}`);
  }
  const { id: fileId } = await uploadRes.json();

  const permRes = await fetch(
    `https://www.googleapis.com/drive/v3/files/${fileId}/permissions`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ role: 'reader', type: 'anyone' })
    }
  );
  if (!permRes.ok) {
    throw new Error('Uploaded to Drive but could not make the file public.');
  }

  return {
    fileId,
    publicUrl: `https://lh3.googleusercontent.com/d/${fileId}`,
    viewUrl: `https://drive.google.com/file/d/${fileId}/view`
  };
}

export async function uploadVideoWithThumb(env, userId, videoDataUrl, fileName, thumbnailDataUrl) {
  const main = await uploadBase64ToDrive(env, userId, videoDataUrl, fileName, { toThumbnail: false });
  if (thumbnailDataUrl && thumbnailDataUrl.startsWith('data:image/')) {
    try {
      const { publicUrl: thumbUrl } = await uploadBase64ToDrive(
        env, userId, thumbnailDataUrl, `${fileName}-thumb.jpg`, { toThumbnail: true }
      );
      return { ...main, thumbnailUrl: thumbUrl, thumbSource: 'client' };
    } catch (e) {
      console.warn('Client thumbnail upload failed:', e.message);
    }
  }
  return { ...main, thumbnailUrl: main.publicUrl, thumbSource: 'none' };
}

export async function setupUserFolders(env, userId) {
  try {
    const accessToken = await getAccessToken(env, userId);
    const { gtrmFolderId, gtrmThumbFolderId } = await ensureFolders(env, userId, accessToken);
    for (const folderId of [gtrmFolderId, gtrmThumbFolderId]) {
      await fetch(`https://www.googleapis.com/drive/v3/files/${folderId}/permissions`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ role: 'reader', type: 'anyone' })
      }).catch(() => {});
    }
    return { gtrmFolderId, gtrmThumbFolderId };
  } catch (e) {
    console.error('setupUserFolders failed:', e.message);
    return null;
  }
}

export async function verifyPublicUrl(url, retries = 5) {
  for (let i = 0; i < retries; i++) {
    try {
      const res = await fetch(url, { method: 'HEAD' });
      if (res.ok) return true;
    } catch {}
    await new Promise(r => setTimeout(r, 1000));
  }
  throw new Error('Google Drive failed to make the file public in time.');
}

export async function deleteDriveFile(env, userId, fileId) {
  try {
    const accessToken = await getAccessToken(env, userId);
    await fetch(`https://www.googleapis.com/drive/v3/files/${fileId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${accessToken}` }
    });
  } catch (e) {
    console.warn('Drive delete failed:', e.message);
  }
}
