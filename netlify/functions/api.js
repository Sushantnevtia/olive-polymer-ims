// netlify/functions/api.js
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY;

const headers = {
  'Content-Type': 'application/json',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type, X-Session-Token',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
};

async function hashPassword(password, salt) {
  const encoder = new TextEncoder();
  const data = encoder.encode(salt + password + 'olive_polymer_2024');
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function sbGet(key) {
  const res = await fetch(
    `${SUPABASE_URL}/rest/v1/ims_data?key=eq.${encodeURIComponent(key)}&select=value`,
    { headers: { 'apikey': SUPABASE_KEY, 'Authorization': `Bearer ${SUPABASE_KEY}` } }
  );
  const data = await res.json();
  return data && data.length ? data[0].value : null;
}

async function sbSet(key, value) {
  await fetch(`${SUPABASE_URL}/rest/v1/ims_data`, {
    method: 'POST',
    headers: {
      'apikey': SUPABASE_KEY,
      'Authorization': `Bearer ${SUPABASE_KEY}`,
      'Content-Type': 'application/json',
      'Prefer': 'resolution=merge-duplicates'
    },
    body: JSON.stringify({ id: key, key, value, updated_at: new Date().toISOString() })
  });
}

async function createSession(userId, username, role) {
  const token = crypto.randomUUID();
  const session = { userId, username, role, createdAt: Date.now(), expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000 };
  await sbSet(`session-${token}`, JSON.stringify(session));
  return token;
}

async function validateSession(token) {
  if (!token) return null;
  const val = await sbGet(`session-${token}`);
  if (!val) return null;
  const session = JSON.parse(val);
  if (Date.now() > session.expiresAt) return null;
  return session;
}

function legacySimpleHash(str) {
  let h = 5381;
  for (let i = 0; i < str.length; i++) h = ((h << 5) + h) + str.charCodeAt(i);
  return (h >>> 0).toString(36);
}

export default async (req, context) => {
  if (req.method === 'OPTIONS') return new Response('', { status: 200, headers });

  const url = new URL(req.url);
  const action = url.searchParams.get('action');
  const sessionToken = req.headers.get('X-Session-Token');

  try {
    if (action === 'login') {
      const { username, password } = await req.json();
      const usersRaw = await sbGet('ims-users-v1');
      const users = usersRaw ? JSON.parse(usersRaw) : [];

      if (!users.length) {
        const salt = 'default_salt';
        const hash = await hashPassword('admin123', salt);
        users.push({ id: 'u0', username: 'admin', passwordHash: hash, salt, role: 'admin' });
        await sbSet('ims-users-v1', JSON.stringify(users));
      }

      const user = users.find(u => u.username === username);
      if (!user) return new Response(JSON.stringify({ error: 'Invalid credentials' }), { status: 401, headers });

      const hash = await hashPassword(password, user.salt || 'legacy');
      const legacyHash = legacySimpleHash(password);
      if (user.passwordHash !== hash && user.passwordHash !== legacyHash) {
        return new Response(JSON.stringify({ error: 'Invalid credentials' }), { status: 401, headers });
      }

      // Migrate legacy hash to SHA-256
      if (user.passwordHash === legacyHash) {
        user.salt = crypto.randomUUID();
        user.passwordHash = await hashPassword(password, user.salt);
        await sbSet('ims-users-v1', JSON.stringify(users));
      }

      const token = await createSession(user.id, user.username, user.role);
      return new Response(JSON.stringify({ token, username: user.username, role: user.role }), { status: 200, headers });
    }

    const session = await validateSession(sessionToken);
    if (!session) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers });

    if (action === 'getData') {
      const val = await sbGet('ims-db-v2');
      return new Response(JSON.stringify({ data: val ? JSON.parse(val) : {} }), { status: 200, headers });
    }

    if (action === 'saveData') {
      const { data } = await req.json();
      await sbSet('ims-db-v2', JSON.stringify(data));
      return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
    }

    if (action === 'getUsers') {
      if (session.role !== 'admin') return new Response(JSON.stringify({ error: 'Forbidden' }), { status: 403, headers });
      const val = await sbGet('ims-users-v1');
      const users = val ? JSON.parse(val) : [];
      return new Response(JSON.stringify({ users: users.map(u => ({ id: u.id, username: u.username, role: u.role })) }), { status: 200, headers });
    }

    if (action === 'addUser') {
      if (session.role !== 'admin') return new Response(JSON.stringify({ error: 'Forbidden' }), { status: 403, headers });
      const { username, password, role } = await req.json();
      const val = await sbGet('ims-users-v1');
      const users = val ? JSON.parse(val) : [];
      if (users.find(u => u.username === username)) return new Response(JSON.stringify({ error: 'Username already exists' }), { status: 400, headers });
      const salt = crypto.randomUUID();
      const hash = await hashPassword(password, salt);
      users.push({ id: `u${Date.now()}`, username, passwordHash: hash, salt, role });
      await sbSet('ims-users-v1', JSON.stringify(users));
      return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
    }

    if (action === 'deleteUser') {
      if (session.role !== 'admin') return new Response(JSON.stringify({ error: 'Forbidden' }), { status: 403, headers });
      const { userId } = await req.json();
      if (userId === 'u0') return new Response(JSON.stringify({ error: 'Cannot delete default admin' }), { status: 400, headers });
      const val = await sbGet('ims-users-v1');
      let users = val ? JSON.parse(val) : [];
      users = users.filter(u => u.id !== userId);
      await sbSet('ims-users-v1', JSON.stringify(users));
      return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
    }

    if (action === 'resetPassword') {
      if (session.role !== 'admin') return new Response(JSON.stringify({ error: 'Forbidden' }), { status: 403, headers });
      const { userId, newPassword } = await req.json();
      const val = await sbGet('ims-users-v1');
      const users = val ? JSON.parse(val) : [];
      const user = users.find(u => u.id === userId);
      if (!user) return new Response(JSON.stringify({ error: 'User not found' }), { status: 404, headers });
      user.salt = crypto.randomUUID();
      user.passwordHash = await hashPassword(newPassword, user.salt);
      await sbSet('ims-users-v1', JSON.stringify(users));
      return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
    }

    if (action === 'logout') {
      await sbSet(`session-${sessionToken}`, JSON.stringify({ expired: true, expiresAt: 0 }));
      return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
    }

    return new Response(JSON.stringify({ error: 'Unknown action' }), { status: 400, headers });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), { status: 500, headers });
  }
};

export const config = { path: '/api' };
