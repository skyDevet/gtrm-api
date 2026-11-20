import { Hono } from 'hono';
import { cors } from 'hono/cors';
import auth from './routes/auth.js';
import pins from './routes/pins.js';
import albums from './routes/albums.js';
import profile from './routes/profile.js';

const app = new Hono();

app.use('*', cors({
  origin: (origin, c) => origin || '*',
  credentials: true
}));

app.get('/health', (c) => c.json({ ok: true }));

app.route('/auth', auth);
app.route('/pins', pins);
app.route('/albums', albums);
app.route('/profile', profile);

export default app;
