import 'dotenv/config';
import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { applicationDefault, getApps, initializeApp } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';
import { createDatabasePool } from './db/pool.js';

const port = Number(process.env.PORT || 3000);
const projectId = process.env.FIREBASE_PROJECT_ID;
if (!projectId || projectId.startsWith('replace-')) throw new Error('Set FIREBASE_PROJECT_ID in your .env file.');
if (!getApps().length) initializeApp({ credential: applicationDefault(), projectId });

const pool = createDatabasePool();
const app = express();
const root = path.dirname(fileURLToPath(import.meta.url));
let previousCpuSample = null;

app.disable('x-powered-by');
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", 'https://www.gstatic.com', 'https://cdn.tailwindcss.com', 'https://cdn.jsdelivr.net'],
            scriptSrcAttr: ["'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
            fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
            imgSrc: ["'self'", 'data:', 'https:'],
            connectSrc: ["'self'", 'https://identitytoolkit.googleapis.com', 'https://securetoken.googleapis.com', 'https://www.googleapis.com', 'https://api.mux.com', 'https://stream.mux.com'],
            mediaSrc: ["'self'", 'blob:', 'https://stream.mux.com'],
            objectSrc: ["'none'"],
            upgradeInsecureRequests: null
        }
    },
    crossOriginEmbedderPolicy: false
}));
app.post('/api/webhooks/mux', express.raw({ type: 'application/json', limit: '256kb' }), async (req, res, next) => {
    const secret = process.env.MUX_WEBHOOK_SECRET;
    const signatureHeader = req.get('mux-signature') || '';
    if (!secret) return res.status(503).json({ error: 'El webhook de Mux no está configurado.' });
    const values = Object.fromEntries(signatureHeader.split(',').map(part => part.split('=')));
    const timestamp = values.t;
    const signature = values.v1;
    if (!Buffer.isBuffer(req.body) || !timestamp || !signature || !/^\d+$/.test(timestamp)
        || Math.abs(Date.now() / 1000 - Number(timestamp)) > 300) {
        return res.status(401).json({ error: 'La firma del webhook no es válida.' });
    }
    const expected = createHmac('sha256', secret).update(`${timestamp}.${req.body.toString('utf8')}`).digest();
    let received;
    try {
        received = Buffer.from(signature, 'hex');
    } catch {
        return res.status(401).json({ error: 'La firma del webhook no es válida.' });
    }
    if (received.length !== expected.length || !timingSafeEqual(received, expected)) {
        return res.status(401).json({ error: 'La firma del webhook no es válida.' });
    }
    try {
        const event = JSON.parse(req.body.toString('utf8'));
        const object = event.data || {};
        if (event.type === 'video.live_stream.active' || event.type === 'video.live_stream.idle'
            || event.type === 'video.live_stream.disabled' || event.type === 'video.live_stream.expired') {
            const active = event.type === 'video.live_stream.active';
            await pool.query(
                `UPDATE creator_streams SET status = $1, updated_at = NOW()
                 WHERE mux_live_stream_id = $2`,
                [active ? 'active' : 'idle', object.id]
            );
            await pool.query(
                `UPDATE creators SET is_live = $1 WHERE firebase_uid = (
                    SELECT creator_uid FROM creator_streams WHERE mux_live_stream_id = $2
                 )`,
                [active, object.id]
            );
        } else if (['video.asset.created', 'video.asset.updated', 'video.asset.ready', 'video.asset.errored'].includes(event.type)) {
            const liveStreamId = object.live_stream_id;
            if (liveStreamId) {
                const owner = await pool.query(
                    `SELECT s.creator_uid, u.nickname FROM creator_streams s
                     JOIN users u ON u.firebase_uid = s.creator_uid
                     WHERE s.mux_live_stream_id = $1`,
                    [liveStreamId]
                );
                if (owner.rowCount) {
                    const playbackId = object.playback_ids?.find(item => item.policy === 'public')?.id || null;
                    const status = event.type === 'video.asset.ready' ? 'ready'
                        : event.type === 'video.asset.errored' ? 'errored'
                            : object.status || 'preparing';
                    await pool.query(
                        `INSERT INTO stream_assets (mux_asset_id, creator_uid, creator_nickname, title, playback_id, status, duration_seconds)
                         VALUES ($1, $2, $3, $4, $5, $6, $7)
                         ON CONFLICT (mux_asset_id) DO UPDATE SET playback_id = COALESCE(EXCLUDED.playback_id, stream_assets.playback_id),
                             status = EXCLUDED.status, duration_seconds = COALESCE(EXCLUDED.duration_seconds, stream_assets.duration_seconds),
                             updated_at = NOW()`,
                        [object.id, owner.rows[0].creator_uid, owner.rows[0].nickname,
                            object.meta?.title || 'Retransmisión Cyber Win', playbackId, status, object.duration || null]
                    );
                }
            }
        } else if (event.type === 'video.asset.deleted') {
            await pool.query('DELETE FROM stream_assets WHERE mux_asset_id = $1', [object.id]);
        }
        res.status(200).json({ received: true });
    } catch (error) {
        if (error instanceof SyntaxError) return res.status(400).json({ error: 'El evento de Mux no contiene JSON válido.' });
        next(error);
    }
});
app.use(express.json({ limit: '2mb' }));
app.use('/api/', rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: 'draft-7', legacyHeaders: false }));

async function requireFirebaseUser(req, res, next) {
    const authorization = req.get('authorization') || '';
    const token = authorization.startsWith('Bearer ') ? authorization.slice(7) : '';
    if (!token) return res.status(401).json({ error: 'Inicia sesión para continuar.' });
    try {
        req.identity = await getAuth().verifyIdToken(token);
        next();
    } catch (error) {
        console.warn('Firebase ID token rejected:', error.message);
        res.status(401).json({ error: 'La sesión no es válida. Inicia sesión de nuevo.' });
    }
}

async function requireAdmin(req, res, next) {
    try {
        const result = await pool.query('SELECT role FROM users WHERE firebase_uid = $1', [req.identity.uid]);
        if (result.rows[0]?.role !== 'admin') return res.status(403).json({ error: 'Se requiere una cuenta administradora.' });
        next();
    } catch (error) {
        next(error);
    }
}

function profileFromRow(row) {
    return {
        email: row.email,
        nickname: row.nickname,
        tag: row.player_tag,
        role: row.role,
        theme: row.theme_key,
        accentColor: row.accent_color,
        avatar: row.avatar_data,
        banner: row.banner_data,
        bannerColor: row.banner_color,
        isCreator: row.is_creator === true
    };
}

function muxConfigured() {
    return Boolean(process.env.MUX_TOKEN_ID && process.env.MUX_TOKEN_SECRET);
}

async function muxRequest(endpoint, options = {}) {
    if (!muxConfigured()) throw Object.assign(new Error('El servicio de vídeo no está configurado. Contacta al administrador.'), { status: 503 });
    const response = await fetch(`https://api.mux.com/video/v1${endpoint}`, {
        ...options,
        headers: {
            Authorization: `Basic ${Buffer.from(`${process.env.MUX_TOKEN_ID}:${process.env.MUX_TOKEN_SECRET}`).toString('base64')}`,
            'Content-Type': 'application/json',
            ...options.headers
        },
        signal: AbortSignal.timeout(15_000)
    });
    if (!response.ok) {
        const details = await response.text();
        console.error(`Mux API ${endpoint} returned ${response.status}: ${details.slice(0, 500)}`);
        throw Object.assign(new Error(`Mux no pudo completar la operación (${response.status}).`), { status: 502 });
    }
    if (response.status === 204) return null;
    return response.json();
}

function encryptStreamKey(streamKey) {
    const key = createHash('sha256').update(process.env.MUX_TOKEN_SECRET).digest();
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(streamKey, 'utf8'), cipher.final()]);
    return `${iv.toString('hex')}:${cipher.getAuthTag().toString('hex')}:${encrypted.toString('hex')}`;
}

function decryptStreamKey(value) {
    const [ivHex, tagHex, encryptedHex] = value.split(':');
    const decipher = createDecipheriv('aes-256-gcm', createHash('sha256').update(process.env.MUX_TOKEN_SECRET).digest(), Buffer.from(ivHex, 'hex'));
    decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
    return Buffer.concat([decipher.update(Buffer.from(encryptedHex, 'hex')), decipher.final()]).toString('utf8');
}

function cpuSnapshot() {
    return os.cpus().reduce((totals, cpu) => {
        for (const [state, value] of Object.entries(cpu.times)) totals[state] = (totals[state] || 0) + value;
        return totals;
    }, {});
}

async function upsertUser(identity) {
    if (!identity.email) throw Object.assign(new Error('La cuenta Firebase debe tener un correo electrónico.'), { status: 400 });
    const result = await pool.query(
        `INSERT INTO users (firebase_uid, email)
         VALUES ($1, $2)
         ON CONFLICT (firebase_uid) DO UPDATE SET email = EXCLUDED.email, updated_at = NOW()
         RETURNING firebase_uid, email, nickname, player_tag, role, theme_key, accent_color,
                   avatar_data, banner_data, banner_color,
                   EXISTS (SELECT 1 FROM creators WHERE firebase_uid = users.firebase_uid AND approved = TRUE) AS is_creator`,
        [identity.uid, identity.email]
    );
    return result.rows[0];
}

app.get('/api/health', async (_req, res, next) => {
    try {
        await pool.query('SELECT 1');
        res.json({ status: 'ok' });
    } catch (error) {
        next(error);
    }
});

app.post('/api/me/presence', requireFirebaseUser, async (req, res, next) => {
    try {
        const result = await pool.query(
            'UPDATE users SET last_seen_at = NOW() WHERE firebase_uid = $1 RETURNING last_seen_at',
            [req.identity.uid]
        );
        if (!result.rowCount) return res.status(404).json({ error: 'No se encontró el perfil de esta cuenta.' });
        res.json({ lastSeenAt: result.rows[0].last_seen_at });
    } catch (error) {
        next(error);
    }
});

app.get('/api/admin/monitoring', requireFirebaseUser, requireAdmin, async (_req, res, next) => {
    try {
        const cpu = cpuSnapshot();
        let cpuUsagePercent = null;
        if (previousCpuSample) {
            const previousTotal = Object.values(previousCpuSample).reduce((sum, value) => sum + value, 0);
            const currentTotal = Object.values(cpu).reduce((sum, value) => sum + value, 0);
            const totalDelta = currentTotal - previousTotal;
            if (totalDelta > 0) cpuUsagePercent = Math.round(((totalDelta - (cpu.idle - previousCpuSample.idle)) / totalDelta) * 1000) / 10;
        }
        previousCpuSample = cpu;
        const [database, users, presence] = await Promise.all([
            (async () => {
                const start = performance.now();
                await pool.query('SELECT 1');
                return Math.round((performance.now() - start) * 100) / 100;
            })(),
            pool.query(
                `SELECT firebase_uid AS id, email, nickname, player_tag, role, last_seen_at,
                        COALESCE(last_seen_at > NOW() - INTERVAL '90 seconds', FALSE) AS online,
                        EXISTS (SELECT 1 FROM creators c WHERE c.firebase_uid = users.firebase_uid AND c.approved = TRUE) AS is_creator
                 FROM users ORDER BY last_seen_at DESC NULLS LAST, created_at DESC LIMIT 500`
            ),
            pool.query(
                `SELECT COUNT(*)::int AS total_count,
                        COUNT(*) FILTER (WHERE last_seen_at > NOW() - INTERVAL '90 seconds')::int AS online_count
                 FROM users`
            )
        ]);
        const totalCount = presence.rows[0].total_count;
        const usersOnline = presence.rows[0].online_count;
        res.json({
            server: {
                hostname: os.hostname(),
                platform: process.platform,
                nodeVersion: process.version,
                processUptimeSeconds: Math.round(process.uptime()),
                systemUptimeSeconds: Math.round(os.uptime()),
                cpuCount: os.cpus().length,
                cpuUsagePercent,
                loadAverage: process.platform === 'win32' ? null : os.loadavg().map(value => Math.round(value * 100) / 100),
                totalMemoryBytes: os.totalmem(),
                freeMemoryBytes: os.freemem(),
                processMemoryBytes: process.memoryUsage(),
                databaseResponseMs: database
            },
            users: users.rows,
            totalCount,
            onlineCount: usersOnline,
            offlineCount: totalCount - usersOnline
        });
    } catch (error) {
        next(error);
    }
});

const stateKeys = new Set(['events', 'proposals', 'bugs', 'creator-applications', 'public-settings']);
const userSubmissionKeys = new Set(['proposals', 'bugs']);

async function readAppState(keys = [...stateKeys]) {
    const result = await pool.query(
        'SELECT state_key, value FROM app_state WHERE state_key = ANY($1::text[])',
        [keys]
    );
    return Object.fromEntries(result.rows.map(row => [row.state_key, row.value]));
}

app.get('/api/public/state', async (_req, res, next) => {
    try {
        const state = await readAppState(['events', 'public-settings']);
        res.json({
            events: state.events || [],
            publicSettings: state['public-settings'] || {}
        });
    } catch (error) {
        next(error);
    }
});

app.get('/api/admin/state', requireFirebaseUser, requireAdmin, async (_req, res, next) => {
    try {
        res.json({ state: await readAppState() });
    } catch (error) {
        next(error);
    }
});

app.put('/api/admin/state/:key', requireFirebaseUser, requireAdmin, async (req, res, next) => {
    const { key } = req.params;
    const { value } = req.body || {};
    if (!stateKeys.has(key) || !value || typeof value !== 'object') {
        return res.status(400).json({ error: 'El estado solicitado no es válido.' });
    }
    if ((key === 'events' || key === 'proposals' || key === 'bugs' || key === 'creator-applications')
        && !Array.isArray(value)) {
        return res.status(400).json({ error: 'El contenido debe ser una lista.' });
    }
    if (key === 'public-settings' && (Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype)) {
        return res.status(400).json({ error: 'La configuración pública debe ser un objeto.' });
    }
    try {
        const result = await pool.query(
            `INSERT INTO app_state (state_key, value) VALUES ($1, $2::jsonb)
             ON CONFLICT (state_key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
             RETURNING value`,
            [key, JSON.stringify(value)]
        );
        res.json({ value: result.rows[0].value });
    } catch (error) {
        next(error);
    }
});

app.post('/api/public/state/:key', requireFirebaseUser, async (req, res, next) => {
    const { key } = req.params;
    if (!userSubmissionKeys.has(key)) return res.status(404).json({ error: 'No se encontró la ruta solicitada.' });
    const submission = req.body || {};
    if (key === 'proposals'
        && (typeof submission.nombre !== 'string' || !submission.nombre.trim() || submission.nombre.trim().length > 80
            || typeof submission.tipo !== 'string' || submission.tipo.length > 80
            || typeof submission.detalles !== 'string' || !submission.detalles.trim() || submission.detalles.length > 1000)) {
        return res.status(400).json({ error: 'Completa el nombre, formato y detalles de la propuesta.' });
    }
    if (key === 'bugs'
        && (typeof submission.origen !== 'string' || submission.origen.length > 80
            || typeof submission.descripcion !== 'string' || !submission.descripcion.trim() || submission.descripcion.length > 2000
            || typeof submission.contacto !== 'string' || !submission.contacto.trim() || submission.contacto.length > 100)) {
        return res.status(400).json({ error: 'Completa la categoría, descripción y contacto del reporte.' });
    }
    if (key === 'creator-applications'
        && (typeof submission.usuario !== 'string' || !/^[a-z0-9._]{2,40}$/i.test(submission.usuario))) {
        return res.status(400).json({ error: 'La cuenta del creador no es válida.' });
    }
    try {
        const value = {
            ...submission,
            reportadoPor: req.identity.name || req.identity.email,
            firebaseUid: req.identity.uid,
            submittedAt: new Date().toISOString()
        };
        await pool.query(
            `INSERT INTO app_state (state_key, value) VALUES ($1, jsonb_build_array($2::jsonb))
             ON CONFLICT (state_key) DO UPDATE SET value = app_state.value || EXCLUDED.value, updated_at = NOW()`,
            [key, JSON.stringify(value)]
        );
        res.status(201).json({ status: 'saved' });
    } catch (error) {
        next(error);
    }
});

app.post('/api/creator-applications', requireFirebaseUser, async (req, res, next) => {
    const handle = typeof req.body?.handle === 'string'
        ? req.body.handle.replace(/^@/, '').trim().toLowerCase() : '';
    if (!/^[a-z0-9._]{2,40}$/.test(handle)) {
        return res.status(400).json({ error: 'La cuenta de creador debe tener entre 2 y 40 letras, números, puntos o guiones bajos.' });
    }
    try {
        const applicant = await pool.query(
            `INSERT INTO creator_applications (applicant_uid, social_handle, display_name)
             SELECT firebase_uid, $2, LEFT(COALESCE(NULLIF(nickname, ''), email), 80)
             FROM users WHERE firebase_uid = $1
             RETURNING id, social_handle AS "socialHandle", display_name AS "displayName",
                       status, submitted_at AS "submittedAt"`,
            [req.identity.uid, handle]
        );
        if (!applicant.rowCount) return res.status(404).json({ error: 'Completa primero tu perfil de usuario.' });
        res.status(201).json({ application: applicant.rows[0] });
    } catch (error) {
        if (error.code === '23505') return res.status(409).json({ error: 'Ya tienes una postulación pendiente.' });
        next(error);
    }
});

app.get('/api/admin/creator-applications', requireFirebaseUser, requireAdmin, async (_req, res, next) => {
    try {
        const result = await pool.query(
            `SELECT a.id, a.applicant_uid AS "applicantId", a.social_handle AS "socialHandle",
                    a.display_name AS "displayName", a.status, a.submitted_at AS "submittedAt",
                    u.email, u.nickname
             FROM creator_applications a
             JOIN users u ON u.firebase_uid = a.applicant_uid
             WHERE a.status = 'pending'
             ORDER BY a.submitted_at ASC LIMIT 500`
        );
        res.json({ applications: result.rows });
    } catch (error) {
        next(error);
    }
});

app.post('/api/admin/creator-applications/:id/review', requireFirebaseUser, requireAdmin, async (req, res, next) => {
    if (!/^\d+$/.test(req.params.id) || !['approved', 'rejected'].includes(req.body?.decision)) {
        return res.status(400).json({ error: 'La decisión de postulación no es válida.' });
    }
    let client;
    let transactionStarted = false;
    try {
        client = await pool.connect();
        await client.query('BEGIN');
        transactionStarted = true;
        const application = await client.query(
            `SELECT a.applicant_uid, a.social_handle, a.display_name, u.email, u.role
             FROM creator_applications a
             JOIN users u ON u.firebase_uid = a.applicant_uid
             WHERE a.id = $1 AND a.status = 'pending'
             FOR UPDATE OF a`,
            [req.params.id]
        );
        if (!application.rowCount) {
            await client.query('ROLLBACK');
            transactionStarted = false;
            return res.status(404).json({ error: 'La postulación ya fue atendida o no existe.' });
        }
        const { applicant_uid: applicantUid, social_handle: handle, display_name: displayName, email, role } = application.rows[0];
        if (req.body.decision === 'approved') {
            if (role === 'admin') {
                await client.query('ROLLBACK');
                transactionStarted = false;
                return res.status(409).json({ error: 'Las cuentas administradoras no se pueden convertir desde una postulación.' });
            }
            const existingByAccount = await client.query(
                'SELECT id FROM creators WHERE firebase_uid = $1 FOR UPDATE',
                [applicantUid]
            );
            if (existingByAccount.rowCount) {
                await client.query(
                    `UPDATE creators SET handle = $1, display_name = $2, category = 'Creador de contenido',
                     profile_url = $3, approved = TRUE WHERE firebase_uid = $4`,
                    [handle, displayName, `https://www.tiktok.com/@${encodeURIComponent(handle)}`, applicantUid]
                );
            } else {
                const existingByHandle = await client.query(
                    'SELECT firebase_uid FROM creators WHERE handle = $1 FOR UPDATE',
                    [handle]
                );
                if (existingByHandle.rowCount && existingByHandle.rows[0].firebase_uid
                    && existingByHandle.rows[0].firebase_uid !== applicantUid) {
                    await client.query('ROLLBACK');
                    transactionStarted = false;
                    return res.status(409).json({ error: 'Ese nombre de cuenta ya está vinculado a otro creador.' });
                }
                if (existingByHandle.rowCount) {
                    await client.query(
                        `UPDATE creators SET display_name = $1, category = 'Creador de contenido',
                         profile_url = $2, approved = TRUE, firebase_uid = $3 WHERE handle = $4`,
                        [displayName, `https://www.tiktok.com/@${encodeURIComponent(handle)}`, applicantUid, handle]
                    );
                } else {
                    await client.query(
                        `INSERT INTO creators (handle, display_name, category, profile_url, approved, created_by, firebase_uid)
                         VALUES ($1, $2, 'Creador de contenido', $3, TRUE, $4, $5)`,
                        [handle, displayName, `https://www.tiktok.com/@${encodeURIComponent(handle)}`,
                            req.identity.uid, applicantUid]
                    );
                }
            }
            await client.query("UPDATE users SET role = 'creator', updated_at = NOW() WHERE firebase_uid = $1", [applicantUid]);
        }
        await client.query(
            `UPDATE creator_applications SET status = $1, reviewed_at = NOW(), reviewed_by = $2 WHERE id = $3`,
            [req.body.decision, req.identity.uid, req.params.id]
        );
        await client.query('COMMIT');
        transactionStarted = false;
        res.json({ status: req.body.decision, email });
    } catch (error) {
        if (client && transactionStarted) await client.query('ROLLBACK');
        if (error.code === '23505') return res.status(409).json({ error: 'La cuenta o el nombre de creador ya están vinculados.' });
        next(error);
    } finally {
        client?.release();
    }
});

app.post('/api/public/events/:id/registrations', requireFirebaseUser, async (req, res, next) => {
    const { nombre, logo, jugadores } = req.body || {};
    if (typeof nombre !== 'string' || !nombre.trim() || nombre.trim().length > 40
        || !Array.isArray(jugadores) || jugadores.length < 3 || jugadores.length > 4
        || jugadores.some(player => !player || typeof player.nickname !== 'string' || !player.nickname.trim()
            || typeof player.tag !== 'string' || !/^#[0-9A-Z]{3,10}$/i.test(player.tag))) {
        return res.status(400).json({ error: 'Los datos de inscripción o los Player Tags no son válidos.' });
    }
    if (logo != null && logo !== '' && (typeof logo !== 'string' || !/^data:image\/(?:png|jpeg|webp);base64,/.test(logo)
        || Buffer.byteLength(logo, 'utf8') > 420_000)) {
        return res.status(400).json({ error: 'El escudo no es válido o supera el límite permitido.' });
    }
    let client;
    let transactionStarted = false;
    try {
        client = await pool.connect();
        await client.query('BEGIN');
        transactionStarted = true;
        const result = await client.query(
            'SELECT value FROM app_state WHERE state_key = $1 FOR UPDATE',
            ['events']
        );
        const events = result.rows[0]?.value || [];
        const event = events.find(item => String(item.id) === req.params.id);
        if (!event) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'No se encontró el torneo.' });
        }
        const teams = event.equipos || [];
        if (event.estado !== 'INSCRIPCIONES ABIERTAS' || teams.length >= Number(event.limite)) {
            await client.query('ROLLBACK');
            return res.status(409).json({ error: 'Las inscripciones están cerradas o el torneo está lleno.' });
        }
        if (teams.some(team => team.nombre?.toLocaleLowerCase() === nombre.trim().toLocaleLowerCase())) {
            await client.query('ROLLBACK');
            return res.status(409).json({ error: 'Ese nombre de club ya está en uso.' });
        }
        const [captain, second, third, substitute] = jugadores;
        event.equipos = [...teams, {
            nombre: nombre.trim(),
            logo: logo || '',
            j1: captain.nickname.trim(),
            id1: captain.tag.toUpperCase(),
            j2: second.nickname.trim(),
            id2: second.tag.toUpperCase(),
            j3: third.nickname.trim(),
            id3: third.tag.toUpperCase(),
            j4: substitute?.nickname?.trim() || '',
            id4: substitute?.tag?.toUpperCase() || '',
            puntos: 0
        }];
        await client.query(
            `UPDATE app_state SET value = $1::jsonb, updated_at = NOW() WHERE state_key = $2`,
            [JSON.stringify(events), 'events']
        );
        await client.query('COMMIT');
        transactionStarted = false;
        res.status(201).json({ event });
    } catch (error) {
        if (client && transactionStarted) await client.query('ROLLBACK');
        next(error);
    } finally {
        client?.release();
    }
});

app.get('/api/me', requireFirebaseUser, async (req, res, next) => {
    try {
        const user = await upsertUser(req.identity);
        res.json({ profile: profileFromRow(user) });
    } catch (error) {
        next(error);
    }
});

app.put('/api/me', requireFirebaseUser, async (req, res, next) => {
    const { nickname, tag, theme, accentColor, avatar, banner, bannerColor } = req.body || {};
    const safeBannerColor = bannerColor ?? null;
    const themeKeys = new Set(['red', 'ocean', 'forest', 'violet', 'rose', 'gold', 'cyber', 'arctic', 'sunset', 'mono']);
    if (typeof nickname !== 'string' || nickname.trim().length < 2 || nickname.trim().length > 20) {
        return res.status(400).json({ error: 'El nickname debe tener entre 2 y 20 caracteres.' });
    }
    if (typeof tag !== 'string' || !/^#[0-9A-Z]{3,10}$/.test(tag.trim().toUpperCase())) {
        return res.status(400).json({ error: 'El Player Tag debe tener el formato #ABC123.' });
    }
    if (typeof theme !== 'string' || !themeKeys.has(theme)) return res.status(400).json({ error: 'El tema seleccionado no es válido.' });
    if (typeof accentColor !== 'string' || !/^#[0-9A-F]{6}$/i.test(accentColor)) return res.status(400).json({ error: 'El color personalizado no es válido.' });
    if (safeBannerColor !== null && (typeof safeBannerColor !== 'string' || !/^#[0-9A-F]{6}$/i.test(safeBannerColor))) {
        return res.status(400).json({ error: 'El color del banner no es válido.' });
    }
    const validateImage = (value, limit, field) => {
        if (typeof value !== 'string' || (value && !new RegExp(`^data:image\\/(?:jpeg|png|webp);base64,[A-Za-z0-9+/]+={0,2}$`).test(value))) {
            throw Object.assign(new Error(`La imagen de ${field} debe ser JPEG, PNG o WebP.`), { status: 400 });
        }
        if (value.length > limit) {
            throw Object.assign(new Error(`La imagen de ${field} supera el tamaño permitido.`), { status: 413 });
        }
        return value;
    };
    try {
        const safeAvatar = typeof avatar === 'undefined' ? null : validateImage(avatar, 420_000, 'perfil');
        const safeBanner = typeof banner === 'undefined' ? null : validateImage(banner, 960_000, 'banner');
        const result = await pool.query(
            `INSERT INTO users (firebase_uid, email, nickname, player_tag, theme_key, accent_color, avatar_data, banner_data, banner_color)
             VALUES ($1, $2, $3, $4, $5, $6, COALESCE($7, ''), COALESCE($8, ''), COALESCE($9, '#1c1917'))
             ON CONFLICT (firebase_uid) DO UPDATE SET email = EXCLUDED.email, nickname = EXCLUDED.nickname,
                 player_tag = EXCLUDED.player_tag, theme_key = EXCLUDED.theme_key,
                 accent_color = EXCLUDED.accent_color, avatar_data = COALESCE($7, users.avatar_data),
                 banner_data = COALESCE($8, users.banner_data), banner_color = COALESCE($9, users.banner_color), updated_at = NOW()
             RETURNING firebase_uid, email, nickname, player_tag, role, theme_key, accent_color,
                       avatar_data, banner_data, banner_color,
                       EXISTS (SELECT 1 FROM creators WHERE firebase_uid = users.firebase_uid AND approved = TRUE) AS is_creator`,
            [req.identity.uid, req.identity.email, nickname.trim(), tag.trim().toUpperCase(), theme, accentColor.toLowerCase(),
                safeAvatar, safeBanner, safeBannerColor?.toLowerCase() ?? null]
        );
        res.json({ profile: profileFromRow(result.rows[0]) });
    } catch (error) {
        next(error);
    }
});

app.get('/api/community/users', requireFirebaseUser, async (req, res, next) => {
    const search = typeof req.query.search === 'string' ? req.query.search.trim().slice(0, 40) : '';
    if (search.length < 2) return res.status(400).json({ error: 'Escribe al menos 2 caracteres para buscar.' });
    try {
        const result = await pool.query(
            `SELECT firebase_uid AS id, nickname, player_tag, avatar_data AS avatar
             FROM users
             WHERE firebase_uid <> $1 AND nickname <> '' AND nickname ILIKE $2
             ORDER BY nickname LIMIT 20`,
            [req.identity.uid, `%${search}%`]
        );
        res.json({ users: result.rows });
    } catch (error) {
        next(error);
    }
});

app.get('/api/friends', requireFirebaseUser, async (req, res, next) => {
    try {
        const [friends, requests] = await Promise.all([
            pool.query(
                `SELECT u.firebase_uid AS id, u.nickname, u.player_tag, u.avatar_data AS avatar,
                        (SELECT COUNT(*)::int FROM direct_messages m
                         WHERE m.sender_uid = u.firebase_uid AND m.recipient_uid = $1 AND m.read_at IS NULL) AS "unreadCount"
                 FROM friend_requests f
                 JOIN users u ON u.firebase_uid = CASE WHEN f.requester_uid = $1 THEN f.recipient_uid ELSE f.requester_uid END
                 WHERE (f.requester_uid = $1 OR f.recipient_uid = $1) AND f.status = 'accepted'
                 ORDER BY u.nickname`,
                [req.identity.uid]
            ),
            pool.query(
                `SELECT f.id, f.status, f.requester_uid = $1 AS outgoing,
                        u.firebase_uid AS user_id, u.nickname, u.player_tag, u.avatar_data AS avatar
                 FROM friend_requests f
                 JOIN users u ON u.firebase_uid = CASE WHEN f.requester_uid = $1 THEN f.recipient_uid ELSE f.requester_uid END
                 WHERE (f.requester_uid = $1 OR f.recipient_uid = $1) AND f.status = 'pending'
                 ORDER BY f.created_at DESC`,
                [req.identity.uid]
            )
        ]);
        res.json({ friends: friends.rows, requests: requests.rows });
    } catch (error) {
        next(error);
    }
});

app.post('/api/friends/requests', requireFirebaseUser, async (req, res, next) => {
    const targetId = typeof req.body?.userId === 'string' ? req.body.userId : '';
    if (!/^[A-Za-z0-9_-]{5,128}$/.test(targetId) || targetId === req.identity.uid) {
        return res.status(400).json({ error: 'La cuenta seleccionada no es válida.' });
    }
    let client;
    let transactionStarted = false;
    try {
        client = await pool.connect();
        await client.query('BEGIN');
        transactionStarted = true;
        await client.query(
            'SELECT pg_advisory_xact_lock(hashtext(LEAST($1, $2)), hashtext(GREATEST($1, $2)))',
            [req.identity.uid, targetId]
        );
        const target = await client.query(
            'SELECT firebase_uid FROM users WHERE firebase_uid = $1 AND nickname <> \'\'',
            [targetId]
        );
        if (!target.rowCount) {
            await client.query('ROLLBACK');
            transactionStarted = false;
            return res.status(404).json({ error: 'No se encontró ese perfil.' });
        }
        const existing = await client.query(
            `SELECT id, status, requester_uid, recipient_uid FROM friend_requests
             WHERE LEAST(requester_uid, recipient_uid) = LEAST($1, $2)
               AND GREATEST(requester_uid, recipient_uid) = GREATEST($1, $2)
             FOR UPDATE`,
            [req.identity.uid, targetId]
        );
        if (existing.rowCount && existing.rows[0].status !== 'rejected') {
            await client.query('ROLLBACK');
            transactionStarted = false;
            const message = existing.rows[0].status === 'accepted'
                ? 'Ya son amigos.'
                : existing.rows[0].requester_uid === req.identity.uid
                    ? 'Ya enviaste una solicitud a este usuario.'
                    : 'Este usuario ya te envió una solicitud; acéptala desde tus solicitudes recibidas.';
            return res.status(409).json({ error: message });
        }
        if (existing.rowCount) {
            await client.query(
                `UPDATE friend_requests SET requester_uid = $1, recipient_uid = $2,
                 status = 'pending', created_at = NOW(), updated_at = NOW() WHERE id = $3`,
                [req.identity.uid, targetId, existing.rows[0].id]
            );
        } else {
            await client.query(
                'INSERT INTO friend_requests (requester_uid, recipient_uid) VALUES ($1, $2)',
                [req.identity.uid, targetId]
            );
        }
        await client.query('COMMIT');
        transactionStarted = false;
        res.status(201).json({ status: 'pending' });
    } catch (error) {
        if (client && transactionStarted) await client.query('ROLLBACK');
        next(error);
    } finally {
        client?.release();
    }
});

app.post('/api/friends/requests/:id/respond', requireFirebaseUser, async (req, res, next) => {
    if (!/^\d+$/.test(req.params.id) || !['accepted', 'rejected'].includes(req.body?.status)) {
        return res.status(400).json({ error: 'La respuesta a la solicitud no es válida.' });
    }
    try {
        const result = await pool.query(
            `UPDATE friend_requests SET status = $1, updated_at = NOW()
             WHERE id = $2 AND recipient_uid = $3 AND status = 'pending'
             RETURNING id`,
            [req.body.status, req.params.id, req.identity.uid]
        );
        if (!result.rowCount) return res.status(404).json({ error: 'La solicitud ya no está disponible.' });
        res.json({ status: req.body.status });
    } catch (error) {
        next(error);
    }
});

app.get('/api/friends/:userId/messages', requireFirebaseUser, async (req, res, next) => {
    const otherId = req.params.userId;
    try {
        const friendship = await pool.query(
            `SELECT 1 FROM friend_requests WHERE status = 'accepted'
             AND LEAST(requester_uid, recipient_uid) = LEAST($1, $2)
             AND GREATEST(requester_uid, recipient_uid) = GREATEST($1, $2)`,
            [req.identity.uid, otherId]
        );
        if (!friendship.rowCount) return res.status(403).json({ error: 'El chat solo está disponible entre amigos.' });
        await pool.query(
            `UPDATE direct_messages SET read_at = NOW()
             WHERE sender_uid = $2 AND recipient_uid = $1 AND read_at IS NULL`,
            [req.identity.uid, otherId]
        );
        const result = await pool.query(
            `SELECT m.id, m.sender_uid AS "senderId", m.recipient_uid AS "recipientId",
                    m.message, m.created_at AS "createdAt", m.read_at AS "readAt"
             FROM direct_messages m
             WHERE (m.sender_uid = $1 AND m.recipient_uid = $2 OR m.sender_uid = $2 AND m.recipient_uid = $1)
             ORDER BY m.created_at DESC LIMIT 100`,
            [req.identity.uid, otherId]
        );
        res.json({ messages: result.rows.reverse() });
    } catch (error) {
        next(error);
    }
});

app.post('/api/friends/:userId/messages', requireFirebaseUser, async (req, res, next) => {
    const otherId = req.params.userId;
    const message = typeof req.body?.message === 'string' ? req.body.message.trim() : '';
    if (!/^[A-Za-z0-9_-]{5,128}$/.test(otherId) || otherId === req.identity.uid
        || !message || message.length > 1000) {
        return res.status(400).json({ error: 'El mensaje debe tener entre 1 y 1000 caracteres.' });
    }
    try {
        const result = await pool.query(
            `INSERT INTO direct_messages (sender_uid, recipient_uid, message)
             SELECT $1, $2, $3
             WHERE EXISTS (
                 SELECT 1 FROM friend_requests f
                 WHERE f.status = 'accepted'
                   AND LEAST(f.requester_uid, f.recipient_uid) = LEAST($1, $2)
                   AND GREATEST(f.requester_uid, f.recipient_uid) = GREATEST($1, $2)
             )
             RETURNING id, sender_uid AS "senderId", recipient_uid AS "recipientId",
                       message, created_at AS "createdAt"`,
            [req.identity.uid, otherId, message]
        );
        if (!result.rowCount) return res.status(403).json({ error: 'El chat solo está disponible entre amigos.' });
        res.status(201).json({ message: result.rows[0] });
    } catch (error) {
        next(error);
    }
});

app.get('/api/admin/users', requireFirebaseUser, requireAdmin, async (_req, res, next) => {
    try {
        const result = await pool.query(
            `SELECT firebase_uid AS id, email, nickname, player_tag, role, theme_key, last_seen_at,
                    COALESCE(last_seen_at > NOW() - INTERVAL '90 seconds', FALSE) AS online,
                    EXISTS (SELECT 1 FROM creators c WHERE c.firebase_uid = users.firebase_uid AND c.approved = TRUE) AS is_creator
             FROM users ORDER BY last_seen_at DESC NULLS LAST, created_at DESC LIMIT 500`
        );
        res.json({ users: result.rows });
    } catch (error) {
        next(error);
    }
});

app.patch('/api/admin/users/:id/role', requireFirebaseUser, requireAdmin, async (req, res, next) => {
    const userId = req.params.id;
    const { role } = req.body || {};
    if (!/^[A-Za-z0-9_-]{5,128}$/.test(userId) || !['player', 'creator'].includes(role)) {
        return res.status(400).json({ error: 'La cuenta o el rol seleccionado no son válidos.' });
    }
    if (userId === req.identity.uid) {
        return res.status(400).json({ error: 'No puedes cambiar tu propio rol de administrador.' });
    }
    let client;
    let transactionStarted = false;
    try {
        client = await pool.connect();
        await client.query('BEGIN');
        transactionStarted = true;
        const user = await client.query(
            'SELECT firebase_uid, email, nickname, role FROM users WHERE firebase_uid = $1 FOR UPDATE',
            [userId]
        );
        if (!user.rowCount) {
            await client.query('ROLLBACK');
            transactionStarted = false;
            return res.status(404).json({ error: 'No se encontró esa cuenta.' });
        }
        if (user.rows[0].role === 'admin') {
            await client.query('ROLLBACK');
            transactionStarted = false;
            return res.status(400).json({ error: 'No se puede cambiar el rol de otra cuenta administradora desde este panel.' });
        }
        if (role === 'creator') {
            const linked = await client.query('SELECT id FROM creators WHERE firebase_uid = $1 FOR UPDATE', [userId]);
            if (linked.rowCount) {
                await client.query(
                    `UPDATE creators SET approved = TRUE, category = 'Creador de contenido'
                     WHERE firebase_uid = $1`,
                    [userId]
                );
            } else {
                const handle = `cw_${createHash('sha256').update(userId).digest('hex').slice(0, 16)}`;
                const displayName = user.rows[0].nickname || user.rows[0].email.split('@')[0];
                await client.query(
                    `INSERT INTO creators (handle, display_name, category, profile_url, approved, created_by, firebase_uid)
                     VALUES ($1, $2, 'Creador de contenido', $3, TRUE, $4, $5)`,
                    [handle, displayName, `https://www.tiktok.com/@${handle}`, req.identity.uid, userId]
                );
            }
        } else {
            await client.query(
                `UPDATE creators SET approved = FALSE, is_live = FALSE
                 WHERE firebase_uid = $1`,
                [userId]
            );
        }
        const updated = await client.query(
            'UPDATE users SET role = $1, updated_at = NOW() WHERE firebase_uid = $2 RETURNING role',
            [role, userId]
        );
        await client.query('COMMIT');
        transactionStarted = false;
        res.json({ user: { id: userId, role: updated.rows[0].role } });
    } catch (error) {
        if (client && transactionStarted) await client.query('ROLLBACK');
        if (error.code === '23505') return res.status(409).json({ error: 'No se pudo crear el perfil de creador porque el identificador ya está ocupado.' });
        next(error);
    } finally {
        client?.release();
    }
});

app.get('/api/announcements', async (_req, res, next) => {
    try {
        const result = await pool.query(
            'SELECT id, title, message, created_at FROM announcements WHERE active = TRUE ORDER BY created_at DESC LIMIT 50'
        );
        res.json({ announcements: result.rows });
    } catch (error) {
        next(error);
    }
});

app.get('/api/admin/announcements', requireFirebaseUser, requireAdmin, async (_req, res, next) => {
    try {
        const result = await pool.query(
            'SELECT id, title, message, active, created_at FROM announcements ORDER BY created_at DESC LIMIT 100'
        );
        res.json({ announcements: result.rows });
    } catch (error) {
        next(error);
    }
});

app.post('/api/admin/announcements', requireFirebaseUser, requireAdmin, async (req, res, next) => {
    const { title, message } = req.body || {};
    if (typeof title !== 'string' || !title.trim() || title.trim().length > 80
        || typeof message !== 'string' || !message.trim() || message.trim().length > 500) {
        return res.status(400).json({ error: 'El título (máx. 80) y mensaje (máx. 500) son obligatorios.' });
    }
    try {
        const result = await pool.query(
            'INSERT INTO announcements (title, message, created_by) VALUES ($1, $2, $3) RETURNING id, title, message, created_at',
            [title.trim(), message.trim(), req.identity.uid]
        );
        res.status(201).json({ announcement: result.rows[0] });
    } catch (error) {
        next(error);
    }
});

app.delete('/api/admin/announcements/:id', requireFirebaseUser, requireAdmin, async (req, res, next) => {
    if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ error: 'El identificador del aviso no es válido.' });
    try {
        const result = await pool.query('DELETE FROM announcements WHERE id = $1 RETURNING id', [req.params.id]);
        if (!result.rowCount) return res.status(404).json({ error: 'No se encontró el aviso.' });
        res.status(204).end();
    } catch (error) {
        next(error);
    }
});

app.get('/api/creators', async (_req, res, next) => {
    try {
        const result = await pool.query(
            `SELECT id, handle, display_name, category, profile_url, live_url, is_live,
                    bio, social_links, featured
             FROM creators WHERE approved = TRUE ORDER BY is_live DESC, created_at DESC LIMIT 100`
        );
        res.json({ creators: result.rows });
    } catch (error) {
        next(error);
    }
});

app.get('/api/admin/creators', requireFirebaseUser, requireAdmin, async (_req, res, next) => {
    try {
        const result = await pool.query(
            `SELECT id, handle, display_name, category, profile_url, live_url, is_live,
                    bio, social_links, featured, firebase_uid
             FROM creators WHERE approved = TRUE ORDER BY featured DESC, display_name LIMIT 100`
        );
        res.json({ creators: result.rows });
    } catch (error) {
        next(error);
    }
});

app.get('/api/creators/featured', async (_req, res, next) => {
    try {
        const result = await pool.query(
            `SELECT id, handle, display_name, category, profile_url, bio, social_links
             FROM creators WHERE approved = TRUE AND featured = TRUE ORDER BY display_name LIMIT 50`
        );
        res.json({ collaborators: result.rows });
    } catch (error) {
        next(error);
    }
});

app.put('/api/admin/creators/:id/profile', requireFirebaseUser, requireAdmin, async (req, res, next) => {
    if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ error: 'El identificador del creador no es válido.' });
    const { bio, socialLinks, featured, userId } = req.body || {};
    if (typeof bio !== 'string' || bio.length > 500 || typeof featured !== 'boolean') {
        return res.status(400).json({ error: 'La biografía o el estado de destacado no son válidos.' });
    }
    const allowedNetworks = new Set(['instagram', 'tiktok', 'youtube', 'twitch', 'discord', 'x']);
    if (!socialLinks || typeof socialLinks !== 'object' || Array.isArray(socialLinks)
        || Object.keys(socialLinks).some(network => !allowedNetworks.has(network))
        || Object.values(socialLinks).some(url => typeof url !== 'string' || (url && !isHttpUrl(url)))) {
        return res.status(400).json({ error: 'Revisa los enlaces de redes sociales; deben ser URLs HTTP o HTTPS.' });
    }
    if (typeof userId !== 'undefined' && userId !== null && typeof userId !== 'string') {
        return res.status(400).json({ error: 'La cuenta vinculada no es válida.' });
    }
    try {
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            if (userId) {
                const linkedUser = await client.query('SELECT role FROM users WHERE firebase_uid = $1', [userId]);
                if (!linkedUser.rowCount || linkedUser.rows[0].role === 'admin') {
                    await client.query('ROLLBACK');
                    return res.status(400).json({ error: 'Selecciona una cuenta de usuario válida que no sea administradora.' });
                }
            }
            const current = await client.query('SELECT firebase_uid FROM creators WHERE id = $1 FOR UPDATE', [req.params.id]);
            if (!current.rowCount) {
                await client.query('ROLLBACK');
                return res.status(404).json({ error: 'No se encontró ese creador.' });
            }
            if (current.rows[0].firebase_uid && current.rows[0].firebase_uid !== userId) {
                await client.query(
                    `UPDATE users SET role = 'player', updated_at = NOW()
                     WHERE firebase_uid = $1 AND role = 'creator'`,
                    [current.rows[0].firebase_uid]
                );
            }
            const result = await client.query(
            `UPDATE creators SET bio = $1, social_links = $2::jsonb, featured = $3, firebase_uid = $4
             WHERE id = $5 RETURNING id, bio, social_links, featured, firebase_uid`,
            [bio.trim(), JSON.stringify(socialLinks), featured, userId || null, req.params.id]
            );
            if (userId) {
                await client.query(
                    `UPDATE creators SET approved = TRUE WHERE firebase_uid = $1`,
                    [userId]
                );
                await client.query(
                    `UPDATE users SET role = 'creator', updated_at = NOW()
                     WHERE firebase_uid = $1 AND role <> 'admin'`,
                    [userId]
                );
            }
            await client.query('COMMIT');
            res.json({ creator: result.rows[0] });
        } catch (error) {
            await client.query('ROLLBACK');
            throw error;
        } finally {
            client.release();
        }
    } catch (error) {
        if (error.code === '23505') return res.status(409).json({ error: 'Esa cuenta ya está vinculada a otro creador.' });
        next(error);
    }
});

app.post('/api/admin/creators', requireFirebaseUser, requireAdmin, async (req, res, next) => {
    const { handle, displayName, category, liveUrl, isLive } = req.body || {};
    const normalizedHandle = typeof handle === 'string' ? handle.replace(/^@/, '').trim().toLowerCase() : '';
    if (!/^[a-z0-9._]{2,40}$/.test(normalizedHandle)) return res.status(400).json({ error: 'El usuario del creador no es válido.' });
    if (typeof displayName !== 'string' || !displayName.trim() || displayName.trim().length > 80) {
        return res.status(400).json({ error: 'El nombre debe tener entre 1 y 80 caracteres.' });
    }
    const safeLiveUrl = liveUrl == null || liveUrl === '' ? null : liveUrl;
    if (safeLiveUrl !== null && !isHttpUrl(safeLiveUrl)) return res.status(400).json({ error: 'El enlace del directo debe ser una URL HTTP o HTTPS válida.' });
    if (typeof isLive !== 'undefined' && typeof isLive !== 'boolean') return res.status(400).json({ error: 'El estado del directo no es válido.' });
    if (isLive && !safeLiveUrl) return res.status(400).json({ error: 'Agrega el enlace del directo antes de marcarlo en vivo.' });
    const safeCategory = typeof category === 'string' && category.trim() ? category.trim().slice(0, 40) : 'Creador Oficial';
    try {
        const result = await pool.query(
            `INSERT INTO creators (handle, display_name, category, profile_url, live_url, is_live, created_by)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             RETURNING id, handle, display_name, category, profile_url, live_url, is_live`,
            [normalizedHandle, displayName.trim(), safeCategory, `https://www.tiktok.com/@${encodeURIComponent(normalizedHandle)}`,
                safeLiveUrl, isLive === true, req.identity.uid]
        );
        res.status(201).json({ creator: result.rows[0] });
    } catch (error) {
        if (error.code === '23505') return res.status(409).json({ error: 'Ese creador ya está registrado.' });
        next(error);
    }
});

app.patch('/api/admin/creators/:id/live', requireFirebaseUser, requireAdmin, async (req, res, next) => {
    const { isLive, liveUrl } = req.body || {};
    if (!/^\d+$/.test(req.params.id) || typeof isLive !== 'boolean') {
        return res.status(400).json({ error: 'El estado del directo no es válido.' });
    }
    if (typeof liveUrl !== 'undefined' && liveUrl !== null && typeof liveUrl !== 'string') {
        return res.status(400).json({ error: 'El enlace del directo no es válido.' });
    }
    const safeLiveUrl = typeof liveUrl === 'string' && liveUrl.trim() ? liveUrl.trim() : null;
    if (safeLiveUrl && !isHttpUrl(safeLiveUrl)) {
        return res.status(400).json({ error: 'El enlace del directo debe ser una URL HTTP o HTTPS válida.' });
    }
    try {
        const result = await pool.query(
            `UPDATE creators SET is_live = $1, live_url = COALESCE($2, live_url)
             WHERE id = $3 AND (COALESCE($2, live_url) IS NOT NULL OR $1 = FALSE)
             RETURNING id, is_live, live_url`,
            [isLive, safeLiveUrl, req.params.id]
        );
        if (!result.rowCount) return res.status(409).json({ error: 'Agrega un enlace de live antes de activarlo o revisa el creador.' });
        res.json({ creator: result.rows[0] });
    } catch (error) {
        next(error);
    }
});

app.get('/api/creator/stream', requireFirebaseUser, async (req, res, next) => {
    if (!muxConfigured()) return res.status(503).json({ error: 'Mux no está configurado. Contacta al administrador.' });
    try {
        const creator = await pool.query(
            `SELECT c.id AS creator_id, c.display_name, s.mux_live_stream_id, s.stream_key_encrypted,
                    s.playback_id, s.title, s.status
             FROM creators c LEFT JOIN creator_streams s ON s.creator_uid = c.firebase_uid
             WHERE c.firebase_uid = $1 AND c.approved = TRUE`,
            [req.identity.uid]
        );
        if (!creator.rowCount) return res.status(403).json({ error: 'Tu cuenta aún no tiene acceso al panel de retransmisión.' });
        const row = creator.rows[0];
        const assets = await pool.query(
            `SELECT mux_asset_id AS id, title, playback_id AS "playbackId", status,
                    duration_seconds AS "durationSeconds", created_at AS "createdAt"
             FROM stream_assets WHERE creator_uid = $1 ORDER BY created_at DESC LIMIT 50`,
            [req.identity.uid]
        );
        res.json({
            stream: row.mux_live_stream_id ? {
                id: row.mux_live_stream_id,
                streamKey: decryptStreamKey(row.stream_key_encrypted),
                playbackId: row.playback_id,
                title: row.title,
                status: row.status,
                ingestUrl: 'rtmp://global-live.mux.com:5222/app'
            } : null,
            assets: assets.rows,
            muxConfigured: muxConfigured()
        });
    } catch (error) {
        next(error);
    }
});

app.post('/api/creator/stream', requireFirebaseUser, async (req, res, next) => {
    const title = typeof req.body?.title === 'string' && req.body.title.trim()
        ? req.body.title.trim().slice(0, 120) : 'Cyber Win en vivo';
    try {
        const creator = await pool.query(
            `SELECT c.id, c.display_name FROM creators c
             WHERE c.firebase_uid = $1 AND c.approved = TRUE`,
            [req.identity.uid]
        );
        if (!creator.rowCount) return res.status(403).json({ error: 'Tu cuenta aún no tiene acceso al panel de retransmisión.' });
        const existing = await pool.query(
            `SELECT mux_live_stream_id, stream_key_encrypted, playback_id, title, status
             FROM creator_streams WHERE creator_uid = $1`,
            [req.identity.uid]
        );
        if (existing.rowCount) {
            const row = existing.rows[0];
            return res.json({
                stream: {
                    id: row.mux_live_stream_id, streamKey: decryptStreamKey(row.stream_key_encrypted),
                    playbackId: row.playback_id, title: row.title, status: row.status,
                    ingestUrl: 'rtmp://global-live.mux.com:5222/app'
                }
            });
        }
        const response = await muxRequest('/live-streams', {
            method: 'POST',
            body: JSON.stringify({
                playback_policies: ['public'],
                latency_mode: 'low',
                reconnect_window: 60,
                meta: { title },
                new_asset_settings: { playback_policies: ['public'], meta: { title } }
            })
        });
        const muxStream = response.data;
        const playbackId = muxStream.playback_ids?.find(item => item.policy === 'public')?.id;
        if (!muxStream.id || !muxStream.stream_key || !playbackId) {
            throw new Error('Mux no devolvió una clave RTMP o un identificador de reproducción válido.');
        }
        await pool.query(
            `INSERT INTO creator_streams
                (creator_uid, creator_id, mux_live_stream_id, stream_key_encrypted, playback_id, title, status)
             VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [req.identity.uid, creator.rows[0].id, muxStream.id, encryptStreamKey(muxStream.stream_key),
                playbackId, title, muxStream.status || 'idle']
        );
        res.status(201).json({
            stream: {
                id: muxStream.id, streamKey: muxStream.stream_key, playbackId,
                title, status: muxStream.status || 'idle', ingestUrl: 'rtmp://global-live.mux.com:5222/app'
            }
        });
    } catch (error) {
        if (error.code === '23505') {
            return res.status(409).json({ error: 'Ya existe un canal de streaming vinculado a esta cuenta; vuelve a cargar el panel.' });
        }
        next(error);
    }
});

app.post('/api/creator/stream/reset-key', requireFirebaseUser, async (req, res, next) => {
    try {
        const current = await pool.query(
            `SELECT mux_live_stream_id FROM creator_streams WHERE creator_uid = $1`,
            [req.identity.uid]
        );
        if (!current.rowCount) return res.status(404).json({ error: 'Primero crea tu canal de streaming.' });
        const result = await muxRequest(`/live-streams/${encodeURIComponent(current.rows[0].mux_live_stream_id)}/reset-stream-key`, {
            method: 'POST',
            body: JSON.stringify({})
        });
        await pool.query(
            `UPDATE creator_streams SET stream_key_encrypted = $1, status = $2, updated_at = NOW()
             WHERE creator_uid = $3`,
            [encryptStreamKey(result.data.stream_key), result.data.status || 'idle', req.identity.uid]
        );
        res.json({ streamKey: result.data.stream_key, status: result.data.status || 'idle' });
    } catch (error) {
        next(error);
    }
});

app.get('/api/creator/stream/assets', requireFirebaseUser, async (req, res, next) => {
    try {
        const result = await pool.query(
            `SELECT mux_asset_id AS id, title, playback_id AS "playbackId", status,
                    duration_seconds AS "durationSeconds", created_at AS "createdAt"
             FROM stream_assets WHERE creator_uid = $1 ORDER BY created_at DESC LIMIT 50`,
            [req.identity.uid]
        );
        const creator = await pool.query('SELECT 1 FROM creators WHERE firebase_uid = $1 AND approved = TRUE', [req.identity.uid]);
        if (!creator.rowCount) return res.status(403).json({ error: 'Tu cuenta aún no tiene acceso al panel de retransmisión.' });
        res.json({ assets: result.rows });
    } catch (error) {
        next(error);
    }
});

app.get('/api/streams/live', async (_req, res, next) => {
    try {
        const result = await pool.query(
            `SELECT u.nickname AS creator, c.display_name AS "displayName", s.title,
                    s.playback_id AS "playbackId", s.updated_at AS "startedAt"
             FROM creator_streams s
             JOIN users u ON u.firebase_uid = s.creator_uid
             JOIN creators c ON c.firebase_uid = s.creator_uid
             WHERE s.status = 'active' AND c.approved = TRUE
             ORDER BY s.updated_at DESC LIMIT 20`
        );
        res.json({ streams: result.rows });
    } catch (error) {
        next(error);
    }
});

app.get('/api/streams/videos', async (_req, res, next) => {
    try {
        const result = await pool.query(
            `SELECT mux_asset_id AS id, creator_nickname AS creator, title,
                    playback_id AS "playbackId", duration_seconds AS "durationSeconds", created_at AS "createdAt"
             FROM stream_assets WHERE status = 'ready' AND playback_id IS NOT NULL
             ORDER BY created_at DESC LIMIT 50`
        );
        res.json({ videos: result.rows });
    } catch (error) {
        next(error);
    }
});

app.get('/api/admin/stream-assets', requireFirebaseUser, requireAdmin, async (_req, res, next) => {
    try {
        const result = await pool.query(
            `SELECT mux_asset_id AS id, creator_nickname AS creator, title, status,
                    playback_id AS "playbackId", duration_seconds AS "durationSeconds", created_at AS "createdAt"
             FROM stream_assets ORDER BY created_at DESC LIMIT 200`
        );
        res.json({ videos: result.rows });
    } catch (error) {
        next(error);
    }
});

app.delete('/api/admin/stream-assets/:id', requireFirebaseUser, requireAdmin, async (req, res, next) => {
    const assetId = req.params.id;
    if (!/^[A-Za-z0-9_-]{5,128}$/.test(assetId)) return res.status(400).json({ error: 'El identificador del vídeo no es válido.' });
    try {
        const asset = await pool.query('SELECT mux_asset_id FROM stream_assets WHERE mux_asset_id = $1', [assetId]);
        if (!asset.rowCount) return res.status(404).json({ error: 'No se encontró esa grabación.' });
        await muxRequest(`/assets/${encodeURIComponent(assetId)}`, { method: 'DELETE' });
        await pool.query('DELETE FROM stream_assets WHERE mux_asset_id = $1', [assetId]);
        res.status(204).end();
    } catch (error) {
        next(error);
    }
});

app.delete('/api/admin/creators/:id', requireFirebaseUser, requireAdmin, async (req, res, next) => {
    if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ error: 'El identificador del creador no es válido.' });
    try {
        const result = await pool.query('DELETE FROM creators WHERE id = $1 RETURNING id', [req.params.id]);
        if (!result.rowCount) return res.status(404).json({ error: 'No se encontró el creador.' });
        res.status(204).end();
    } catch (error) {
        next(error);
    }
});

function isHttpUrl(value) {
    if (typeof value !== 'string') return false;
    try {
        const url = new URL(value);
        return url.protocol === 'https:' || url.protocol === 'http:';
    } catch {
        return false;
    }
}

app.get('/', (_req, res) => res.sendFile(path.join(root, 'UserGG6.0.HTML')));
app.get('/admin', (_req, res) => res.sendFile(path.join(root, 'AdminGG6.0.html')));
const publicAssets = new Set([
    '/UserGG6.0.HTML',
    '/AdminGG6.0.html',
    '/firebase-config.js',
    '/firebase-auth.js',
    '/fondo-brawl.png'
]);
app.use((req, res, next) => {
    if (!publicAssets.has(req.path)) return next();
    express.static(root, { index: false, dotfiles: 'deny' })(req, res, next);
});
app.use((_req, res) => res.status(404).json({ error: 'No se encontró la ruta solicitada.' }));
app.use((error, _req, res, _next) => {
    console.error('Request failed:', error);
    if (res.headersSent) return;
    res.status(error.status || 500).json({ error: error.status ? error.message : 'Ocurrió un error en el servidor.' });
});

const server = app.listen(port, () => console.log(`Cyber Win available at http://localhost:${port}`));

async function shutdown() {
    server.close();
    await pool.end();
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
