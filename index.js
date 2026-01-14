// Mock Users API: TTL for create + update (PUT/PATCH) + temporary delete + AccessToken + Swagger
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const swaggerUi = require('swagger-ui-express');
const swaggerJSDoc = require('swagger-jsdoc');

const app = express();
const PORT = process.env.PORT || 3000;
const REQUIRED_API_KEY = process.env.API_KEY || null; // optional for /users
const STRICT_PARAMS = (() => {
  const raw = String(process.env.STRICT_PARAMS || '').trim().toLowerCase();
  return ['true', '1', 'yes', 'y'].includes(raw);
})();

const TTL_MINUTES = Number(process.env.TTL_MINUTES || 10);
const TTL_MS = TTL_MINUTES * 60 * 1000;

app.use(cors());
app.use(express.json());

// ---- Base users ----
const baseUsers = [
  { id: 1, name: 'Milind', role: 'Engineer' },
  { id: 2, name: 'Sunita', role: 'QA' },
  { id: 3, name: 'Seha', role: 'Designer' },
  { id: 4, name: 'Omansh', role: 'DevOps' },
  { id: 5, name: 'Ritesh', role: 'Product Manager' },
  { id: 6, name: 'Namrata', role: 'Backend Engineer' },
  { id: 7, name: 'Harshika', role: 'Frontend Engineer' },
  { id: 8, name: 'Nityam', role: 'QA' },
  { id: 9, name: 'Mahesh', role: 'UX Designer' },
  { id: 10, name: 'Garvita', role: 'Engineer' },
  { id: 11, name: 'Ishaan', role: 'Delivery Manager' },
  { id: 12, name: 'Riddhi', role: 'Program Manager' }
];

// ---- Temporary create + override + delete stores ----
const tempUsers = new Map(); // id -> {id,name,role,expiresAt}
const tempOverrides = new Map(); // id -> {id,name?,role?,deleted?,expiresAt}

// ---- Access Token store (in-memory; does not affect existing APIs) ----
const ACCESS_TOKEN_TTL_MINUTES = Number(process.env.ACCESS_TOKEN_TTL_MINUTES || 30);
const ACCESS_TOKEN_TTL_MS = ACCESS_TOKEN_TTL_MINUTES * 60 * 1000;
const accessTokens = new Map(); // token -> { token, createdAt, expiresAt }

const now = () => Date.now();

function pruneExpired() {
  const t = now();
  for (const [id, u] of tempUsers.entries()) {
    if (u.expiresAt <= t) tempUsers.delete(id);
  }
  for (const [id, o] of tempOverrides.entries()) {
    if (o.expiresAt <= t) tempOverrides.delete(id);
  }
}

function pruneExpiredAccessTokens() {
  const t = now();
  for (const [token, obj] of accessTokens.entries()) {
    if (obj.expiresAt <= t) accessTokens.delete(token);
  }
}

function generateAccessToken() {
  // 32 bytes -> 64 hex characters
  return crypto.randomBytes(32).toString('hex');
}

function combinedUsers() {
  pruneExpired();

  const overridden = baseUsers.reduce((acc, u) => {
    const o = tempOverrides.get(u.id);
    if (o && o.deleted === true) return acc;

    const out = o
      ? { id: u.id, name: o.name ?? u.name, role: o.role ?? u.role }
      : { ...u };

    acc.push(out);
    return acc;
  }, []);

  const created = Array.from(tempUsers.values()).map(u => ({
    id: u.id,
    name: u.name,
    role: u.role
  }));

  return overridden.concat(created);
}

// ---- Utilities ----
function badRequest(res, message, details) {
  return res.status(400).json({ status: 400, error: 'Bad Request', message, ...(details ? { details } : {}) });
}
function unauthorized(res, message) {
  return res.status(401).json({ status: 401, error: 'Unauthorized', message });
}
function forbidden(res, message) {
  return res.status(403).json({ status: 403, error: 'Forbidden', message });
}
function notFound(res, message) {
  return res.status(404).json({ status: 404, error: 'Not Found', message });
}
function methodNotAllowed(res, allow) {
  res.set('Allow', allow.join(', '));
  return res.status(405).json({ status: 405, error: 'Method Not Allowed', message: `Allowed: ${allow.join(', ')}` });
}
function unsupportedMediaType(res) {
  return res
    .status(415)
    .json({ status: 415, error: 'Unsupported Media Type', message: 'Content-Type must be application/json' });
}
function unprocessable(res, message, details) {
  return res.status(422).json({ status: 422, error: 'Unprocessable Entity', message, ...(details ? { details } : {}) });
}
function tooManyRequests(res, retryAfterSec) {
  res.set('Retry-After', String(retryAfterSec));
  return res
    .status(429)
    .json({ status: 429, error: 'Too Many Requests', message: 'Rate limit exceeded', retryAfterSeconds: retryAfterSec });
}

// ETag helpers (for 304)
const cryptoHash = str => crypto.createHash('md5').update(str).digest('hex');
function computeETag(list) {
  const payload = JSON.stringify(list.map(u => ({ id: u.id, name: u.name, role: u.role })));
  return `W/"${cryptoHash(payload)}"`;
}
function sendWithETag(req, res, list) {
  const etag = computeETag(list);
  const inm = req.headers['if-none-match'];
  if (inm && inm === etag) {
    res.set('ETag', etag);
    return res.status(304).end();
  }
  res.set('ETag', etag);
  return res.status(200).json({ status: 200, count: list.length, data: list });
}

// Auth middlewares
function apiKeyRequired(req, res, next) {
  const key = req.headers['x-api-key'];
  const expected = process.env.API_KEY || 'dev-key-123';
  if (!key || key !== expected) return unauthorized(res, 'Invalid or missing API key');
  next();
}
function apiKeyOptional(req, res, next) {
  if (!REQUIRED_API_KEY) return next();
  const key = req.headers['x-api-key'];
  if (!key || key !== REQUIRED_API_KEY) return unauthorized(res, 'Invalid or missing API key');
  next();
}
function accessTokenRequired(req, res, next) {
  pruneExpiredAccessTokens();

  const auth = req.headers['authorization'] || '';
  const bearerToken = auth.toLowerCase().startsWith('bearer ') ? auth.slice(7).trim() : null;
  const token = bearerToken || req.headers['x-access-token'];

  if (!token || typeof token !== 'string' || token.trim() === '') return unauthorized(res, 'Invalid or missing access token');

  const record = accessTokens.get(token);
  if (!record) return unauthorized(res, 'Invalid or expired access token');

  next();
}

function requireJson(req, res, next) {
  const ct = req.headers['content-type'] || '';
  if (!ct.toLowerCase().includes('application/json')) return unsupportedMediaType(res);
  next();
}

// Validation helpers
function isEmpty(val) {
  return val === undefined || val === null || String(val).trim() === '';
}
function parseLimit(limitStr) {
  if (isEmpty(limitStr)) return { provided: false };
  const num = Number(limitStr);
  if (!Number.isFinite(num) || !Number.isInteger(num) || num <= 0) return { provided: true, value: null };
  return { provided: true, value: num };
}
function parseSort(sortStr) {
  if (isEmpty(sortStr)) return { provided: false };
  const v = String(sortStr).toLowerCase();
  if (v !== 'asc' && v !== 'desc') return { provided: true, value: null };
  return { provided: true, value: v };
}
function parseId(idStr) {
  if (isEmpty(idStr)) return { provided: false };
  const num = Number(idStr);
  if (!Number.isInteger(num) || num <= 0) return { provided: true, value: null };
  return { provided: true, value: num };
}
function validateKnownParams(query, knownKeys, res) {
  if (!STRICT_PARAMS) return true;
  const unknown = Object.keys(query).filter(k => !knownKeys.includes(k));
  if (unknown.length > 0) {
    badRequest(res, 'Unsupported query parameter(s)', { unsupported: unknown });
    return false;
  }
  return true;
}

function nextId() {
  const maxBase = Math.max(...baseUsers.map(u => u.id));
  let maxTemp = 0;
  for (const u of tempUsers.values()) if (u.id > maxTemp) maxTemp = u.id;
  return Math.max(maxBase, maxTemp) + 1;
}
function baseUserById(id) {
  return baseUsers.find(u => u.id === id) || null;
}
function userExistsAnywhere(id) {
  return !!baseUserById(id) || tempUsers.has(id);
}

// ---------------- Swagger ----------------
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Mock Users API',
      version: '1.0.0',
      description: 'Mock API for student validation, testing, and automation'
    },
    servers: [
      { url: 'https://automatedscript-api.onrender.com', description: 'Production' },
      { url: 'http://localhost:3000', description: 'Local' }
    ],
    components: {
      securitySchemes: {
        ApiKeyAuth: { type: 'apiKey', in: 'header', name: 'x-api-key' },
        AccessTokenAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'Token' }
      }
    },
    security: [{ ApiKeyAuth: [] }]
  },
  apis: ['./index.js']
};
const swaggerSpec = swaggerJSDoc(swaggerOptions);

/**
 * @swagger
 * /users:
 *   get:
 *     summary: Get all users
 *     tags: [Users]
 *     parameters:
 *       - in: query
 *         name: limit
 *         schema: { type: integer }
 *       - in: query
 *         name: sort
 *         schema: { type: string, enum: [asc, desc] }
 *     responses:
 *       200: { description: List of users }
 */
app.get('/users', apiKeyOptional, (req, res) => {
  if (!validateKnownParams(req.query, ['limit', 'sort'], res)) return;

  const { limit: limitStr, sort: sortStr } = req.query;
  const limit = parseLimit(limitStr);
  if (limit.provided && limit.value === null) return badRequest(res, 'Query parameter "limit" must be a positive integer');

  const sort = parseSort(sortStr);
  if (sort.provided && sort.value === null) return badRequest(res, 'Query parameter "sort" must be either "asc" or "desc"');

  let list = combinedUsers();
  if (sort.value) list.sort((a, b) => (sort.value === 'asc' ? a.id - b.id : b.id - a.id));
  if (limit.value) list = list.slice(0, limit.value);

  return sendWithETag(req, res, list); // 200 or 304
});

/**
 * @swagger
 * /getUser:
 *   get:
 *     summary: Get users by query parameters
 *     description: Fetch users by id, name, or role (supports partial role search)
 *     tags: [Users]
 *     security: [{ ApiKeyAuth: [] }]
 *     parameters:
 *       - in: query
 *         name: id
 *         schema: { type: integer }
 *       - in: query
 *         name: name
 *         schema: { type: string }
 *       - in: query
 *         name: role
 *         schema: { type: string }
 *     responses:
 *       200: { description: User(s) found }
 *       400: { description: Bad Request }
 *       401: { description: Unauthorized }
 *       404: { description: Not Found }
 */
app.get('/getUser', apiKeyRequired, (req, res) => {
  if (!validateKnownParams(req.query, ['id', 'name', 'role'], res)) return;

  const { id: idStr, name, role } = req.query;
  const id = parseId(idStr);

  let list = combinedUsers();

  if (id.provided) {
    if (id.value === null) return badRequest(res, 'Query parameter "id" must be a positive integer');
    list = list.filter(u => u.id === id.value);
  }

  if (name !== undefined) {
    if (typeof name !== 'string' || name.trim() === '')
      return badRequest(res, 'Query parameter "name" must be a non-empty string');
    list = list.filter(u => u.name.toLowerCase().includes(name.trim().toLowerCase()));
  }

  if (role !== undefined) {
    if (typeof role !== 'string' || role.trim() === '')
      return badRequest(res, 'Query parameter "role" must be a non-empty string');
    list = list.filter(u => u.role.toLowerCase().includes(role.trim().toLowerCase()));
  }

  if (list.length === 0) return notFound(res, 'User not found');

  return res.status(200).json({ status: 200, count: list.length, data: list });
});

/**
 * @swagger
 * /getUser/{id}:
 *   get:
 *     summary: Get user by ID
 *     tags: [Users]
 *     security: [{ ApiKeyAuth: [] }]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer }
 *     responses:
 *       200: { description: User found }
 *       400: { description: Bad Request }
 *       401: { description: Unauthorized }
 *       404: { description: Not Found }
 */
app.get('/getUser/:id', apiKeyRequired, (req, res) => {
  const id = parseId(req.params.id);
  if (id.value === null) return badRequest(res, 'Route parameter "id" must be a positive integer');

  const list = combinedUsers();
  const match = list.find(u => u.id === id.value);
  if (!match) return notFound(res, 'User not found');

  return res.status(200).json({ status: 200, count: 1, data: [match] });
});

// -------------------- Access Token endpoints (existing) --------------------

/**
 * @swagger
 * /accessToken:
 *   get:
 *     summary: Generate access token (mock)
 *     tags: [Security]
 *     responses:
 *       200: { description: Access token generated }
 */
app.get('/accessToken', (req, res) => {
  pruneExpiredAccessTokens();

  const token = generateAccessToken();
  const createdAt = now();
  const expiresAt = createdAt + ACCESS_TOKEN_TTL_MS;

  accessTokens.set(token, { token, createdAt, expiresAt });

  return res.status(200).json({
    status: 200,
    message: 'Access token generated',
    accessToken: token,
    tokenType: 'Bearer',
    ttlMinutes: ACCESS_TOKEN_TTL_MINUTES,
    expiresAt
  });
});

/**
 * @swagger
 * /getUserByAccessToken:
 *   get:
 *     summary: Get users list using access token auth
 *     tags: [Security]
 *     security: [{ AccessTokenAuth: [] }]
 *     responses:
 *       200: { description: List of users }
 *       401: { description: Unauthorized }
 */
app.get('/getUserByAccessToken', accessTokenRequired, (req, res) => {
  const list = combinedUsers();
  return sendWithETag(req, res, list);
});

/**
 * @swagger
 * /createUserByAccessToken:
 *   post:
 *     summary: Create a temporary user (access token auth)
 *     tags: [Security]
 *     security: [{ AccessTokenAuth: [] }]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [name, role]
 *             properties:
 *               id: { type: integer }
 *               name: { type: string }
 *               role: { type: string }
 *     responses:
 *       201: { description: User created (temporary) }
 *       400: { description: Bad Request }
 *       401: { description: Unauthorized }
 *       422: { description: Unprocessable Entity }
 */
app.post('/createUserByAccessToken', requireJson, accessTokenRequired, (req, res) => {
  const { name, role, id } = req.body || {};
  if (isEmpty(name) || typeof name !== 'string')
    return badRequest(res, 'Field "name" is required and must be a non-empty string');
  if (isEmpty(role) || typeof role !== 'string')
    return badRequest(res, 'Field "role" is required and must be a non-empty string');

  let newId;
  if (!isEmpty(id)) {
    const num = Number(id);
    if (!Number.isInteger(num) || num <= 0) return badRequest(res, 'Field "id" must be a positive integer');
    if (userExistsAnywhere(num)) return unprocessable(res, 'Field "id" already exists');
    newId = num;
  } else {
    newId = nextId();
  }

  const expiresAt = now() + TTL_MS;
  const tempUser = { id: newId, name: String(name).trim(), role: String(role).trim(), expiresAt };

  tempUsers.set(newId, tempUser);
  setTimeout(() => {
    tempUsers.delete(newId);
  }, TTL_MS);

  res.set('Location', `/getUser/${newId}`);

  return res.status(201).json({
    status: 201,
    message: 'User created (temporary)',
    data: { id: newId, name: tempUser.name, role: tempUser.role },
    ttlMinutes: TTL_MINUTES,
    expiresAt
  });
});

// ---- PUT/PATCH /updateUser (temporary overrides) ----
function handleUpdateOverride(idNum, body, res) {
  const base = baseUserById(idNum);
  if (!base) return notFound(res, 'Only base users can be updated temporarily');

  const { name, role } = body || {};
  const fieldsProvided = !isEmpty(name) || !isEmpty(role);
  if (!fieldsProvided) return badRequest(res, 'Provide at least one of "name" or "role"');

  if (!isEmpty(name) && typeof name !== 'string') return badRequest(res, 'Field "name" must be a non-empty string');
  if (!isEmpty(role) && typeof role !== 'string') return badRequest(res, 'Field "role" must be a non-empty string');
  if (!isEmpty(name) && String(name).trim() === '') return badRequest(res, 'Field "name" must be a non-empty string');
  if (!isEmpty(role) && String(role).trim() === '') return badRequest(res, 'Field "role" must be a non-empty string');

  const expiresAt = now() + TTL_MS;
  const override = { id: idNum, expiresAt };
  if (!isEmpty(name)) override.name = String(name).trim();
  if (!isEmpty(role)) override.role = String(role).trim();

  tempOverrides.set(idNum, override);
  setTimeout(() => {
    tempOverrides.delete(idNum);
  }, TTL_MS);

  const updated = { id: base.id, name: override.name ?? base.name, role: override.role ?? base.role };
  return res.status(200).json({ status: 200, message: 'User updated temporarily', ttlMinutes: TTL_MINUTES, expiresAt, data: updated });
}

// Existing REST update endpoints
app.put('/updateUser/:id', requireJson, apiKeyRequired, (req, res) => {
  const idNum = Number(req.params.id);
  if (!Number.isInteger(idNum) || idNum <= 0) return badRequest(res, 'Route parameter "id" must be a positive integer');
  return handleUpdateOverride(idNum, req.body, res);
});
app.put('/updateUser', requireJson, apiKeyRequired, (req, res) => {
  const { id } = req.body || {};
  if (isEmpty(id)) return badRequest(res, 'Field "id" is required');
  const idNum = Number(id);
  if (!Number.isInteger(idNum) || idNum <= 0) return badRequest(res, 'Field "id" must be a positive integer');
  return handleUpdateOverride(idNum, req.body, res);
});
app.patch('/updateUser/:id', requireJson, apiKeyRequired, (req, res) => {
  const idNum = Number(req.params.id);
  if (!Number.isInteger(idNum) || idNum <= 0) return badRequest(res, 'Route parameter "id" must be a positive integer');
  return handleUpdateOverride(idNum, req.body, res);
});
app.patch('/updateUser', requireJson, apiKeyRequired, (req, res) => {
  const { id } = req.body || {};
  if (isEmpty(id)) return badRequest(res, 'Field "id" is required');
  const idNum = Number(id);
  if (!Number.isInteger(idNum) || idNum <= 0) return badRequest(res, 'Field "id" must be a positive integer');
  return handleUpdateOverride(idNum, req.body, res);
});

// Existing REST delete endpoints
app.delete('/deleteUser/:id', apiKeyRequired, (req, res) => {
  const idNum = Number(req.params.id);
  if (!Number.isInteger(idNum) || idNum <= 0) return badRequest(res, 'Route parameter "id" must be a positive integer');

  const base = baseUserById(idNum);
  if (!base) return notFound(res, 'Only base users can be temporarily deleted');

  const expiresAt = now() + TTL_MS;
  const override = { id: idNum, deleted: true, expiresAt };

  tempOverrides.set(idNum, override);
  setTimeout(() => {
    tempOverrides.delete(idNum);
  }, TTL_MS);

  return res.status(200).json({ status: 200, message: 'User temporarily deleted', ttlMinutes: TTL_MINUTES, expiresAt, data: { id: idNum } });
});

app.delete('/deleteUser', requireJson, apiKeyRequired, (req, res) => {
  const { id } = req.body || {};
  if (isEmpty(id)) return badRequest(res, 'Field "id" is required');

  const idNum = Number(id);
  if (!Number.isInteger(idNum) || idNum <= 0) return badRequest(res, 'Field "id" must be a positive integer');

  const base = baseUserById(idNum);
  if (!base) return notFound(res, 'Only base users can be temporarily deleted');

  const expiresAt = now() + TTL_MS;
  const override = { id: idNum, deleted: true, expiresAt };

  tempOverrides.set(idNum, override);
  setTimeout(() => {
    tempOverrides.delete(idNum);
  }, TTL_MS);

  return res.status(200).json({ status: 200, message: 'User temporarily deleted', ttlMinutes: TTL_MINUTES, expiresAt, data: { id: idNum } });
});

// Existing permanent DELETE for temp-created users
app.delete('/users/:id', apiKeyRequired, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return badRequest(res, 'Route parameter "id" must be a positive integer');
  if (baseUsers.some(u => u.id === id)) return forbidden(res, 'Cannot delete base users');
  if (!tempUsers.has(id)) return notFound(res, 'User not found or already expired');
  tempUsers.delete(id);
  return res.status(204).end();
});

// Rate-limited demo endpoint
app.get('/users-limited', (req, res, next) => {
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  const WINDOW_MS = 60 * 1000;
  const MAX_REQ = 5;
  const store = (app.rateStore ||= new Map());
  const nowTs = Date.now();
  const rec = store.get(ip) || { count: 0, timestamp: nowTs };

  if (nowTs - rec.timestamp > WINDOW_MS) {
    rec.count = 0;
    rec.timestamp = nowTs;
  }
  rec.count++;
  store.set(ip, rec);

  if (rec.count > MAX_REQ) {
    const retryAfter = Math.ceil((rec.timestamp + WINDOW_MS - nowTs) / 1000);
    return tooManyRequests(res, retryAfter);
  }
  next();
}, (req, res) => {
  const list = combinedUsers();
  return res.status(200).json({ status: 200, count: list.length, data: list });
});

app.get('/simulate-error', (req, res) => {
  return res.status(500).json({ status: 500, error: 'Internal Server Error', message: 'Simulated failure' });
});

app.get('/secure/ping', apiKeyRequired, (req, res) => {
  return res.status(200).json({ status: 200, message: 'Authorized' });
});

// Root
app.get('/', (req, res) => {
  res.json({
    status: 'ok',
    endpoints: [
      'GET /users', 'GET /getUser', 'GET /getUser/:id',
      'GET /accessToken', 'GET /getUserByAccessToken',
      'POST /createUserByAccessToken',
      'POST /createUser', 'PUT/PATCH /updateUser/:id', 'PUT/PATCH /updateUser',
      'DELETE /deleteUser/:id', 'DELETE /deleteUser',
      'DELETE /users/:id (temp only, 204)',
      'GET /users-limited (429 demo)', 'GET /simulate-error (500)', 'GET /secure/ping (401)',
      'POST /graphql (GraphQL)'
    ],
    notes: { ttlMinutes: TTL_MINUTES, strictParams: STRICT_PARAMS, accessTokenTtlMinutes: ACCESS_TOKEN_TTL_MINUTES }
  });
});


// ======================================================================
// ✅ NEW SECTION: GraphQL endpoint (ONLY ADDITION - REST untouched)
// ======================================================================

// GraphQL API Keys & role simulation
const GRAPHQL_ADMIN_KEY = process.env.GRAPHQL_ADMIN_KEY || 'admin-key-123';

// helper: parse GraphQL request body
function parseGraphQLBody(req, res) {
  const body = req.body || {};
  if (!body.query || typeof body.query !== 'string') {
    return { ok: false, response: badRequest(res, 'GraphQL field "query" is required') };
  }
  return { ok: true, query: body.query, variables: body.variables || {} };
}

// helper: return GraphQL error with HTTP status
function graphQLError(res, status, message) {
  return res.status(status).json({
    errors: [
      {
        message,
        extensions: { status }
      }
    ]
  });
}

/**
 * @swagger
 * /graphql:
 *   post:
 *     summary: GraphQL endpoint (Mock Users)
 *     description: |
 *       GraphQL entrypoint for students.
 *       Supports queries: users, user(id), adminUsers, securePing
 *       Supports mutations: createUser(name,role,id?), deleteUser(id)
 *     tags: [GraphQL]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               query:
 *                 type: string
 *                 example: query { users { status count data { id name role } } }
 *               variables:
 *                 type: object
 *     responses:
 *       200: { description: OK }
 *       201: { description: Created (mutation createUser) }
 *       204: { description: No Content (mutation deleteUser when x-no-content=true) }
 *       304: { description: Not Modified (ETag caching) }
 *       400: { description: Bad Request }
 *       401: { description: Unauthorized }
 *       403: { description: Forbidden }
 *       405: { description: Method Not Allowed }
 *       415: { description: Unsupported Media Type }
 *       422: { description: Unprocessable Entity }
 *       429: { description: Too Many Requests }
 *       500: { description: Internal Server Error }
 */
app.get('/graphql', (req, res) => {
  return methodNotAllowed(res, ['POST']);
});

app.post('/graphql', (req, res) => {
  // simulate server error via header (as per Postman collection)
  if ((req.headers['x-simulate-error'] || '').toString().toLowerCase() === 'true') {
    return res.status(500).json({ status: 500, error: 'Internal Server Error', message: 'Simulated GraphQL failure' });
  }

  // 415 for unsupported media type
  const ct = req.headers['content-type'] || '';
  if (!ct.toLowerCase().includes('application/json')) return unsupportedMediaType(res);

  const parsed = parseGraphQLBody(req, res);
  if (!parsed.ok) return;
  const { query, variables } = parsed;

  // naive string matching (enough for student training / Postman collection)
  const q = query.replace(/\s+/g, ' ').trim().toLowerCase();

  // ----------------------------------------------------------
  // Query: users(limit, sort) -> 200 or 304
  // ----------------------------------------------------------
  if (q.includes('users(') || q.includes('query') && q.includes(' users')) {
    const limit = variables.limit;
    const sort = variables.sort;

    let list = combinedUsers();

    if (sort) {
      const s = String(sort).toLowerCase();
      if (s !== 'asc' && s !== 'desc') return graphQLError(res, 400, 'Invalid sort order');
      list.sort((a, b) => (s === 'asc' ? a.id - b.id : b.id - a.id));
    }

    if (limit !== undefined && limit !== null) {
      const n = Number(limit);
      if (!Number.isInteger(n) || n <= 0) return graphQLError(res, 400, 'Limit must be positive integer');
      list = list.slice(0, n);
    }

    // ETag / 304 behavior
    const etag = computeETag(list);
    const inm = req.headers['if-none-match'];
    if (inm && inm === etag) {
      res.set('ETag', etag);
      return res.status(304).end();
    }
    res.set('ETag', etag);

    return res.status(200).json({
      data: {
        users: {
          status: 200,
          count: list.length,
          data: list
        }
      }
    });
  }

  // ----------------------------------------------------------
  // Query: user(id:Int!)
  // ----------------------------------------------------------
  if (q.includes('user(')) {
    // requires API key like other secure endpoints
    const key = req.headers['x-api-key'];
    const expected = process.env.API_KEY || 'dev-key-123';
    if (!key || key !== expected) return graphQLError(res, 401, 'Invalid or missing API key');

    const id = variables.id;
    const idNum = Number(id);
    if (!Number.isInteger(idNum) || idNum <= 0) return graphQLError(res, 400, 'id must be positive integer');

    const list = combinedUsers();
    const match = list.find(u => u.id === idNum);
    if (!match) return graphQLError(res, 404, 'User not found');

    return res.status(200).json({ data: { user: match } });
  }

  // ----------------------------------------------------------
  // Query: adminUsers -> 403 unless ADMIN key
  // ----------------------------------------------------------
  if (q.includes('adminusers')) {
    const key = req.headers['x-api-key'];
    if (!key) return graphQLError(res, 401, 'Missing API key');

    if (key !== GRAPHQL_ADMIN_KEY) return graphQLError(res, 403, 'Forbidden: Admin access required');

    const list = combinedUsers();
    return res.status(200).json({
      data: { adminUsers: { status: 200, count: list.length, data: list } }
    });
  }

  // ----------------------------------------------------------
  // Query: securePing -> rate limit demo + 429
  // ----------------------------------------------------------
  if (q.includes('secureping')) {
    // use same rate-limit logic as /users-limited
    const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    const WINDOW_MS = 60 * 1000;
    const MAX_REQ = 5;
    const store = (app.graphqlRateStore ||= new Map());
    const nowTs = Date.now();
    const rec = store.get(ip) || { count: 0, timestamp: nowTs };

    if (nowTs - rec.timestamp > WINDOW_MS) {
      rec.count = 0;
      rec.timestamp = nowTs;
    }
    rec.count++;
    store.set(ip, rec);

    if (rec.count > MAX_REQ) {
      const retryAfter = Math.ceil((rec.timestamp + WINDOW_MS - nowTs) / 1000);
      res.set('Retry-After', String(retryAfter));
      return res.status(429).json({ status: 429, error: 'Too Many Requests', message: 'GraphQL rate limit exceeded', retryAfterSeconds: retryAfter });
    }

    return res.status(200).json({ data: { securePing: { status: 200, message: 'ok' } } });
  }

  // ----------------------------------------------------------
  // Mutation: createUser (TTL temp create)
  // ----------------------------------------------------------
  if (q.includes('mutation') && q.includes('createuser')) {
    const key = req.headers['x-api-key'];
    const expected = process.env.API_KEY || 'dev-key-123';
    if (!key || key !== expected) return graphQLError(res, 401, 'Invalid or missing API key');

    const { name, role, id } = variables || {};
    if (isEmpty(name) || typeof name !== 'string') return graphQLError(res, 400, 'Field "name" is required and must be a non-empty string');
    if (isEmpty(role) || typeof role !== 'string') return graphQLError(res, 400, 'Field "role" is required and must be a non-empty string');

    let newId;
    if (!isEmpty(id)) {
      const num = Number(id);
      if (!Number.isInteger(num) || num <= 0) return graphQLError(res, 400, 'Field "id" must be a positive integer');
      if (userExistsAnywhere(num)) return graphQLError(res, 422, 'Field "id" already exists');
      newId = num;
    } else {
      newId = nextId();
    }

    const expiresAt = now() + TTL_MS;
    const tempUser = { id: newId, name: String(name).trim(), role: String(role).trim(), expiresAt };
    tempUsers.set(newId, tempUser);
    setTimeout(() => {
      tempUsers.delete(newId);
    }, TTL_MS);

    // Location header (Postman expects)
    res.set('Location', `/getUser/${newId}`);

    return res.status(201).json({
      data: {
        createUser: {
          status: 201,
          message: 'User created (temporary)',
          ttlMinutes: TTL_MINUTES,
          expiresAt,
          data: { id: newId, name: tempUser.name, role: tempUser.role }
        }
      }
    });
  }

  // ----------------------------------------------------------
  // Mutation: deleteUser (temp delete / 204 demo)
  // - if header x-no-content=true => return 204 no body
  // ----------------------------------------------------------
  if (q.includes('mutation') && q.includes('deleteuser')) {
    const key = req.headers['x-api-key'];
    const expected = process.env.API_KEY || 'dev-key-123';
    if (!key || key !== expected) return graphQLError(res, 401, 'Invalid or missing API key');

    const id = variables.id;
    const idNum = Number(id);
    if (!Number.isInteger(idNum) || idNum <= 0) return graphQLError(res, 400, 'id must be positive integer');

    if (baseUsers.some(u => u.id === idNum)) return graphQLError(res, 403, 'Cannot delete base users');
    if (!tempUsers.has(idNum)) return graphQLError(res, 404, 'User not found or expired');

    tempUsers.delete(idNum);

    const noContent = (req.headers['x-no-content'] || '').toString().toLowerCase() === 'true';
    if (noContent) return res.status(204).end();

    return res.status(200).json({
      data: {
        deleteUser: { status: 200, message: 'User deleted' }
      }
    });
  }

  // default: unknown query
  return graphQLError(res, 400, 'Unsupported GraphQL operation');
});

// ======================================================================
// ✅ END GraphQL additions
// ======================================================================


// Global error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  return res.status(500).json({ status: 500, error: 'Internal Server Error', message: err?.message || 'Unexpected error' });
});

// Swagger UI endpoint
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Mock Users API running at http://localhost:${PORT}`);
});
