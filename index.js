// Mock Users API: TTL for create + update (PUT/PATCH) + temporary delete
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
//swagger UI
const swaggerUi = require('swagger-ui-express');
const swaggerJSDoc = require('swagger-jsdoc');
//swagger UI ends
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
  { id: 1, name: 'Milind',  role: 'Engineer' },
  { id: 2, name: 'Sunita', role: 'QA' },
  { id: 3, name: 'Seha',  role: 'Designer' },
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
const tempUsers = new Map();       // id -> {id,name,role,expiresAt}
const tempOverrides = new Map();   // id -> {id,name?,role?,deleted?,expiresAt}

// ---- NEW: Access Token store (in-memory; does not affect existing APIs) ----
const ACCESS_TOKEN_TTL_MINUTES = Number(process.env.ACCESS_TOKEN_TTL_MINUTES || 30);
const ACCESS_TOKEN_TTL_MS = ACCESS_TOKEN_TTL_MINUTES * 60 * 1000;
// token -> { token, createdAt, expiresAt }
const accessTokens = new Map();
// ---- NEW: Access Token ends ----

const now = () => Date.now();
function pruneExpired(){
  const t = now();
  for (const [id,u] of tempUsers.entries()) { if (u.expiresAt <= t) tempUsers.delete(id); }
  for (const [id,o] of tempOverrides.entries()) { if (o.expiresAt <= t) tempOverrides.delete(id); }
}

// ---- NEW: Access Token helpers ----
function pruneExpiredAccessTokens(){
  const t = now();
  for (const [token,obj] of accessTokens.entries()){
    if (obj.expiresAt <= t) accessTokens.delete(token);
  }
}
function generateAccessToken(){
  // 32 bytes -> 64 hex characters (industry-standard length)
  return crypto.randomBytes(32).toString('hex');
}
// ---- NEW: Access Token helpers ends ----

function combinedUsers(){
  pruneExpired();
  // start with base and apply overrides (including temporary delete)
  const overridden = baseUsers.reduce((acc, u) => {
    const o = tempOverrides.get(u.id);
    if (o && o.deleted === true) {
      // temporarily deleted: skip this base user
      return acc;
    }
    // apply name/role override if present
    const out = o ? { id: u.id, name: o.name ?? u.name, role: o.role ?? u.role } : { ...u };
    acc.push(out);
    return acc;
  }, []);
  // append temp-created users
  const created = Array.from(tempUsers.values()).map(u => ({ id: u.id, name: u.name, role: u.role }));
  return overridden.concat(created);
}

// ---- Utilities ----
function badRequest(res, message, details){
  return res.status(400).json({ status: 400, error: 'Bad Request', message, ...(details?{details}:{}) });
}
function unauthorized(res, message){
  return res.status(401).json({ status: 401, error: 'Unauthorized', message });
}
function forbidden(res, message){
  return res.status(403).json({ status: 403, error: 'Forbidden', message });
}
function notFound(res, message){
  return res.status(404).json({ status: 404, error: 'Not Found', message });
}
function methodNotAllowed(res, allow){
  res.set('Allow', allow.join(', '));
  return res.status(405).json({ status: 405, error: 'Method Not Allowed', message: `Allowed: ${allow.join(', ')}`});
}
function unsupportedMediaType(res){
  return res.status(415).json({ status: 415, error: 'Unsupported Media Type', message: 'Content-Type must be application/json' });
}
function unprocessable(res, message, details){
  return res.status(422).json({ status: 422, error: 'Unprocessable Entity', message, ...(details?{details}:{}) });
}
function tooManyRequests(res, retryAfterSec){
  res.set('Retry-After', String(retryAfterSec));
  return res.status(429).json({ status: 429, error: 'Too Many Requests', message: 'Rate limit exceeded', retryAfterSeconds: retryAfterSec });
}

// ETag helpers (for 304)
const cryptoHash = str => crypto.createHash('md5').update(str).digest('hex');
function computeETag(list){
  const payload = JSON.stringify(list.map(u=>({id:u.id,name:u.name,role:u.role})));
  return `W/"${cryptoHash(payload)}"`;
}
function sendWithETag(req,res,list){
  const etag = computeETag(list);
  const inm = req.headers['if-none-match'];
  if (inm && inm === etag){ res.set('ETag', etag); return res.status(304).end(); }
  res.set('ETag', etag);
  return res.status(200).json({ status: 200, count: list.length, data: list });
}

// Auth middlewares
function apiKeyRequired(req,res,next){
  const key = req.headers['x-api-key'];
  const expected = process.env.API_KEY || 'dev-key-123';
  if (!key || key !== expected) return unauthorized(res, 'Invalid or missing API key');
  next();
}
function apiKeyOptional(req,res,next){
  if (!REQUIRED_API_KEY) return next();
  const key = req.headers['x-api-key'];
  if (!key || key !== REQUIRED_API_KEY) return unauthorized(res, 'Invalid or missing API key');
  next();
}

// ---- NEW: Access Token middleware (does not affect existing APIs) ----
function accessTokenRequired(req,res,next){
  pruneExpiredAccessTokens();

  // Support either:
  // 1) Authorization: Bearer <token>
  // 2) x-access-token: <token>
  const auth = req.headers['authorization'] || '';
  const bearerToken = auth.toLowerCase().startsWith('bearer ')
    ? auth.slice(7).trim()
    : null;

  const token = bearerToken || req.headers['x-access-token'];

  if (!token || typeof token !== 'string' || token.trim() === '') {
    return unauthorized(res, 'Invalid or missing access token');
  }

  const record = accessTokens.get(token);
  if (!record) {
    return unauthorized(res, 'Invalid or expired access token');
  }

  next();
}
// ---- NEW: Access Token middleware ends ----

function requireJson(req,res,next){
  const ct = req.headers['content-type']||'';
  if (!ct.toLowerCase().includes('application/json')) return unsupportedMediaType(res);
  next();
}

// Validation helpers
function isEmpty(val){ return val === undefined || val === null || String(val).trim() === ''; }
function parseLimit(limitStr){ if (isEmpty(limitStr)) return { provided:false }; const num = Number(limitStr); if (!Number.isFinite(num)||!Number.isInteger(num)||num<=0) return { provided:true,value:null}; return { provided:true,value:num}; }
function parseSort(sortStr){ if (isEmpty(sortStr)) return { provided:false }; const v = String(sortStr).toLowerCase(); if (v!=='asc'&&v!=='desc') return { provided:true,value:null}; return { provided:true,value:v}; }
function parseId(idStr){ if (isEmpty(idStr)) return { provided:false }; const num = Number(idStr); if (!Number.isInteger(num)||num<=0) return { provided:true,value:null}; return { provided:true,value:num}; }
function validateKnownParams(query, knownKeys, res){ if (!STRICT_PARAMS) return true; const unknown = Object.keys(query).filter(k=>!knownKeys.includes(k)); if (unknown.length>0){ badRequest(res,'Unsupported query parameter(s)',{unsupported:unknown}); return false;} return true; }

function nextId(){ const maxBase = Math.max(...baseUsers.map(u=>u.id)); let maxTemp = 0; for (const u of tempUsers.values()) { if (u.id>maxTemp) maxTemp = u.id; } return Math.max(maxBase, maxTemp)+1; }
function baseUserById(id){ return baseUsers.find(u=>u.id===id) || null; }
function userExistsAnywhere(id){ return !!baseUserById(id) || tempUsers.has(id); }

//swagger UI
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Mock Users API',
      version: '1.0.0',
      description: 'Mock API for student validation, testing, and automation'
    },
    servers: [
      {
        url: 'https://automatedscript-api.onrender.com',
        description: 'Production'
      },
      {
        url: 'http://localhost:3000',
        description: 'Local'
      }
    ],
    components: {
      securitySchemes: {
        ApiKeyAuth: {
          type: 'apiKey',
          in: 'header',
          name: 'x-api-key'
        },
        // NEW: Access token auth schema for Swagger UI
        AccessTokenAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'Token'
        }
      }
    },
    security: [{ ApiKeyAuth: [] }]
  },
  apis: ['./index.js'] // read JSDoc from same file
};

const swaggerSpec = swaggerJSDoc(swaggerOptions);
//Swagger UI Ends

/**
 * @swagger
 * /users:
 *   get:
 *     summary: Get all users
 *     tags:
 *       - Users
 *     parameters:
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *       - in: query
 *         name: sort
 *         schema:
 *           type: string
 *           enum: [asc, desc]
 *     responses:
 *       200:
 *         description: List of users
 */

// ---- GET /users (optional API key) ----
app.get('/users', apiKeyOptional, (req,res)=>{
  if (!validateKnownParams(req.query, ['limit','sort'], res)) return;
  const { limit:limitStr, sort:sortStr } = req.query;
  const limit = parseLimit(limitStr); if (limit.provided && limit.value===null) return badRequest(res,'Query parameter "limit" must be a positive integer');
  const sort = parseSort(sortStr);  if (sort.provided && sort.value===null)   return badRequest(res,'Query parameter "sort" must be either "asc" or "desc"');

  let list = combinedUsers();
  if (sort.value) list.sort((a,b)=> sort.value==='asc' ? a.id-b.id : b.id-a.id);
  if (limit.value) list = list.slice(0, limit.value);
  return sendWithETag(req,res,list); // 200 or 304
});

/**
 * @swagger
 * /getUser:
 *   get:
 *     summary: Get users by query parameters
 *     description: Fetch users by id, name, or role (supports partial role search)
 *     tags:
 *       - Users
 *     parameters:
 *       - in: query
 *         name: id
 *         schema:
 *           type: integer
 *       - in: query
 *         name: name
 *         schema:
 *           type: string
 *       - in: query
 *         name: role
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: User(s) found
 *       400:
 *         description: Bad Request
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: User not found
 */

// ---- GET /getUser (API key required) ----
app.get('/getUser', apiKeyRequired, (req,res)=>{
  // allow id, name, role (STRICT_PARAMS still enforced)
  if (!validateKnownParams(req.query, ['id', 'name', 'role'], res)) return;

  const { id: idStr, name, role } = req.query;
  const id = parseId(idStr);

  let list = combinedUsers();

  // --- existing ID logic (UNCHANGED BEHAVIOR) ---
  if (id.provided) {
    if (id.value === null)
      return badRequest(res,'Query parameter "id" must be a positive integer');

    list = list.filter(u => u.id === id.value);
  }

  // --- name filter (partial search) ---
  if (name !== undefined) {
    if (typeof name !== 'string' || name.trim() === '')
      return badRequest(res,'Query parameter "name" must be a non-empty string');

    list = list.filter(
      u => u.name.toLowerCase().includes(name.trim().toLowerCase())
    );
  }

  // --- role filter (partial search) ---
  if (role !== undefined) {
    if (typeof role !== 'string' || role.trim() === '')
      return badRequest(res,'Query parameter "role" must be a non-empty string');

    list = list.filter(
      u => u.role.toLowerCase().includes(role.trim().toLowerCase())
    );
  }

  if (list.length === 0)
    return notFound(res,'User not found');

  // preserve original response structure
  return res.status(200).json({
    status: 200,
    count: list.length,
    data: list
  });
});

/**
 * @swagger
 * /getUser/{id}:
 *   get:
 *     summary: Get user by ID
 *     tags:
 *       - Users
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: User found
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: User not found
 */

app.get('/getUser/:id', apiKeyRequired, (req,res)=>{
  const id = parseId(req.params.id);
  if (id.value===null) return badRequest(res,'Route parameter "id" must be a positive integer');
  const list = combinedUsers();
  const match = list.find(u=>u.id===id.value);
  if (!match) return notFound(res,'User not found');
  return res.status(200).json({ status:200, count:1, data:[match] });
});

// -------------------- NEW ENDPOINTS (ONLY ADDITIONS) --------------------

/**
 * @swagger
 * /accessToken:
 *   get:
 *     summary: Generate access token (mock)
 *     tags:
 *       - Security
 *     responses:
 *       200:
 *         description: Access token generated
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
 *     tags:
 *       - Security
 *     security:
 *       - AccessTokenAuth: []
 *     responses:
 *       200:
 *         description: List of users
 *       401:
 *         description: Unauthorized
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
 *     tags:
 *       - Security
 *     security:
 *       - AccessTokenAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [name, role]
 *             properties:
 *               id:
 *                 type: integer
 *               name:
 *                 type: string
 *               role:
 *                 type: string
 *     responses:
 *       201:
 *         description: User created (temporary)
 *       400:
 *         description: Bad Request
 *       401:
 *         description: Unauthorized
 *       422:
 *         description: Unprocessable Entity
 */
app.post('/createUserByAccessToken', requireJson, accessTokenRequired, (req,res)=>{
  // SAME validations as /createUser (copied as-is)
  const { name, role, id } = req.body || {};
  if (isEmpty(name) || typeof name!=='string') return badRequest(res,'Field "name" is required and must be a non-empty string');
  if (isEmpty(role) || typeof role!=='string') return badRequest(res,'Field "role" is required and must be a non-empty string');
  let newId;
  if (!isEmpty(id)){
    const num = Number(id);
    if (!Number.isInteger(num) || num<=0) return badRequest(res,'Field "id" must be a positive integer');
    if (userExistsAnywhere(num)) return unprocessable(res,'Field "id" already exists');
    newId = num;
  } else {
    newId = nextId();
  }
  const expiresAt = now()+TTL_MS;
  const tempUser = { id:newId, name:String(name).trim(), role:String(role).trim(), expiresAt };
  tempUsers.set(newId, tempUser);
  setTimeout(()=>{ tempUsers.delete(newId); }, TTL_MS);
  res.set('Location', `/getUser/${newId}`);
  return res.status(201).json({ status:201, message:'User created (temporary)', data:{ id:newId, name:tempUser.name, role:tempUser.role }, ttlMinutes:TTL_MINUTES, expiresAt });
});

/**
 * @swagger
 * /updateUserByAccessToken/{id}:
 *   put:
 *     summary: Update base user temporarily by ID (access token auth)
 *     tags:
 *       - Security
 *     security:
 *       - AccessTokenAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer }
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name: { type: string }
 *               role: { type: string }
 *     responses:
 *       200: { description: User updated temporarily }
 *       400: { description: Bad Request }
 *       401: { description: Unauthorized }
 *       404: { description: Not Found }
 *   patch:
 *     summary: Partially update base user temporarily by ID (access token auth)
 *     tags:
 *       - Security
 *     security:
 *       - AccessTokenAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer }
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name: { type: string }
 *               role: { type: string }
 *     responses:
 *       200: { description: User updated temporarily }
 *       400: { description: Bad Request }
 *       401: { description: Unauthorized }
 *       404: { description: Not Found }
 */

// new token-based update endpoints, using EXACT same validations via handleUpdateOverride
app.put('/updateUserByAccessToken/:id', requireJson, accessTokenRequired, (req,res)=>{
  const idNum = Number(req.params.id);
  if (!Number.isInteger(idNum) || idNum<=0) return badRequest(res,'Route parameter "id" must be a positive integer');
  return handleUpdateOverride(idNum, req.body, res);
});
app.patch('/updateUserByAccessToken/:id', requireJson, accessTokenRequired, (req,res)=>{
  const idNum = Number(req.params.id);
  if (!Number.isInteger(idNum) || idNum<=0) return badRequest(res,'Route parameter "id" must be a positive integer');
  return handleUpdateOverride(idNum, req.body, res);
});

/**
 * @swagger
 * /updateUserByAccessToken:
 *   put:
 *     summary: Update base user temporarily by body ID (access token auth)
 *     tags:
 *       - Security
 *     security:
 *       - AccessTokenAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [id]
 *             properties:
 *               id: { type: integer }
 *               name: { type: string }
 *               role: { type: string }
 *     responses:
 *       200: { description: User updated temporarily }
 *       400: { description: Bad Request }
 *       401: { description: Unauthorized }
 *       404: { description: Not Found }
 *   patch:
 *     summary: Partially update base user temporarily by body ID (access token auth)
 *     tags:
 *       - Security
 *     security:
 *       - AccessTokenAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [id]
 *             properties:
 *               id: { type: integer }
 *               name: { type: string }
 *               role: { type: string }
 *     responses:
 *       200: { description: User updated temporarily }
 *       400: { description: Bad Request }
 *       401: { description: Unauthorized }
 *       404: { description: Not Found }
 */

app.put('/updateUserByAccessToken', requireJson, accessTokenRequired, (req,res)=>{
  const { id } = req.body || {};
  if (isEmpty(id)) return badRequest(res,'Field "id" is required');
  const idNum = Number(id);
  if (!Number.isInteger(idNum) || idNum<=0) return badRequest(res,'Field "id" must be a positive integer');
  return handleUpdateOverride(idNum, req.body, res);
});
app.patch('/updateUserByAccessToken', requireJson, accessTokenRequired, (req,res)=>{
  const { id } = req.body || {};
  if (isEmpty(id)) return badRequest(res,'Field "id" is required');
  const idNum = Number(id);
  if (!Number.isInteger(idNum) || idNum<=0) return badRequest(res,'Field "id" must be a positive integer');
  return handleUpdateOverride(idNum, req.body, res);
});

/**
 * @swagger
 * /deleteUserByAccessToken/{id}:
 *   delete:
 *     summary: Temporarily delete a base user by ID (access token auth)
 *     tags:
 *       - Security
 *     security:
 *       - AccessTokenAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer }
 *     responses:
 *       200: { description: User temporarily deleted }
 *       400: { description: Bad Request }
 *       401: { description: Unauthorized }
 *       404: { description: Not Found }
 */
app.delete('/deleteUserByAccessToken/:id', accessTokenRequired, (req,res)=>{
  // SAME validations + logic as /deleteUser/:id (copied as-is, just auth changed)
  const idNum = Number(req.params.id);
  if (!Number.isInteger(idNum) || idNum<=0) return badRequest(res,'Route parameter "id" must be a positive integer');
  const base = baseUserById(idNum);
  if (!base) return notFound(res,'Only base users can be temporarily deleted');
  const expiresAt = now()+TTL_MS;
  const override = { id:idNum, deleted:true, expiresAt };
  tempOverrides.set(idNum, override);
  setTimeout(()=>{ tempOverrides.delete(idNum); }, TTL_MS);
  return res.status(200).json({ status:200, message:'User temporarily deleted', ttlMinutes:TTL_MINUTES, expiresAt, data:{ id:idNum } });
});

/**
 * @swagger
 * /deleteUserByAccessToken:
 *   delete:
 *     summary: Temporarily delete a base user by body ID (access token auth)
 *     tags:
 *       - Security
 *     security:
 *       - AccessTokenAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [id]
 *             properties:
 *               id: { type: integer }
 *     responses:
 *       200: { description: User temporarily deleted }
 *       400: { description: Bad Request }
 *       401: { description: Unauthorized }
 *       404: { description: Not Found }
 */
app.delete('/deleteUserByAccessToken', requireJson, accessTokenRequired, (req,res)=>{
  // SAME validations + logic as /deleteUser (copied as-is, just auth changed)
  const { id } = req.body || {};
  if (isEmpty(id)) return badRequest(res,'Field "id" is required');
  const idNum = Number(id);
  if (!Number.isInteger(idNum) || idNum<=0) return badRequest(res,'Field "id" must be a positive integer');
  const base = baseUserById(idNum);
  if (!base) return notFound(res,'Only base users can be temporarily deleted');
  const expiresAt = now()+TTL_MS;
  const override = { id:idNum, deleted:true, expiresAt };
  tempOverrides.set(idNum, override);
  setTimeout(()=>{ tempOverrides.delete(idNum); }, TTL_MS);
  return res.status(200).json({ status:200, message:'User temporarily deleted', ttlMinutes:TTL_MINUTES, expiresAt, data:{ id:idNum } });
});

// -------------------- NEW ENDPOINTS END --------------------

/**
 * @swagger
 * /createUser:
 *   post:
 *     summary: Create a temporary user (TTL-based)
 *     description: Creates a user temporarily (stored in memory). The user auto-expires after configured TTL.
 *     tags:
 *       - Users
 *     security:
 *       - ApiKeyAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [name, role]
 *             properties:
 *               id:
 *                 type: integer
 *                 example: 101
 *                 description: Optional. If not provided, API generates next ID.
 *               name:
 *                 type: string
 *                 example: "Rohit"
 *               role:
 *                 type: string
 *                 example: "Engineer"
 *     responses:
 *       201:
 *         description: User created temporarily
 *       400:
 *         description: Bad request / validation error
 *       401:
 *         description: Unauthorized (missing/wrong API key)
 *       415:
 *         description: Unsupported Media Type (Content-Type must be application/json)
 *       422:
 *         description: Unprocessable Entity (ID already exists)
 */

// ---- POST /createUser (API key required) ----
app.post('/createUser', requireJson, apiKeyRequired, (req,res)=>{
  const { name, role, id } = req.body || {};
  if (isEmpty(name) || typeof name!=='string') return badRequest(res,'Field "name" is required and must be a non-empty string');
  if (isEmpty(role) || typeof role!=='string') return badRequest(res,'Field "role" is required and must be a non-empty string');
  let newId;
  if (!isEmpty(id)){
    const num = Number(id);
    if (!Number.isInteger(num) || num<=0) return badRequest(res,'Field "id" must be a positive integer');
    if (userExistsAnywhere(num)) return unprocessable(res,'Field "id" already exists');
    newId = num;
  } else {
    newId = nextId();
  }
  const expiresAt = now()+TTL_MS;
  const tempUser = { id:newId, name:String(name).trim(), role:String(role).trim(), expiresAt };
  tempUsers.set(newId, tempUser);
  setTimeout(()=>{ tempUsers.delete(newId); }, TTL_MS);
  res.set('Location', `/getUser/${newId}`);
  return res.status(201).json({ status:201, message:'User created (temporary)', data:{ id:newId, name:tempUser.name, role:tempUser.role }, ttlMinutes:TTL_MINUTES, expiresAt });
});

// ---- PUT/PATCH /updateUser (temporary overrides) ----
function handleUpdateOverride(idNum, body, res){
  const base = baseUserById(idNum);
  if (!base) return notFound(res,'Only base users can be updated temporarily');
  const { name, role } = body || {};
  const fieldsProvided = (!isEmpty(name)) || (!isEmpty(role));
  if (!fieldsProvided) return badRequest(res,'Provide at least one of "name" or "role"');
  if (!isEmpty(name) && typeof name !== 'string') return badRequest(res,'Field "name" must be a non-empty string');
  if (!isEmpty(role) && typeof role !== 'string') return badRequest(res,'Field "role" must be a non-empty string');
  if (!isEmpty(name) && String(name).trim()==='') return badRequest(res,'Field "name" must be a non-empty string');
  if (!isEmpty(role) && String(role).trim()==='') return badRequest(res,'Field "role" must be a non-empty string');
  const expiresAt = now()+TTL_MS;
  const override = { id:idNum, expiresAt };
  if (!isEmpty(name)) override.name = String(name).trim();
  if (!isEmpty(role)) override.role = String(role).trim();
  tempOverrides.set(idNum, override);
  setTimeout(()=>{ tempOverrides.delete(idNum); }, TTL_MS);
  const updated = { id: base.id, name: override.name ?? base.name, role: override.role ?? base.role };
  return res.status(200).json({ status:200, message:'User updated temporarily', ttlMinutes:TTL_MINUTES, expiresAt, data: updated });
}
/**
 * @swagger
 * /updateUser/{id}:
 *   put:
 *     summary: Update base user temporarily (PUT)
 *     description: Updates base user temporarily (stored as override). Changes auto-expire after TTL.
 *     tags:
 *       - Users
 *     security:
 *       - ApiKeyAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         example: 2
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *                 example: "Rahul Updated"
 *               role:
 *                 type: string
 *                 example: "Senior QA"
 *     responses:
 *       200:
 *         description: User updated temporarily
 *       400:
 *         description: Bad request / validation error
 *       401:
 *         description: Unauthorized (missing/wrong API key)
 *       404:
 *         description: Not Found (Only base users can be updated temporarily)
 *       415:
 *         description: Unsupported Media Type (Content-Type must be application/json)
 *   patch:
 *     summary: Update base user temporarily (PATCH)
 *     description: Partial update of base user temporarily. Changes auto-expire after TTL.
 *     tags:
 *       - Users
 *     security:
 *       - ApiKeyAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         example: 2
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *                 example: "Rahul Patch"
 *               role:
 *                 type: string
 *                 example: "QA Lead"
 *     responses:
 *       200:
 *         description: User updated temporarily
 *       400:
 *         description: Bad request / validation error
 *       401:
 *         description: Unauthorized (missing/wrong API key)
 *       404:
 *         description: Not Found (Only base users can be updated temporarily)
 *       415:
 *         description: Unsupported Media Type (Content-Type must be application/json)
 */

app.put('/updateUser/:id', requireJson, apiKeyRequired, (req,res)=>{
  const idNum = Number(req.params.id);
  if (!Number.isInteger(idNum) || idNum<=0) return badRequest(res,'Route parameter "id" must be a positive integer');
  return handleUpdateOverride(idNum, req.body, res);
});
/**
 * @swagger
 * /updateUser:
 *   put:
 *     summary: Update base user temporarily by request body ID (PUT)
 *     description: Updates base user temporarily using "id" inside request body.
 *     tags:
 *       - Users
 *     security:
 *       - ApiKeyAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [id]
 *             properties:
 *               id:
 *                 type: integer
 *                 example: 3
 *               name:
 *                 type: string
 *                 example: "Neha Updated"
 *               role:
 *                 type: string
 *                 example: "Senior Designer"
 *     responses:
 *       200:
 *         description: User updated temporarily
 *       400:
 *         description: Bad request / validation error
 *       401:
 *         description: Unauthorized (missing/wrong API key)
 *       404:
 *         description: Not Found (Only base users can be updated temporarily)
 *       415:
 *         description: Unsupported Media Type (Content-Type must be application/json)
 *   patch:
 *     summary: Update base user temporarily by request body ID (PATCH)
 *     description: Partial update of base user temporarily using "id" inside request body.
 *     tags:
 *       - Users
 *     security:
 *       - ApiKeyAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [id]
 *             properties:
 *               id:
 *                 type: integer
 *                 example: 3
 *               name:
 *                 type: string
 *                 example: "Neha Patch"
 *               role:
 *                 type: string
 *                 example: "UI/UX Designer"
 *     responses:
 *       200:
 *         description: User updated temporarily
 *       400:
 *         description: Bad request / validation error
 *       401:
 *         description: Unauthorized (missing/wrong API key)
 *       404:
 *         description: Not Found (Only base users can be updated temporarily)
 *       415:
 *         description: Unsupported Media Type (Content-Type must be application/json)
 */

app.put('/updateUser', requireJson, apiKeyRequired, (req,res)=>{
  const { id } = req.body || {};
  if (isEmpty(id)) return badRequest(res,'Field "id" is required');
  const idNum = Number(id);
  if (!Number.isInteger(idNum) || idNum<=0) return badRequest(res,'Field "id" must be a positive integer');
  return handleUpdateOverride(idNum, req.body, res);
});
/**
 * @swagger
 * /updateUser/{id}:
 *   put:
 *     summary: Update base user temporarily (PUT)
 *     description: Updates base user temporarily (stored as override). Changes auto-expire after TTL.
 *     tags:
 *       - Users
 *     security:
 *       - ApiKeyAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         example: 2
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *                 example: "Rahul Updated"
 *               role:
 *                 type: string
 *                 example: "Senior QA"
 *     responses:
 *       200:
 *         description: User updated temporarily
 *       400:
 *         description: Bad request / validation error
 *       401:
 *         description: Unauthorized (missing/wrong API key)
 *       404:
 *         description: Not Found (Only base users can be updated temporarily)
 *       415:
 *         description: Unsupported Media Type (Content-Type must be application/json)
 *   patch:
 *     summary: Update base user temporarily (PATCH)
 *     description: Partial update of base user temporarily. Changes auto-expire after TTL.
 *     tags:
 *       - Users
 *     security:
 *       - ApiKeyAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         example: 2
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *                 example: "Rahul Patch"
 *               role:
 *                 type: string
 *                 example: "QA Lead"
 *     responses:
 *       200:
 *         description: User updated temporarily
 *       400:
 *         description: Bad request / validation error
 *       401:
 *         description: Unauthorized (missing/wrong API key)
 *       404:
 *         description: Not Found (Only base users can be updated temporarily)
 *       415:
 *         description: Unsupported Media Type (Content-Type must be application/json)
 */

app.patch('/updateUser/:id', requireJson, apiKeyRequired, (req,res)=>{
  const idNum = Number(req.params.id);
  if (!Number.isInteger(idNum) || idNum<=0) return badRequest(res,'Route parameter "id" must be a positive integer');
  return handleUpdateOverride(idNum, req.body, res);
});
/**
 * @swagger
 * /updateUser:
 *   put:
 *     summary: Update base user temporarily by request body ID (PUT)
 *     description: Updates base user temporarily using "id" inside request body.
 *     tags:
 *       - Users
 *     security:
 *       - ApiKeyAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [id]
 *             properties:
 *               id:
 *                 type: integer
 *                 example: 3
 *               name:
 *                 type: string
 *                 example: "Neha Updated"
 *               role:
 *                 type: string
 *                 example: "Senior Designer"
 *     responses:
 *       200:
 *         description: User updated temporarily
 *       400:
 *         description: Bad request / validation error
 *       401:
 *         description: Unauthorized (missing/wrong API key)
 *       404:
 *         description: Not Found (Only base users can be updated temporarily)
 *       415:
 *         description: Unsupported Media Type (Content-Type must be application/json)
 *   patch:
 *     summary: Update base user temporarily by request body ID (PATCH)
 *     description: Partial update of base user temporarily using "id" inside request body.
 *     tags:
 *       - Users
 *     security:
 *       - ApiKeyAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [id]
 *             properties:
 *               id:
 *                 type: integer
 *                 example: 3
 *               name:
 *                 type: string
 *                 example: "Neha Patch"
 *               role:
 *                 type: string
 *                 example: "UI/UX Designer"
 *     responses:
 *       200:
 *         description: User updated temporarily
 *       400:
 *         description: Bad request / validation error
 *       401:
 *         description: Unauthorized (missing/wrong API key)
 *       404:
 *         description: Not Found (Only base users can be updated temporarily)
 *       415:
 *         description: Unsupported Media Type (Content-Type must be application/json)
 */

app.patch('/updateUser', requireJson, apiKeyRequired, (req,res)=>{
  const { id } = req.body || {};
  if (isEmpty(id)) return badRequest(res,'Field "id" is required');
  const idNum = Number(id);
  if (!Number.isInteger(idNum) || idNum<=0) return badRequest(res,'Field "id" must be a positive integer');
  return handleUpdateOverride(idNum, req.body, res);
});
/**
 * @swagger
 * /deleteUser/{id}:
 *   delete:
 *     summary: Temporarily delete a base user by ID (TTL-based)
 *     description: Temporarily hides base user for TTL duration using delete override.
 *     tags:
 *       - Users
 *     security:
 *       - ApiKeyAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         example: 4
 *     responses:
 *       200:
 *         description: User temporarily deleted
 *       400:
 *         description: Bad request / validation error
 *       401:
 *         description: Unauthorized (missing/wrong API key)
 *       404:
 *         description: Not Found (Only base users can be temporarily deleted)
 */

// ---- DELETE /deleteUser/:id (temporary delete override) ----
app.delete('/deleteUser/:id', apiKeyRequired, (req,res)=>{
  const idNum = Number(req.params.id);
  if (!Number.isInteger(idNum) || idNum<=0) return badRequest(res,'Route parameter "id" must be a positive integer');
  const base = baseUserById(idNum);
  if (!base) return notFound(res,'Only base users can be temporarily deleted');
  const expiresAt = now()+TTL_MS;
  const override = { id:idNum, deleted:true, expiresAt };
  tempOverrides.set(idNum, override);
  setTimeout(()=>{ tempOverrides.delete(idNum); }, TTL_MS);
  return res.status(200).json({ status:200, message:'User temporarily deleted', ttlMinutes:TTL_MINUTES, expiresAt, data:{ id:idNum } });
});
/**
 * @swagger
 * /deleteUser:
 *   delete:
 *     summary: Temporarily delete a base user by request body ID (TTL-based)
 *     description: Temporarily hides base user for TTL duration using delete override.
 *     tags:
 *       - Users
 *     security:
 *       - ApiKeyAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [id]
 *             properties:
 *               id:
 *                 type: integer
 *                 example: 4
 *     responses:
 *       200:
 *         description: User temporarily deleted
 *       400:
 *         description: Bad request / validation error
 *       401:
 *         description: Unauthorized (missing/wrong API key)
 *       404:
 *         description: Not Found (Only base users can be temporarily deleted)
 *       415:
 *         description: Unsupported Media Type (Content-Type must be application/json)
 */

// ---- DELETE /deleteUser (body includes id) ----
app.delete('/deleteUser', requireJson, apiKeyRequired, (req,res)=>{
  const { id } = req.body || {};
  if (isEmpty(id)) return badRequest(res,'Field "id" is required');
  const idNum = Number(id);
  if (!Number.isInteger(idNum) || idNum<=0) return badRequest(res,'Field "id" must be a positive integer');
  const base = baseUserById(idNum);
  if (!base) return notFound(res,'Only base users can be temporarily deleted');
  const expiresAt = now()+TTL_MS;
  const override = { id:idNum, deleted:true, expiresAt };
  tempOverrides.set(idNum, override);
  setTimeout(()=>{ tempOverrides.delete(idNum); }, TTL_MS);
  return res.status(200).json({ status:200, message:'User temporarily deleted', ttlMinutes:TTL_MINUTES, expiresAt, data:{ id:idNum } });
});
/**
 * @swagger
 * /users/{id}:
 *   delete:
 *     summary: Permanently delete a temporary user
 *     description: Permanently deletes ONLY temporary users created via /createUser. Base users cannot be deleted (403).
 *     tags:
 *       - Users
 *     security:
 *       - ApiKeyAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         example: 101
 *     responses:
 *       204:
 *         description: User permanently deleted
 *       400:
 *         description: Bad request / invalid id
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden (Cannot delete base users)
 *       404:
 *         description: Not Found (User not found or expired)
 */

// ---- Existing permanent DELETE for temp-created users (unchanged) ----
app.delete('/users/:id', apiKeyRequired, (req,res)=>{
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id<=0) return badRequest(res,'Route parameter "id" must be a positive integer');
  if (baseUsers.some(u=>u.id===id)) return forbidden(res,'Cannot delete base users');
  if (!tempUsers.has(id)) return notFound(res,'User not found or already expired');
  tempUsers.delete(id);
  return res.status(204).end();
});
/**
 * @swagger
 * /users-limited:
 *   get:
 *     summary: Rate limited endpoint (429 demo)
 *     description: Demo endpoint to simulate rate limiting. Returns 429 after exceeding threshold.
 *     tags:
 *       - Demos
 *     responses:
 *       200:
 *         description: Users returned
 *       429:
 *         description: Too Many Requests (rate limit exceeded)
 */

// ---- Other demos retained ----
app.get('/users-limited', (req,res,next)=>{
  // simple per-IP rate limit demo
  const ip = (req.headers['x-forwarded-for']||req.socket.remoteAddress||'').split(',')[0].trim();
  const WINDOW_MS = 60*1000; const MAX_REQ = 5;
  const store = (app.rateStore ||= new Map());
  const nowTs = Date.now();
  const rec = store.get(ip) || { count:0, timestamp:nowTs };
  if (nowTs - rec.timestamp > WINDOW_MS){ rec.count=0; rec.timestamp=nowTs; }
  rec.count++; store.set(ip, rec);
  if (rec.count > MAX_REQ){ const retryAfter = Math.ceil((rec.timestamp+WINDOW_MS - nowTs)/1000); return tooManyRequests(res, retryAfter); }
  next();
}, (req,res)=>{
  const list = combinedUsers();
  return res.status(200).json({ status:200, count:list.length, data:list });
});
/**
 * @swagger
 * /simulate-error:
 *   get:
 *     summary: Simulate server error (500 demo)
 *     tags:
 *       - Demos
 *     responses:
 *       500:
 *         description: Internal Server Error (simulated)
 */

app.get('/simulate-error', (req,res)=>{ return res.status(500).json({ status:500, error:'Internal Server Error', message:'Simulated failure' }); });
/**
 * @swagger
 * /secure/ping:
 *   get:
 *     summary: Authorized ping (API key check)
 *     description: Returns 200 only if valid x-api-key is provided.
 *     tags:
 *       - Security
 *     security:
 *       - ApiKeyAuth: []
 *     responses:
 *       200:
 *         description: Authorized
 *       401:
 *         description: Unauthorized
 */

app.get('/secure/ping', apiKeyRequired, (req,res)=>{ return res.status(200).json({ status:200, message:'Authorized' }); });
/**
 * @swagger
 * /:
 *   get:
 *     summary: Root endpoint
 *     description: Lists all available endpoints and notes (TTL, strict params, token TTL, etc.)
 *     tags:
 *       - Meta
 *     responses:
 *       200:
 *         description: API info returned
 */

// Root
app.get('/', (req,res)=>{
  res.json({
    status:'ok',
    endpoints:[
      'GET /users', 'GET /getUser', 'GET /getUser/:id',
      'GET /accessToken', 'GET /getUserByAccessToken',
      'POST /createUserByAccessToken',
      'PUT/PATCH /updateUserByAccessToken/:id', 'PUT/PATCH /updateUserByAccessToken',
      'DELETE /deleteUserByAccessToken/:id', 'DELETE /deleteUserByAccessToken',
      'POST /createUser', 'PUT/PATCH /updateUser/:id', 'PUT/PATCH /updateUser',
      'DELETE /deleteUser/:id', 'DELETE /deleteUser',
      'DELETE /users/:id (temp only, 204)',
      'GET /users-limited (429 demo)', 'GET /simulate-error (500)', 'GET /secure/ping (401)'
    ],
    notes:{ ttlMinutes: TTL_MINUTES, strictParams: STRICT_PARAMS, accessTokenTtlMinutes: ACCESS_TOKEN_TTL_MINUTES }
  });
});

// Global error handler
app.use((err, req, res, next)=>{ console.error('Unhandled error:', err); return res.status(500).json({ status:500, error:'Internal Server Error', message: err?.message || 'Unexpected error' }); });
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

app.listen(PORT, '0.0.0.0', ()=>{ console.log(`Mock Users API (delete TTL ${TTL_MINUTES}m) running at http://localhost:${PORT}`); });
