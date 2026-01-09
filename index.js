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

const now = () => Date.now();
function pruneExpired(){
  const t = now();
  for (const [id,u] of tempUsers.entries()) { if (u.expiresAt <= t) tempUsers.delete(id); }
  for (const [id,o] of tempOverrides.entries()) { if (o.expiresAt <= t) tempOverrides.delete(id); }
}

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

  // --- NEW: name filter ---
  if (name !== undefined) {
    if (typeof name !== 'string' || name.trim() === '')
      return badRequest(res,'Query parameter "name" must be a non-empty string');

    list = list.filter(
      //u => u.name.toLowerCase() === name.trim().toLowerCase()
      u => u.name.toLowerCase().includes(name.trim().toLowerCase())
    );
  }

  // --- NEW: role filter ---
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

app.put('/updateUser/:id', requireJson, apiKeyRequired, (req,res)=>{
  const idNum = Number(req.params.id);
  if (!Number.isInteger(idNum) || idNum<=0) return badRequest(res,'Route parameter "id" must be a positive integer');
  return handleUpdateOverride(idNum, req.body, res);
});

app.put('/updateUser', requireJson, apiKeyRequired, (req,res)=>{
  const { id } = req.body || {};
  if (isEmpty(id)) return badRequest(res,'Field "id" is required');
  const idNum = Number(id);
  if (!Number.isInteger(idNum) || idNum<=0) return badRequest(res,'Field "id" must be a positive integer');
  return handleUpdateOverride(idNum, req.body, res);
});

app.patch('/updateUser/:id', requireJson, apiKeyRequired, (req,res)=>{
  const idNum = Number(req.params.id);
  if (!Number.isInteger(idNum) || idNum<=0) return badRequest(res,'Route parameter "id" must be a positive integer');
  return handleUpdateOverride(idNum, req.body, res);
});

app.patch('/updateUser', requireJson, apiKeyRequired, (req,res)=>{
  const { id } = req.body || {};
  if (isEmpty(id)) return badRequest(res,'Field "id" is required');
  const idNum = Number(id);
  if (!Number.isInteger(idNum) || idNum<=0) return badRequest(res,'Field "id" must be a positive integer');
  return handleUpdateOverride(idNum, req.body, res);
});

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

// ---- Existing permanent DELETE for temp-created users (unchanged) ----
app.delete('/users/:id', apiKeyRequired, (req,res)=>{
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id<=0) return badRequest(res,'Route parameter "id" must be a positive integer');
  if (baseUsers.some(u=>u.id===id)) return forbidden(res,'Cannot delete base users');
  if (!tempUsers.has(id)) return notFound(res,'User not found or already expired');
  tempUsers.delete(id);
  return res.status(204).end();
});

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

app.get('/simulate-error', (req,res)=>{ return res.status(500).json({ status:500, error:'Internal Server Error', message:'Simulated failure' }); });
app.get('/secure/ping', apiKeyRequired, (req,res)=>{ return res.status(200).json({ status:200, message:'Authorized' }); });

// Root
app.get('/', (req,res)=>{
  res.json({
    status:'ok',
    endpoints:[
      'GET /users', 'GET /getUser', 'GET /getUser/:id',
      'POST /createUser', 'PUT/PATCH /updateUser/:id', 'PUT/PATCH /updateUser',
      'DELETE /deleteUser/:id', 'DELETE /deleteUser',
      'DELETE /users/:id (temp only, 204)',
      'GET /users-limited (429 demo)', 'GET /simulate-error (500)', 'GET /secure/ping (401)'
    ],
    notes:{ ttlMinutes: TTL_MINUTES, strictParams: STRICT_PARAMS }
  });
});

// Global error handler
app.use((err, req, res, next)=>{ console.error('Unhandled error:', err); return res.status(500).json({ status:500, error:'Internal Server Error', message: err?.message || 'Unexpected error' }); });

app.listen(PORT, '0.0.0.0', ()=>{ console.log(`Mock Users API (delete TTL ${TTL_MINUTES}m) running at http://localhost:${PORT}`); });
