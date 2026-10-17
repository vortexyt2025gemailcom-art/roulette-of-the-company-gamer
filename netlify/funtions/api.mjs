// ============================================================================
//  Servidor de la Ruleta · Netlify Function en /api
//  Guarda cuentas, monedas y compras en Netlify Blobs (no necesitas base de datos).
//
//  Variable de entorno obligatoria para el "modo dueño":
//    OWNER_KEY  (Netlify → Site configuration → Environment variables), mínimo 6 caracteres
// ============================================================================
import { getStore } from '@netlify/blobs';
import { createHash, randomBytes, randomInt, scrypt as scryptCb, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(scryptCb);

/* ---------- Catálogo: precios de la tienda ----------
   Son los mismos precios que hay en index.html. Si cambias uno allá, cámbialo aquí también.
   Claves: r<n> skin de ruleta · b<n> fondo · d<id> decoración · pc/pd flecha · hc/hd centro */
const WS = [0, 500, 800, 1000, 1200, 1500, 1800, 2000, 2300, 2500, 3000, 3500, 4000, 4500, 5000,
  6000, 7000, 8000, 9000, 6500, 1500, 2000, 3000, 3500, 4000, 5500, 7500, 10000];
const BG = [0, 300, 500, 700, 900, 1100, 1300, 1500, 1800, 2000, 2300, 2600, 3000, 3400, 3800,
  4200, 4600, 5000, 5500, 6000, 800, 1200, 1800, 2200, 2600, 3200, 4000, 4500, 5200, 6000, 7000,
  2400, 2800, 3200, 3600, 4000, 4400];
const DC = {
  rb: 20000, fi: 12000, ne: 12000, or: 15000, ic: 12000, to: 12000, co: 12000, ga: 25000,
  pl: 14000, so: 14000, bn: 16000, ec: 20000, pa: 22000, ho: 18000, au: 26000, la: 28000,
  l1: 9000, l2: 9000, l3: 13000, l4: 13000, l5: 13000, l6: 15000, l7: 16000, l8: 17000,
  l9: 18000, l10: 19000, l11: 21000, l12: 24000,
};
const HIDE = ['cp', 'ck', 'bT', 'bt', 'bS', 'bM', 'bU', 'bE'];

function priceOf(k) {
  if (k === 'rf' || k === 'bv') return 50000; // tu foto de ruleta · tu video de fondo
  let m = /^([rb])(0|[1-9]\d*)$/.exec(k);
  if (m) return (m[1] === 'r' ? WS : BG)[+m[2]];
  m = /^d(\w+)$/.exec(k);
  if (m) return Object.hasOwn(DC, m[1]) ? DC[m[1]] : undefined;
  m = /^[ph]([cd])(0|[1-9]\d*)$/.exec(k); // flecha (p) y centro (h): 20 colores y 20 decoraciones
  if (m && +m[2] < 20) {
    const i = +m[2];
    return m[1] === 'c' ? (i ? 200 + i * 100 : 0) : 800 + i * 400;
  }
}

/* ---------- Utilidades ---------- */
class E extends Error {
  constructor(status, msg) { super(msg); this.status = status; }
}
// El cliente cierra la sesión sola si el mensaje empieza con "Sesión" o "Cuenta bloq"
const SES = () => new E(401, 'Sesión vencida. Entra de nuevo.');

const NAME = /^\w{3,16}$/;
const IMG = /^data:image\/(?:jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/;
const sha = (s) => createHash('sha256').update(String(s)).digest('hex');
const same = (a, b) => { const x = Buffer.from(a), y = Buffer.from(b); return x.length === y.length && timingSafeEqual(x, y); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const env = (k) => globalThis.Netlify?.env?.get(k) ?? process.env[k];
const lc = (n) => String(n ?? '').toLowerCase();
const str = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
const int = (v, lo, hi) => Math.min(hi, Math.max(lo, Math.floor(+v) || 0));
const img = (v, max) => (typeof v === 'string' && v.length <= max && IMG.test(v) ? v : '');
const idx = (v) => (v === '' || v == null ? '' : int(v, 0, 19));
const hashPw = async (pw, salt) => (await scrypt(pw, salt, 32)).toString('hex');
const newKey = () => randomBytes(24).toString('base64url');
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });

const uk = (n) => 'u/' + lc(n); // cuenta + monedas + compras
const dk = (n) => 'd/' + lc(n); // ajustes, lista de la ruleta y foto de ruleta

let S; // almacén de Netlify Blobs (se abre en cada petición)

/* Lee → modifica → guarda solo si nadie lo tocó mientras tanto (si hubo choque, reintenta).
   fn(objeto) modifica el objeto; si devuelve false no se guarda nada. */
async function update(key, fn) {
  for (let i = 0; i < 8; i++) {
    const cur = await S.getWithMetadata(key, { type: 'json' });
    if (!cur) return null;
    if ((await fn(cur.data)) === false) return cur.data;
    const r = await S.setJSON(key, cur.data, { onlyIfMatch: cur.etag });
    if (r.modified) return cur.data;
    await sleep(20 + Math.random() * 60);
  }
  throw new E(503, 'Hay mucho movimiento. Intenta otra vez en un momento.');
}

const chk = (u, k) => { if (typeof k !== 'string' || !u.se.includes(sha(k))) throw SES(); };

async function who(b) { // cuenta + comprobar sesión (solo lectura)
  const n = lc(b.n);
  const u = NAME.test(n) ? await S.get(uk(n), { type: 'json' }) : null;
  if (!u) throw SES();
  chk(u, b.k);
  return u;
}
async function mine(b, fn) { // cuenta + comprobar sesión + modificarla
  const n = lc(b.n);
  if (!NAME.test(n)) throw SES();
  const u = await update(uk(n), (d) => { chk(d, b.k); return fn(d); });
  if (!u) throw SES();
  return u;
}

/* Límite de intentos por conexión (aproximado, suficiente contra abuso básico) */
async function rate(bucket, id, max, secs, add = true) {
  const key = `rl/${bucket}/${sha(id).slice(0, 20)}`, now = Date.now();
  const cur = await S.getWithMetadata(key, { type: 'json' });
  let d = cur?.data;
  if (!d || now - d.w > secs * 1000) d = { w: now, n: 0 };
  if (d.n >= max) throw new E(429, 'Demasiados intentos. Prueba más tarde.');
  if (add) {
    d.n++;
    await S.setJSON(key, d, cur ? { onlyIfMatch: cur.etag } : { onlyIfNew: true }).catch(() => {});
  }
}

async function owner(key, ip) {
  const real = env('OWNER_KEY');
  if (!real || real.length < 6) throw new E(503, 'Falta crear OWNER_KEY en Netlify (mínimo 6 caracteres)');
  await rate('own', ip, 8, 3600, false);
  if (typeof key !== 'string' || !same(sha(key), sha(real))) {
    await rate('own', ip, 8, 3600);
    throw new E(403, 'Código incorrecto');
  }
}

/* Solo se guarda lo que la app necesita, con tipos y tamaños controlados */
function cleanData(d) {
  d = d && typeof d === 'object' ? d : {};
  const ph = img(d.ph, 450000);
  return {
    rs: d.rs === 'f' && ph ? 'f' : int(d.rs, 0, WS.length - 1),
    bg: int(d.bg, 0, BG.length - 1),
    dc: typeof d.dc === 'string' && Object.hasOwn(DC, d.dc) ? d.dc : '',
    ph,
    pc: idx(d.pc), pd: idx(d.pd), hc: idx(d.hc), hd: idx(d.hd),
    keep: !!d.keep,
    rm: !!d.rm,
    hide: Array.isArray(d.hide) ? [...new Set(d.hide.filter((x) => HIDE.includes(x)))] : HIDE,
    sec: int(d.sec, 0, 1e9),
    spins: int(d.spins, 0, 1e9),
    items: (Array.isArray(d.items) ? d.items : []).slice(0, 500)
      .map((i) => ({ id: int(i?.id, 0, 1e9), name: str(i?.name, 40) })),
  };
}
// Monedas y compras las manda siempre el servidor, nunca el celular
const pack = (u, d) => ({ ...d, coins: u.c, own: u.o });
const loadData = async (n) => (await S.get(dk(n), { type: 'json' })) ?? cleanData({});

/* ---------- Acciones (lo que llama la app con fetch('/api')) ---------- */
const ACTIONS = {
  async reg(b, ip) {
    await rate('reg', ip, 15, 3600);
    const n = str(b.n, 16), r = str(b.r, 30), pw = typeof b.pw === 'string' ? b.pw : '';
    if (!NAME.test(n)) throw new E(400, 'Nombre de perfil: 3 a 16 letras, números o _');
    if (!r) throw new E(400, 'Pon tu nombre real');
    if (pw.length < 6 || pw.length > 200) throw new E(400, 'La contraseña necesita entre 6 y 200 caracteres');
    const d = cleanData(b.d), k = newKey(), salt = randomBytes(16).toString('hex');
    const u = {
      n, r, p: img(b.p, 60000), s: salt, h: await hashPw(pw, salt), se: [sha(k)],
      c: 500, o: {}, t: Date.now(), fl: 0, lk: 0, dh: sha(JSON.stringify(d)).slice(0, 16), ct: Date.now(),
    };
    if (!(await S.setJSON(uk(n), u, { onlyIfNew: true })).modified) throw new E(409, 'Ese nombre ya está en uso');
    await S.setJSON(dk(n), d);
    return { n, k, p: u.p, r, d: pack(u, d) };
  },

  async login(b) {
    const n = lc(b.n), pw = typeof b.pw === 'string' ? b.pw.slice(0, 200) : '';
    const bad = new E(401, 'Nombre o contraseña incorrectos');
    const u0 = NAME.test(n) ? await S.get(uk(n), { type: 'json' }) : null;
    if (!u0) { await hashPw(pw, 'relleno'); throw bad; } // tarda igual que con una cuenta real
    const wait = () => Math.ceil((u0.lk - Date.now()) / 60000);
    if (u0.lk > Date.now()) throw new E(429, `Cuenta bloqueada por intentos fallidos. Prueba en ${wait()} min.`);
    const ok = same(await hashPw(pw, u0.s), u0.h), k = newKey();
    const u = await update(uk(n), (d) => {
      if (!ok) { d.fl = (d.fl || 0) + 1; if (d.fl >= 5) { d.fl = 0; d.lk = Date.now() + 10 * 60000; } return; }
      d.fl = 0; d.lk = 0; d.se = [...d.se, sha(k)].slice(-5);
    });
    if (!ok) {
      if (u.lk > Date.now()) throw new E(429, 'Cuenta bloqueada por intentos fallidos. Prueba en 10 min.');
      throw bad;
    }
    return { n: u.n, k, p: u.p, r: u.r, d: pack(u, await loadData(n)) };
  },

  async me(b) {
    const u = await who(b);
    return { p: u.p, d: pack(u, await loadData(b.n)) };
  },

  async save(b) { // sincroniza ajustes y foto de perfil; devuelve las monedas reales
    const u0 = await who(b);
    const d = cleanData(b.d), h = sha(JSON.stringify(d)).slice(0, 16), av = img(b.p, 60000);
    if (u0.dh === h && (!av || av === u0.p)) return { c: u0.c };
    if (u0.dh !== h) await S.setJSON(dk(b.n), d);
    const u = await mine(b, (x) => { x.dh = h; if (av) x.p = av; });
    return { c: u.c };
  },

  async earn(b) { // 50 monedas por minuto como máximo
    let v = 0;
    const u = await mine(b, (d) => {
      v = 0;
      const now = Date.now();
      if (now - (d.t || 0) < 55000) return false;
      d.c += 50; d.t = now; v = 50;
    });
    return { c: u.c, v };
  },

  async buy(b) {
    const key = str(b.key, 12), price = priceOf(key);
    if (price === undefined) throw new E(400, 'Ese artículo no existe');
    const u = await mine(b, (d) => {
      if (d.o[key]) return false;
      if (d.c < price) throw new E(400, `Te faltan ${price - d.c} monedas`);
      d.c -= price; d.o[key] = 1;
    });
    return { c: u.c, o: u.o };
  },

  async gift(b) {
    const to = lc(b.to), amt = Math.floor(+b.amt);
    if (!(amt >= 1 && amt <= 1e9)) throw new E(400, 'Pon una cantidad válida');
    if (to === lc(b.n)) throw new E(400, 'No puedes regalarte monedas a ti mismo');
    if (!NAME.test(to) || !(await S.get(uk(to), { type: 'json' }))) throw new E(404, 'Ese usuario no existe');
    const me = await mine(b, (d) => {
      if (d.c < amt) throw new E(400, 'No te alcanzan las monedas');
      d.c -= amt;
    });
    try {
      if (!(await update(uk(to), (d) => { d.c += amt; }))) throw new Error('sin cuenta');
    } catch {
      await mine(b, (d) => { d.c += amt; }).catch(() => {}); // devolver las monedas
      throw new E(503, 'No se pudo enviar el regalo. Intenta otra vez.');
    }
    return { c: me.c };
  },

  async find(b) { // buscar perfiles por el inicio del nombre
    const q = lc(b.q).replace(/[^a-z0-9_]/g, '').slice(0, 16);
    if (!q) return { u: [] };
    let keys = [];
    for await (const page of S.list({ prefix: 'u/' + q, paginate: true })) {
      keys = page.blobs.slice(0, 12).map((x) => x.key);
      break;
    }
    const us = await Promise.all(keys.map((k) => S.get(k, { type: 'json' })));
    return { u: us.filter(Boolean).map((u) => ({ n: u.n, p: u.p })) };
  },

  async own(b, ip) { // comprobar el código de dueño
    await owner(b.key, ip);
    return { ok: 1 };
  },

  async grant(b, ip) { // dueño: monedas gratis para su propia cuenta
    await owner(b.key, ip);
    const v = Math.floor(+b.v);
    if (!(v >= 1 && v <= 1e8)) throw new E(400, 'Cantidad inválida');
    const u = await mine(b, (d) => { d.c += v; });
    return { c: u.c };
  },

  async mk(b, ip) { // dueño: crear código de regalo de un solo uso
    await owner(b.key, ip);
    const v = Math.floor(+b.v);
    if (!(v >= 1 && v <= 1e8)) throw new E(400, 'Cantidad inválida');
    const AB = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const raw = Array.from({ length: 24 }, () => AB[randomInt(AB.length)]).join('');
    if (!(await S.setJSON('c/' + raw, { v, ts: Date.now() }, { onlyIfNew: true })).modified) {
      throw new E(503, 'Intenta otra vez');
    }
    return { code: raw.match(/.{4}/g).join('-') };
  },

  async use(b) { // canjear código
    const code = String(b.code ?? '').toUpperCase().replace(/[^A-Z0-9]/g, '');
    if (code.length !== 24) throw new E(400, 'Ese código no es válido');
    await who(b);
    const key = 'c/' + code, gone = new E(404, 'Ese código no existe o ya se usó');
    const cur = await S.getWithMetadata(key, { type: 'json' });
    if (!cur || cur.data.u) throw gone;
    // Primero se marca como usado (solo uno puede ganar), luego se pagan las monedas
    const claim = await S.setJSON(key, { ...cur.data, u: lc(b.n), at: Date.now() }, { onlyIfMatch: cur.etag });
    if (!claim.modified) throw gone;
    try {
      const u = await mine(b, (d) => { d.c += cur.data.v; });
      await S.delete(key);
      return { c: u.c, v: cur.data.v };
    } catch (e) {
      await S.setJSON(key, cur.data).catch(() => {}); // si falló el pago, el código vuelve a servir
      throw e;
    }
  },
};

export default async (req, context) => {
  if (req.method !== 'POST') return json({ e: 'Método no permitido' }, 405);
  try {
    S = getStore({ name: 'ruleta', consistency: 'strong' });
    const text = await req.text();
    if (text.length > 900000) throw new E(413, 'Los datos son demasiado grandes');
    let b;
    try { b = JSON.parse(text); } catch { throw new E(400, 'Solicitud inválida'); }
    if (!b || typeof b !== 'object' || typeof b.a !== 'string' || !Object.hasOwn(ACTIONS, b.a)) {
      throw new E(400, 'Acción desconocida');
    }
    const ip = context?.ip || req.headers.get('x-nf-client-connection-ip') || 'desconocida';
    return json(await ACTIONS[b.a](b, ip));
  } catch (e) {
    if (e instanceof E) return json({ e: e.message }, e.status);
    console.error('api', e);
    return json({ e: 'Error del servidor' }, 500);
  }
};

export const config = { path: '/api' };

// ============================================================================
//  PVP en vivo y tienda de objetos · Netlify Function en /pvp
//  Va en la MISMA carpeta que tu archivo del API: usa las mismas cuentas y el mismo almacén.
//  No necesita variables nuevas. Precios = los de la lista TG de index.html.
// ============================================================================
import { getStore } from '@netlify/blobs';
import { createHash, randomBytes } from 'node:crypto';

const IT = {"h1": 250000, "h2": 600000, "h3": 450000, "h4": 800000, "y1": 1500000, "he": 900000, "m1": 70000, "m2": 40000, "m3": 75000, "a1": 400000, "a2": 650000, "a3": 120000, "a4": 700000, "a5": 150000, "a6": 300000, "d1": 100000, "d2": 60000, "d3": 70000, "d4": 90000, "d5": 80000, "o1": 30000, "r1": 25000, "r2": 20000, "t1": 4500, "t2": 6000, "t3": 5000, "t4": 5500};
const SECS = 120; // duración de cada batalla
const NAME = /^\w{3,16}$/;
const sha = (s) => createHash('sha256').update(String(s)).digest('hex');
const lc = (n) => String(n ?? '').toLowerCase();
const int = (v, lo, hi) => Math.min(hi, Math.max(lo, Math.floor(+v) || 0));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
class E extends Error { constructor(s, m) { super(m); this.status = s; } }
const SES = () => new E(401, 'Sesión vencida. Entra de nuevo.');
const json = (d, s = 200) => new Response(JSON.stringify(d), { status: s, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' } });
const total = (inv) => Object.entries(inv || {}).reduce((s, [k, v]) => s + (Object.hasOwn(IT, k) ? IT[k] * v : 0), 0);
const MK = (id) => 'pvp/m/' + id, PT = (n) => 'pvp/p/' + n;
let S;

async function update(key, fn) { // leer → modificar → guardar solo si nadie lo tocó (si no, reintenta)
  for (let i = 0; i < 8; i++) {
    const cur = await S.getWithMetadata(key, { type: 'json' });
    if (!cur) return null;
    if ((await fn(cur.data)) === false) return cur.data;
    if ((await S.setJSON(key, cur.data, { onlyIfMatch: cur.etag })).modified) return cur.data;
    await sleep(20 + Math.random() * 60);
  }
  throw new E(503, 'Hay mucho movimiento. Intenta otra vez en un momento.');
}
async function acct(b, fn) { // comprueba la sesión (y modifica la cuenta si hay fn)
  const n = lc(b.n);
  if (!NAME.test(n)) throw SES();
  const chk = (u) => { if (typeof b.k !== 'string' || !u.se.includes(sha(b.k))) throw SES(); };
  const u = fn ? await update('u/' + n, (d) => { chk(d); return fn(d); }) : await S.get('u/' + n, { type: 'json' });
  if (!u) throw SES();
  if (!fn) chk(u);
  return u;
}
async function active(n) { // partida en curso de este jugador
  const p = await S.get(PT(n), { type: 'json' }), m = p && (await S.get(MK(p.m), { type: 'json' }));
  if (m && Date.now() < m.end + 20000) return m;
  if (p) await S.delete(PT(n));
  return null;
}
async function view(m, me) {
  const opp = m.a === me ? m.b : m.a, u = await S.get('u/' + opp, { type: 'json' });
  return { id: m.id, o: { n: u?.n || opp, p: u?.p || '' }, left: Math.max(1, Math.ceil((m.end - Date.now()) / 1000)) };
}

const A = {
  async inv(b) { const u = await acct(b); return { inv: u.inv || {}, cr: u.cr || 0, c: u.c }; },

  async buyi(b) { // comprar objetos de la tienda (q unidades); las monedas las descuenta el servidor
    const k = String(b.key ?? '').slice(0, 4), q = int(b.q, 1, 99);
    if (!Object.hasOwn(IT, k)) throw new E(400, 'Ese objeto no existe');
    const u = await acct(b, (d) => {
      const t = IT[k] * q;
      if (d.c < t) throw new E(400, `Te faltan ${t - d.c} monedas`);
      d.c -= t; d.inv = { ...d.inv, [k]: (d.inv?.[k] || 0) + q };
    });
    return { c: u.c, inv: u.inv };
  },

  async pq(b) { // buscar jugador real: cada 1,5 s la app vuelve a preguntar
    const u = await acct(b), me = lc(u.n), cur = await active(me);
    if (cur) return { m: await view(cur, me) };
    for (let i = 0; i < 6; i++) {
      const w = await S.getWithMetadata('pvp/wait', { type: 'json' }), now = Date.now(), o = w?.data;
      if (o?.n && o.n !== me && now - o.t < 6000) { // hay alguien esperando: emparejar
        if (!(await S.setJSON('pvp/wait', {}, { onlyIfMatch: w.etag })).modified) continue; // solo uno gana el turno
        if (await active(o.n)) continue;
        const m = { id: randomBytes(6).toString('hex'), a: o.n, b: me, end: now + SECS * 1000, inv: {}, fin: 0 };
        await S.setJSON(MK(m.id), m);
        await S.setJSON(PT(o.n), { m: m.id });
        await S.setJSON(PT(me), { m: m.id });
        return { m: await view(m, me) };
      }
      const r = await S.setJSON('pvp/wait', { n: me, t: now }, w ? { onlyIfMatch: w.etag } : { onlyIfNew: true });
      if (r.modified) return { m: null }; // quedé esperando
    }
    return { m: null };
  },

  async pc(b) { // cancelar la búsqueda
    const u = await acct(b), w = await S.getWithMetadata('pvp/wait', { type: 'json' });
    if (w?.data?.n === lc(u.n)) await S.setJSON('pvp/wait', {}, { onlyIfMatch: w.etag });
    return { ok: 1 };
  },

  async ps(b) { // batalla: guardo lo mío, leo lo del rival; con f:1 cierra y da la corona (una sola vez)
    const u = await acct(b), me = lc(u.n), id = String(b.m ?? '').replace(/[^a-f0-9]/g, '').slice(0, 12);
    let pay = false;
    const m = id && (await update(MK(id), (d) => {
      if (d.a !== me && d.b !== me) throw new E(403, 'No estás en esa partida');
      pay = false;
      const now = Date.now();
      if (!d.fin && now <= d.end + 1500) { // solo cuenta lo que de verdad tienes
        const own = u.inv || {}, c = {};
        for (const [k, v] of Object.entries(b.inv && typeof b.inv === 'object' ? b.inv : {})) {
          const n = Object.hasOwn(IT, k) ? Math.min(int(v, 0, 99), own[k] || 0) : 0;
          if (n) c[k] = n;
        }
        d.inv[me] = c;
      }
      if (b.f && !d.fin && now >= d.end + 2000) {
        const ta = total(d.inv[d.a]), tb = total(d.inv[d.b]);
        Object.assign(d, { fin: 1, ta, tb, w: ta > tb ? d.a : tb > ta ? d.b : '' });
        pay = !!d.w;
      }
    }));
    if (!m) throw new E(404, 'Esa partida no existe');
    if (pay) await update('u/' + m.w, (d) => { d.cr = (d.cr || 0) + 1; });
    const opp = m.a === me ? m.b : m.a, out = { o: m.inv[opp] || {} };
    if (m.fin) {
      await S.delete(PT(me));
      const cr = (await S.get('u/' + me, { type: 'json' }))?.cr || 0;
      Object.assign(out, { r: m.w === me ? 1 : m.w ? -1 : 0, mt: me === m.a ? m.ta : m.tb, ot: me === m.a ? m.tb : m.ta, cr });
    }
    return out;
  },
};

export default async (req) => {
  if (req.method !== 'POST') return json({ e: 'Método no permitido' }, 405);
  try {
    S = getStore({ name: 'ruleta', consistency: 'strong' });
    const text = await req.text();
    if (text.length > 20000) throw new E(413, 'Datos demasiado grandes');
    let b;
    try { b = JSON.parse(text); } catch { throw new E(400, 'Solicitud inválida'); }
    if (!b || typeof b.a !== 'string' || !Object.hasOwn(A, b.a)) throw new E(400, 'Acción desconocida');
    return json(await A[b.a](b));
  } catch (e) {
    if (e instanceof E) return json({ e: e.message }, e.status);
    console.error('pvp', e);
    return json({ e: 'Error del servidor' }, 500);
  }
};

export const config = { path: '/pvp' };
           
  
