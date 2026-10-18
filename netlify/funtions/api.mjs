// Ruleta: API principal + PVP en vivo en un solo archivo Netlify Function.
// Ubicación: netlify/functions/api.mjs
// Variable de entorno opcional para funciones de dueño: OWNER_KEY (mínimo 6 caracteres).

import { getStore } from '@netlify/blobs';
import { createHash, randomBytes, randomInt, scrypt as scryptCb, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(scryptCb);

const WS = [0,500,800,1000,1200,1500,1800,2000,2300,2500,3000,3500,4000,4500,5000,6000,7000,8000,9000,6500,1500,2000,3000,3500,4000,5500,7500,10000];
const BG = [0,300,500,700,900,1100,1300,1500,1800,2000,2300,2600,3000,3400,3800,4200,4600,5000,5500,6000,800,1200,1800,2200,2600,3200,4000,4500,5200,6000,7000,2400,2800,3200,3600,4000,4400];
const DC = {rb:20000,fi:12000,ne:12000,or:15000,ic:12000,to:12000,co:12000,ga:25000,pl:14000,so:14000,bn:16000,ec:20000,pa:22000,ho:18000,au:26000,la:28000,l1:9000,l2:9000,l3:13000,l4:13000,l5:13000,l6:15000,l7:16000,l8:17000,l9:18000,l10:19000,l11:21000,l12:24000};
const HIDE = ['cp','ck','bT','bt','bS','bM','bU','bE'];

function priceOf(k) {
  if (k === 'rf' || k === 'bv') return 50000;
  let m = /^([rb])(0|[1-9]\d*)$/.exec(k);
  if (m) return (m[1] === 'r' ? WS : BG)[+m[2]];
  m = /^d(\w+)$/.exec(k);
  if (m) return Object.hasOwn(DC,m[1]) ? DC[m[1]] : undefined;
  m = /^[ph]([cd])(0|[1-9]\d*)$/.exec(k);
  if (m && +m[2] < 20) {
    const i=+m[2];
    return m[1]==='c' ? (i ? 200+i*100 : 0) : 800+i*400;
  }
}

class E extends Error {
  constructor(status,msg) {
    super(msg);
    this.status=status;
  }
}

const SES = () => new E(401,'Sesión vencida. Entra de nuevo.');
const NAME = /^\w{3,16}$/;
const IMG = /^data:image\/(?:jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/;
const sha = s => createHash('sha256').update(String(s)).digest('hex');
const same = (a,b) => {
  const x=Buffer.from(a), y=Buffer.from(b);
  return x.length===y.length && timingSafeEqual(x,y);
};
const sleep = ms => new Promise(r=>setTimeout(r,ms));
const env = k => globalThis.Netlify?.env?.get(k) ?? process.env[k];
const lc = n => String(n ?? '').toLowerCase();
const str = (v,max) => typeof v==='string' ? v.trim().slice(0,max) : '';
const int = (v,lo,hi) => Math.min(hi,Math.max(lo,Math.floor(+v)||0));
const img = (v,max) => typeof v==='string' && v.length<=max && IMG.test(v) ? v : '';
const idx = v => v==='' || v==null ? '' : int(v,0,19);
const hashPw = async (pw,salt) => (await scrypt(pw,salt,32)).toString('hex');
const newKey = () => randomBytes(24).toString('base64url');
const json = (data,status=200) => new Response(JSON.stringify(data), {
  status,
  headers: {
    'content-type':'application/json; charset=utf-8',
    'cache-control':'no-store'
  }
});
const uk = n => 'u/'+lc(n);
const dk = n => 'd/'+lc(n);

let S;

async function update(key,fn) {
  for(let i=0;i<8;i++) {
    const cur=await S.getWithMetadata(key,{type:'json'});
    if(!cur) return null;
    if((await fn(cur.data))===false) return cur.data;
    const r=await S.setJSON(key,cur.data,{onlyIfMatch:cur.etag});
    if(r.modified) return cur.data;
    await sleep(20+Math.random()*60);
  }
  throw new E(503,'Hay mucho movimiento. Intenta otra vez en un momento.');
}

const chk = (u,k) => {
  if(typeof k!=='string' || !u.se.includes(sha(k))) throw SES();
};

async function who(b) {
  const n=lc(b.n);
  const u=NAME.test(n) ? await S.get(uk(n),{type:'json'}) : null;
  if(!u) throw SES();
  chk(u,b.k);
  return u;
}

async function mine(b,fn) {
  const n=lc(b.n);
  if(!NAME.test(n)) throw SES();
  const u=await update(uk(n),d=>{
    chk(d,b.k);
    return fn(d);
  });
  if(!u) throw SES();
  return u;
}

async function rate(bucket,id,max,secs,add=true) {
  const key=`rl/${bucket}/${sha(id).slice(0,20)}`;
  const now=Date.now();
  const cur=await S.getWithMetadata(key,{type:'json'});
  let d=cur?.data;
  if(!d || now-d.w>secs*1000) d={w:now,n:0};
  if(d.n>=max) throw new E(429,'Demasiados intentos. Prueba más tarde.');
  if(add) {
    d.n++;
    await S.setJSON(key,d,cur?{onlyIfMatch:cur.etag}:{onlyIfNew:true}).catch(()=>{});
  }
}

async function owner(key,ip) {
  const real=env('OWNER_KEY');
  if(!real || real.length<6) {
    throw new E(503,'Falta crear OWNER_KEY en Netlify (mínimo 6 caracteres)');
  }
  await rate('own',ip,8,3600,false);
  if(typeof key!=='string' || !same(sha(key),sha(real))) {
    await rate('own',ip,8,3600);
    throw new E(403,'Código incorrecto');
  }
}

function cleanData(d) {
  d=d && typeof d==='object' ? d : {};
  const ph=img(d.ph,450000);
  return {
    rs:d.rs==='f'&&ph?'f':int(d.rs,0,WS.length-1),
    bg:int(d.bg,0,BG.length-1),
    dc:typeof d.dc==='string'&&Object.hasOwn(DC,d.dc)?d.dc:'',
    ph,
    pc:idx(d.pc),
    pd:idx(d.pd),
    hc:idx(d.hc),
    hd:idx(d.hd),
    keep:!!d.keep,
    rm:!!d.rm,
    hide:Array.isArray(d.hide)?[...new Set(d.hide.filter(x=>HIDE.includes(x)))]:HIDE,
    sec:int(d.sec,0,1e9),
    spins:int(d.spins,0,1e9),
    items:(Array.isArray(d.items)?d.items:[]).slice(0,500).map(i=>({
      id:int(i?.id,0,1e9),
      name:str(i?.name,40)
    }))
  };
}

const pack=(u,d)=>({...d,coins:u.c,own:u.o});
const loadData=async n=>(await S.get(dk(n),{type:'json'}))??cleanData({});

const ACTIONS = {
  async reg(b,ip) {
    await rate('reg',ip,15,3600);
    const n=str(b.n,16);
    const r=str(b.r,30);
    const pw=typeof b.pw==='string'?b.pw:'';

    if(!NAME.test(n)) throw new E(400,'Nombre de perfil: 3 a 16 letras, números o _');
    if(!r) throw new E(400,'Pon tu nombre real');
    if(pw.length<6||pw.length>200) {
      throw new E(400,'La contraseña necesita entre 6 y 200 caracteres');
    }

    const d=cleanData(b.d);
    const k=newKey();
    const salt=randomBytes(16).toString('hex');
    const u={
      n,r,p:img(b.p,60000),s:salt,
      h:await hashPw(pw,salt),
      se:[sha(k)],c:500,o:{},t:Date.now(),
      fl:0,lk:0,dh:sha(JSON.stringify(d)).slice(0,16),
      ct:Date.now()
    };

    if(!(await S.setJSON(uk(n),u,{onlyIfNew:true})).modified) {
      throw new E(409,'Ese nombre ya está en uso');
    }

    await S.setJSON(dk(n),d);
    return {n,k,p:u.p,r,d:pack(u,d)};
  },

  async login(b) {
    const n=lc(b.n);
    const pw=typeof b.pw==='string'?b.pw.slice(0,200):'';
    const bad=new E(401,'Nombre o contraseña incorrectos');
    const u0=NAME.test(n)?await S.get(uk(n),{type:'json'}):null;

    if(!u0) {
      await hashPw(pw,'relleno');
      throw bad;
    }

    const wait=()=>Math.ceil((u0.lk-Date.now())/60000);
    if(u0.lk>Date.now()) {
      throw new E(429,`Cuenta bloqueada por intentos fallidos. Prueba en ${wait()} min.`);
    }

    const ok=same(await hashPw(pw,u0.s),u0.h);
    const k=newKey();

    const u=await update(uk(n),d=>{
      if(!ok) {
        d.fl=(d.fl||0)+1;
        if(d.fl>=5) {
          d.fl=0;
          d.lk=Date.now()+10*60000;
        }
        return;
      }
      d.fl=0;
      d.lk=0;
      d.se=[...d.se,sha(k)].slice(-5);
    });

    if(!ok) {
      if(u.lk>Date.now()) {
        throw new E(429,'Cuenta bloqueada por intentos fallidos. Prueba en 10 min.');
      }
      throw bad;
    }

    return {n:u.n,k,p:u.p,r:u.r,d:pack(u,await loadData(n))};
  },

  async me(b) {
    const u=await who(b);
    return {p:u.p,d:pack(u,await loadData(b.n))};
  },

  async save(b) {
    const u0=await who(b);
    const d=cleanData(b.d);
    const h=sha(JSON.stringify(d)).slice(0,16);
    const av=img(b.p,60000);

    if(u0.dh===h&&(!av||av===u0.p)) return {c:u0.c};
    if(u0.dh!==h) await S.setJSON(dk(b.n),d);

    const u=await mine(b,x=>{
      x.dh=h;
      if(av) x.p=av;
    });

    return {c:u.c};
  },

  async earn(b) {
    let v=0;
    const u=await mine(b,d=>{
      v=0;
      const now=Date.now();
      if(now-(d.t||0)<55000) return false;
      d.c+=50;
      d.t=now;
      v=50;
    });
    return {c:u.c,v};
  },

  async buy(b) {
    const key=str(b.key,12);
    const price=priceOf(key);
    if(price===undefined) throw new E(400,'Ese artículo no existe');

    const u=await mine(b,d=>{
      if(d.o[key]) return false;
      if(d.c<price) throw new E(400,`Te faltan ${price-d.c} monedas`);
      d.c-=price;
      d.o[key]=1;
    });

    return {c:u.c,o:u.o};
  },

  async gift(b) {
    const to=lc(b.to);
    const amt=Math.floor(+b.amt);

    if(!(amt>=1&&amt<=1e9)) throw new E(400,'Pon una cantidad válida');
    if(to===lc(b.n)) throw new E(400,'No puedes regalarte monedas a ti mismo');
    if(!NAME.test(to)||!(await S.get(uk(to),{type:'json'}))) {
      throw new E(404,'Ese usuario no existe');
    }

    const me=await mine(b,d=>{
      if(d.c<amt) throw new E(400,'No te alcanzan las monedas');
      d.c-=amt;
    });

    try {
      if(!(await update(uk(to),d=>{
        d.c+=amt;
      }))) throw new Error('sin cuenta');
    } catch {
      await mine(b,d=>{
        d.c+=amt;
      }).catch(()=>{});
      throw new E(503,'No se pudo enviar el regalo. Intenta otra vez.');
    }

    return {c:me.c};
  },

  async find(b) {
    const q=lc(b.q).replace(/[^a-z0-9_]/g,'').slice(0,16);
    if(!q) return {u:[]};

    let keys=[];
    for await(const page of S.list({prefix:'u/'+q,paginate:true})) {
      keys=page.blobs.slice(0,12).map(x=>x.key);
      break;
    }

    const us=await Promise.all(keys.map(k=>S.get(k,{type:'json'})));
    return {u:us.filter(Boolean).map(u=>({n:u.n,p:u.p}))};
  },

  async own(b,ip) {
    await owner(b.key,ip);
    return {ok:1};
  },

  async grant(b,ip) {
    await owner(b.key,ip);
    const v=Math.floor(+b.v);
    if(!(v>=1&&v<=1e8)) throw new E(400,'Cantidad inválida');
    const u=await mine(b,d=>{
      d.c+=v;
    });
    return {c:u.c};
  },

  async mk(b,ip) {
    await owner(b.key,ip);
    const v=Math.floor(+b.v);
    if(!(v>=1&&v<=1e8)) throw new E(400,'Cantidad inválida');

    const AB='ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const raw=Array.from({length:24},()=>AB[randomInt(AB.length)]).join('');

    if(!(await S.setJSON('c/'+raw,{v,ts:Date.now()},{onlyIfNew:true})).modified) {
      throw new E(503,'Intenta otra vez');
    }

    return {code:raw.match(/.{4}/g).join('-')};
  },

  async use(b) {
    const code=String(b.code??'').toUpperCase().replace(/[^A-Z0-9]/g,'');
    if(code.length!==24) throw new E(400,'Ese código no es válido');
    await who(b);

    const key='c/'+code;
    const gone=new E(404,'Ese código no existe o ya se usó');
    const cur=await S.getWithMetadata(key,{type:'json'});

    if(!cur||cur.data.u) throw gone;

    const claim=await S.setJSON(key,{
      ...cur.data,
      u:lc(b.n),
      at:Date.now()
    },{onlyIfMatch:cur.etag});

    if(!claim.modified) throw gone;

    try {
      const u=await mine(b,d=>{
        d.c+=cur.data.v;
      });
      await S.delete(key);
      return {c:u.c,v:cur.data.v};
    } catch(e) {
      await S.setJSON(key,cur.data).catch(()=>{});
      throw e;
    }
  }
};

/* PVP: se mantiene en el mismo archivo y usa el mismo almacén de cuentas. */

const PVP_ITEMS={
  h1:250000,h2:600000,h3:450000,h4:800000,
  y1:1500000,he:900000,m1:70000,m2:40000,m3:75000,
  a1:400000,a2:650000,a3:120000,a4:700000,a5:150000,a6:300000,
  d1:100000,d2:60000,d3:70000,d4:90000,d5:80000,
  o1:30000,r1:25000,r2:20000,t1:4500,t2:6000,t3:5000,t4:5500
};

const SECS=120;
const MK=id=>'pvp/m/'+id;
const PT=n=>'pvp/p/'+n;

const total=inv=>Object.entries(inv||{}).reduce(
  (s,[k,v])=>s+(Object.hasOwn(PVP_ITEMS,k)?PVP_ITEMS[k]*v:0),0
);

async function pvpAcct(b,fn) {
  const n=lc(b.n);
  if(!NAME.test(n)) throw SES();

  const u=fn
    ? await update(uk(n),d=>{
        chk(d,b.k);
        return fn(d);
      })
    : await S.get(uk(n),{type:'json'});

  if(!u) throw SES();
  if(!fn) chk(u,b.k);
  return u;
}

async function active(n) {
  const p=await S.get(PT(n),{type:'json'});
  const m=p&&(await S.get(MK(p.m),{type:'json'}));

  if(m&&Date.now()<m.end+20000) return m;
  if(p) await S.delete(PT(n));
  return null;
}

async function viewMatch(m,me) {
  const opp=m.a===me?m.b:m.a;
  const u=await S.get(uk(opp),{type:'json'});
  return {
    id:m.id,
    o:{n:u?.n||opp,p:u?.p||''},
    left:Math.max(1,Math.ceil((m.end-Date.now())/1000))
  };
}

const PVP = {
  async inv(b) {
    const u=await pvpAcct(b);
    return {inv:u.inv||{},cr:u.cr||0,c:u.c};
  },

  async buyi(b) {
    const k=String(b.key??'').slice(0,4);
    const q=int(b.q,1,99);

    if(!Object.hasOwn(PVP_ITEMS,k)) {
      throw new E(400,'Ese objeto no existe');
    }

    const u=await pvpAcct(b,d=>{
      const t=PVP_ITEMS[k]*q;
      if(d.c<t) throw new E(400,`Te faltan ${t-d.c} monedas`);
      d.c-=t;
      d.inv={...d.inv,[k]:(d.inv?.[k]||0)+q};
    });

    return {c:u.c,inv:u.inv};
  },

  async pq(b) {
    const u=await pvpAcct(b);
    const me=lc(u.n);
    const cur=await active(me);
    if(cur) return {m:await viewMatch(cur,me)};

    for(let i=0;i<6;i++) {
      const w=await S.getWithMetadata('pvp/wait',{type:'json'});
      const now=Date.now();
      const o=w?.data;

      if(o?.n&&o.n!==me&&now-o.t<6000) {
        if(!(await S.setJSON('pvp/wait',{}, {onlyIfMatch:w.etag})).modified) continue;
        if(await active(o.n)) continue;

        const m={
          id:randomBytes(6).toString('hex'),
          a:o.n,b:me,end:now+SECS*1000,
          inv:{},fin:0
        };

        await S.setJSON(MK(m.id),m);
        await S.setJSON(PT(o.n),{m:m.id});
        await S.setJSON(PT(me),{m:m.id});

        return {m:await viewMatch(m,me)};
      }

      const r=await S.setJSON('pvp/wait',{n:me,t:now},
        w?{onlyIfMatch:w.etag}:{onlyIfNew:true});

      if(r.modified) return {m:null};
    }

    return {m:null};
  },

  async pc(b) {
    const u=await pvpAcct(b);
    const w=await S.getWithMetadata('pvp/wait',{type:'json'});

    if(w?.data?.n===lc(u.n)) {
      await S.setJSON('pvp/wait',{}, {onlyIfMatch:w.etag});
    }

    return {ok:1};
  },

  async ps(b) {
    const u=await pvpAcct(b);
    const me=lc(u.n);
    const id=String(b.m??'').replace(/[^a-f0-9]/g,'').slice(0,12);
    let pay=false;

    const m=id&&await update(MK(id),d=>{
      if(d.a!==me&&d.b!==me) throw new E(403,'No estás en esa partida');
      pay=false;

      const now=Date.now();

      if(!d.fin&&now<=d.end+1500) {
        const own=u.inv||{};
        const c={};

        for(const [k,v] of Object.entries(
          b.inv&&typeof b.inv==='object'?b.inv:{}
        )) {
          const n=Object.hasOwn(PVP_ITEMS,k)
            ?Math.min(int(v,0,99),own[k]||0)
            :0;
          if(n) c[k]=n;
        }

        d.inv[me]=c;
      }

      if(b.f&&!d.fin&&now>=d.end+2000) {
        const ta=total(d.inv[d.a]);
        const tb=total(d.inv[d.b]);
        Object.assign(d,{
          fin:1,
          ta,
          tb,
          w:ta>tb?d.a:tb>ta?d.b:''
        });
        pay=!!d.w;
      }
    });

    if(!m) throw new E(404,'Esa partida no existe');

    if(pay) {
      await update(uk(m.w),d=>{
        d.cr=(d.cr||0)+1;
      });
    }

    const opp=m.a===me?m.b:m.a;
    const out={o:m.inv[opp]||{}};

    if(m.fin) {
      await S.delete(PT(me));
      const cr=(await S.get(uk(me),{type:'json'}))?.cr||0;

      Object.assign(out,{
        r:m.w===me?1:m.w?-1:0,
        mt:me===m.a?m.ta:m.tb,
        ot:me===m.a?m.tb:m.ta,
        cr
      });
    }

    return out;
  }
};

export default async function handler(req,context) {
  if(req.method!=='POST') {
    return json({e:'Método no permitido'},405);
  }

  try {
    S=getStore({name:'ruleta',consistency:'strong'});

    const body=await req.text();
    if(body.length>900000) {
      throw new E(413,'Los datos son demasiado grandes');
    }

    let b;
    try {
      b=JSON.parse(body);
    } catch {
      throw new E(400,'Solicitud inválida');
    }

    if(!b||typeof b!=='object'||typeof b.a!=='string') {
      throw new E(400,'Acción desconocida');
    }

    const ip=context?.ip
      ||req.headers.get('x-nf-client-connection-ip')
      ||'desconocida';

    if(Object.hasOwn(ACTIONS,b.a)) {
      return json(await ACTIONS[b.a](b,ip));
    }

    if(Object.hasOwn(PVP,b.a)) {
      return json(await PVP[b.a](b));
    }

    throw new E(400,'Acción desconocida');
  } catch(e) {
    if(e instanceof E) return json({e:e.message},e.status);
    console.error('api',e);
    return json({e:'Error del servidor'},500);
  }
}

export const config={path:'/api'};
