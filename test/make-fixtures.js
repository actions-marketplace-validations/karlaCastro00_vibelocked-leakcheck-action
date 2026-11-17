// Builds fake secrets at run time so no secret-shaped string is ever committed.
const fs = require('node:fs'); const path = require('node:path');
const dir = process.argv[2] || 'fixtures'; fs.mkdirSync(path.join(dir, 'src'), { recursive: true });
const r = (n, a = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') => Array.from({ length: n }, (_, i) => a[(i * 7 + 3) % a.length]).join('');
const stripe = ['sk', 'live', r(24)].join('_');
const aws = 'AK' + 'IA' + r(16, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567');
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const service = ['ey' + b64({ alg: 'HS256', typ: 'JWT' }).slice(2), b64({ iss: 'supabase', role: 'service_role' }), r(30)].join('.');
const anon = ['ey' + b64({ alg: 'HS256', typ: 'JWT' }).slice(2), b64({ iss: 'supabase', role: 'anon' }), r(30)].join('.');
fs.writeFileSync(path.join(dir, 'src', 'client.js'), `const stripe = "${stripe}";\nconst supa = "${service}";\nconst pub = "${anon}";\n`);
fs.writeFileSync(path.join(dir, 'src', 'config.ts'), `export const awsKey = '${aws}';\nexport const MY_SERVICE_TOKEN = "${r(24)}";\nexport const API_KEY = process.env.API_KEY;\n`);
fs.writeFileSync(path.join(dir, '.env'), 'DATABASE_URL=placeholder\n');
fs.writeFileSync(path.join(dir, '.env.example'), 'OPENAI_API_KEY=your-key-here\n');
console.log('fixtures written to', dir);
