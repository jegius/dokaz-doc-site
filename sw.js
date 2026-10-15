/*
 * Service Worker гейта документации.
 * Перехватывает все запросы под baseUrl, заменяет путь на enc/<path>.enc,
 * скачивает шифротекст (AES-256-GCM) и расшифровывает в памяти браузера.
 * Ключ хранится только в Cache API (записывает его страница-гейт после
 * проверки доступа через GitHub API) и в памяти воркера.
 */
const SCOPE_URL = new URL(self.registration.scope);
const BASE = SCOPE_URL.pathname.endsWith('/') ? SCOPE_URL.pathname : SCOPE_URL.pathname + '/';
const ENC_PREFIX = BASE + 'enc/';
const KEY_CACHE = '__dokaz_gate__';
const KEY_URL = '/__dokaz_key__';

const MIME = {
  html: 'text/html; charset=utf-8',
  js: 'text/javascript; charset=utf-8',
  mjs: 'text/javascript; charset=utf-8',
  css: 'text/css; charset=utf-8',
  json: 'application/json',
  map: 'application/json',
  svg: 'image/svg+xml',
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  gif: 'image/gif',
  webp: 'image/webp',
  ico: 'image/x-icon',
  woff: 'font/woff',
  woff2: 'font/woff2',
  ttf: 'font/ttf',
  txt: 'text/plain; charset=utf-8',
  xml: 'application/xml',
  webmanifest: 'application/manifest+json',
};

let keyPromise = null;

async function loadKeyBytes() {
  const cache = await caches.open(KEY_CACHE);
  const hit = await cache.match(KEY_URL);
  if (!hit) return null;
  return new Uint8Array(await hit.arrayBuffer());
}

// Принимаем и 32 сырых байта, и hex-строку (64 символа) — самолечение
// для браузеров, где ранее сохранилось содержимое файла ключа как текст.
async function importAesKey(bytes) {
  try {
    return await crypto.subtle.importKey('raw', bytes, 'AES-GCM', false, ['decrypt']);
  } catch (err) {
    let text = '';
    try { text = new TextDecoder('utf-8', { fatal: false }).decode(bytes).trim(); } catch (e) { text = ''; }
    if (/^[0-9a-fA-F]{64}$/.test(text)) {
      const raw = new Uint8Array(32);
      for (let i = 0; i < 32; i += 1) raw[i] = parseInt(text.substr(i * 2, 2), 16);
      return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
    }
    throw err;
  }
}

async function getKey() {
  if (!keyPromise) {
    keyPromise = (async () => {
      const bytes = await loadKeyBytes();
      if (!bytes) return null;
      return importAesKey(bytes);
    })();
  }
  const key = await keyPromise;
  if (!key) keyPromise = null; // ключ мог появиться позже — пробуем снова при следующем запросе
  return key;
}

async function decryptBuffer(buffer) {
  const bytes = new Uint8Array(buffer);
  const iv = bytes.slice(0, 12);
  const data = bytes.slice(12); // ciphertext + auth tag (16 байт) — формат WebCrypto
  const key = await getKey();
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
}

function normalizeRel(rel) {
  const clean = rel.split('?')[0].split('#')[0];
  return clean.endsWith('/') ? clean.slice(0, -1) : clean;
}

// Файлы без расширения в последнем сегменте — страницы (dir/index.html или file.html),
// файлы с расширением — ассеты (file.ext.enc).
function candidatesFor(rel) {
  const n = normalizeRel(rel);
  const last = n.split('/').pop() || '';
  if (last.includes('.')) return [encodeURI(n + '.enc')];
  return [encodeURI(n + '/index.html.enc'), encodeURI(n + '.html.enc')];
}

function mimeFor(rel) {
  const n = normalizeRel(rel);
  const last = n.split('/').pop() || '';
  if (!last.includes('.') || last === 'index.html') return MIME.html;
  const ext = (last.split('.').pop() || '').toLowerCase();
  return MIME[ext] || 'application/octet-stream';
}

function gateRedirectResponse() {
  // Нет ключа: ведём на гейт (воркер не отдаёт контент без аутентификации).
  const html = '<!DOCTYPE html><meta charset="utf-8">'
    + '<script>location.replace(' + JSON.stringify(BASE) + ');</script>'
    + '<p><a href="' + BASE + '">Открыть гейт доступа</a></p>';
  return new Response(html, { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });
}

function notFoundResponse() {
  // Ключ есть, файла нет: не редиректим на гейт (риск цикла), показываем заглушку.
  const html = '<!DOCTYPE html><meta charset="utf-8"><title>Не найдено</title>'
    + '<body style="font-family:sans-serif;padding:2rem">Страница не найдена в зашифрованной сборке.'
    + ' <a href="' + BASE + '">К гейту доступа</a></body>';
  return new Response(html, { status: 404, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });
}

async function fetchEncrypted(candidates) {
  for (const candidate of candidates) {
    const res = await fetch(ENC_PREFIX + candidate, { credentials: 'same-origin' });
    if (res.ok) return res;
  }
  return null;
}

async function handleRequest(request, rel) {
  try {
    return await handleRequestInner(request, rel);
  } catch (err) {
    // Никогда не отклоняем respondWith: браузер показал бы ERR_FAILED.
    // Показываем причину и даём кнопку полного сброса доступа на устройстве.
    const reason = (err && err.message ? err.message : String(err)).slice(0, 200);
    const html = '<!DOCTYPE html><meta charset="utf-8"><title>Восстановление доступа</title>'
      + '<body style="font-family:sans-serif;padding:2rem;line-height:1.6;max-width:720px">'
      + '<h2>Не удалось загрузить раздел</h2>'
      + '<p>Причина: <code>' + reason.replace(/</g, '&lt;') + '</code></p>'
      + '<p>Обычно помогает обновление страницы. Если не помогает — сбросьте доступ на этом устройстве '
      + '(кэш и воркер обновятся, затем введите токен заново).</p>'
      + '<p><a href="' + BASE + '">Перейти к входу</a> · '
      + '<button id="reset" style="cursor:pointer;padding:8px 14px;border-radius:8px;border:1px solid #888;background:#2563eb;color:#fff">Сбросить доступ и обновить</button></p>'
      + '<script>document.getElementById("reset").onclick=async function(){'
      + 'try{var ks=await caches.keys();for(var i=0;i<ks.length;i++)await caches.delete(ks[i]);}catch(e){}'
      + 'try{var rs=await navigator.serviceWorker.getRegistrations();for(var j=0;j<rs.length;j++)await rs[j].unregister();}catch(e){}'
      + 'location.replace(' + JSON.stringify(BASE) + ');};</script>'
      + '</body>';
    return new Response(html, { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });
  }
}

async function handleRequestInner(request, rel) {
  const isNavigation = request.mode === 'navigate';
  const key = await getKey();
  if (!key) {
    return isNavigation ? gateRedirectResponse() : new Response('dokaz-doc: нет ключа доступа', { status: 401 });
  }
  const encRes = await fetchEncrypted(candidatesFor(rel));
  if (!encRes) {
    return isNavigation ? notFoundResponse() : new Response('dokaz-doc: не найдено', { status: 404 });
  }
  try {
    const plain = await decryptBuffer(await encRes.arrayBuffer());
    return new Response(plain, { headers: { 'Content-Type': mimeFor(rel), 'Cache-Control': 'no-store' } });
  } catch (err) {
    return new Response('dokaz-doc: ошибка расшифровки (ключ не подходит — вероятно, сменился после нового деплоя)', { status: 500 });
  }
}

self.addEventListener('install', () => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', (event) => {
  let url;
  try {
    url = new URL(event.request.url);
  } catch (err) {
    return; // не-URL запросы не трогаем
  }
  try {
    if (url.origin !== SCOPE_URL.origin) return; // внешние запросы — не трогаем
    if (!url.pathname.startsWith(BASE)) return;
    const rel = url.pathname.slice(BASE.length);
    if (rel === '' || rel === 'index.html' || rel === 'sw.js') return; // гейт и сам воркер — в открытую
    event.respondWith(handleRequest(event.request, rel));
  } catch (err) {
    // ничего не делаем: запрос уйдёт в сеть по умолчанию
  }
});

// Ключ может прилететь сообщением от страницы (резервный канал к Cache API)
self.addEventListener('message', (event) => {
  const data = event.data || {};
  if (data.type === 'SET_KEY' && data.b64) {
    event.waitUntil((async () => {
      const bytes = new Uint8Array(atob(data.b64).split('').map((ch) => ch.charCodeAt(0)));
      const cache = await caches.open(KEY_CACHE);
      await cache.put(KEY_URL, new Response(bytes));
      keyPromise = null;
    })());
  }
  if (data.type === 'RESET_KEY') {
    event.waitUntil((async () => {
      const cache = await caches.open(KEY_CACHE);
      await cache.delete(KEY_URL);
      keyPromise = null;
    })());
  }
});
