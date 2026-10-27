// Caches only the static app shell. API responses are never cached (they hold secrets).
const CACHE = 'swg-shell-v0.1.4';
const SHELL = ['/', '/index.html', '/css/app.css', '/js/app.js', '/manifest.webmanifest', '/icons/icon.svg'];
self.addEventListener('install', e => e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting())));
self.addEventListener('activate', e => e.waitUntil(
  caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim())));
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.pathname.startsWith('/api/')) return;
  // network first, fall back to cache when offline
  e.respondWith(fetch(e.request).then(r => {
    const copy = r.clone();
    if (r.ok && SHELL.includes(url.pathname)) caches.open(CACHE).then(c => c.put(e.request, copy));
    return r;
  }).catch(() => caches.match(e.request).then(r => r || caches.match('/index.html'))));
});
