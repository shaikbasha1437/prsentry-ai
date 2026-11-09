const CACHE = 'prsentry-v1';
const FILES = ['./', './index.html', './styles.css', './js/app.js', './js/diff.js', './js/rules.js', './js/review.js', './js/github.js', './js/llm.js', './samples/demo-prs.json', './manifest.webmanifest', './icons/icon.svg', './icons/icon-192.png', './icons/icon-512.png'];
self.addEventListener('install', (event) => { event.waitUntil((async () => { const cache = await caches.open(CACHE); for (const file of FILES) { try { const res = await fetch(file, { cache: 'reload' }); if (res.ok) await cache.put(file, res); } catch (e) { /* keep going: one missing file must not break install */ } } await self.skipWaiting(); })()); });
self.addEventListener('activate', (event) => { event.waitUntil((async () => { for (const k of await caches.keys()) if (k.startsWith('prsentry-') && k !== CACHE) await caches.delete(k); await self.clients.claim(); })()); });
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== 'GET' || url.origin !== self.location.origin || !url.pathname.startsWith(new URL('./', self.location).pathname)) return;
  event.respondWith((async () => {
    const cache = await caches.open(CACHE);
    try { const res = await fetch(event.request); if (res.ok) await cache.put(event.request, res.clone()); return res; }
    catch (e) { const hit = await cache.match(event.request, { ignoreSearch: true }); if (hit) return hit; if (event.request.mode === 'navigate') return (await cache.match('./index.html')) || Response.error(); return new Response('Offline: resource not cached', { status: 503 }); }
  })());
});
