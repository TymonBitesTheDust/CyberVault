// sw.js: lets CyberVault open with no internet connection.
// It only keeps copies of the app's own files (HTML, code, styles, fonts, icons) and of
// Google's Firebase code. Your vault data never passes through here: Firestore keeps its
// own encrypted offline copy. Sign-in and database traffic is left alone.

const CACHE = 'cybervault-app-v2';

self.addEventListener('install', () => self.skipWaiting());

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    for (const k of await caches.keys()) if (k !== CACHE) await caches.delete(k);
    await self.clients.claim();
  })());
});

const isFirebaseSdk = (url) => url.origin === 'https://www.gstatic.com' && url.pathname.startsWith('/firebasejs/');

// The page sends the list of files it loaded, so they're ready for the next offline start.
self.addEventListener('message', (event) => {
  if (event.data?.type !== 'cache-urls' || !Array.isArray(event.data.urls)) return;
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE);
    await Promise.all(event.data.urls.map(async (u) => {
      try {
        const url = new URL(u);
        if (url.origin !== self.location.origin && !isFirebaseSdk(url)) return;
        if (url.origin === self.location.origin && await cache.match(url.href, { ignoreSearch: true })) return;
        const res = await fetch(url.href, { mode: url.origin === self.location.origin ? 'same-origin' : 'cors', credentials: 'omit', cache: 'no-cache' });
        if (res.ok) await cache.put(url.href, res);
      } catch { /* try again next time */ }
    }));
  })());
});

async function networkFirst(request, timeoutMs) {
  const cache = await caches.open(CACHE);
  try {
    const res = await Promise.race([
      fetch(request),
      new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), timeoutMs)),
    ]);
    if (res.ok && res.type !== 'opaque') cache.put(request, res.clone());
    return res;
  } catch (e) {
    const hit = await cache.match(request, { ignoreSearch: request.mode === 'navigate' });
    if (hit) return hit;
    throw e;
  }
}

async function cacheFirst(request) {
  const cache = await caches.open(CACHE);
  const hit = await cache.match(request);
  if (hit) return hit;
  const res = await fetch(request);
  if (res.ok) cache.put(request, res.clone());
  return res;
}

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  // Firebase's code is versioned in its address, so a saved copy never goes stale.
  if (isFirebaseSdk(url)) { event.respondWith(cacheFirst(req)); return; }
  if (url.origin !== self.location.origin || url.pathname.startsWith('/__/')) return;
  // The app's own files: always the newest when online, the saved copy when offline.
  event.respondWith(networkFirst(req, req.mode === 'navigate' ? 4000 : 8000));
});
