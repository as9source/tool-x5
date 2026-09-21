const CACHE_NAME = 'saisun-v6';
const ASSETS = [
  './',
  './index.html',
  './manifest.json',
  './icons/icon-512.png',
  './icons/icon-192.png',
  './cloud-backup.js',
  './pdf-zip-lock.js'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(ASSETS)).catch(() => {})
  );
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') return;
  event.respondWith(
    fetch(event.request.mode === 'navigate'
      ? new Request(event.request, { cache: 'reload' })
      : event.request)
      .then(res => {
        // 成功した応答だけ保存する。404などを入れてしまうと、オフライン時に
        // アプリの代わりにエラーページが返り続ける。
        // type==='opaque' は cdnjs や Google Fonts など別ドメインの応答で、
        // status が 0 のため res.ok では判定できない。
        if (res.ok || res.type === 'opaque') {
          const clone = res.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone)).catch(() => {});
        }
        return res;
      })
      .catch(() => caches.match(event.request))
  );
});
