// AlertCitoyen — service worker : ouverture hors connexion
const CACHE = 'alertcitoyen-v1';
const COQUILLE = ['./', './index.html', './manifest.json'];
const EXTERNES = [
  'https://unpkg.com/leaflet@1.9.4/dist/leaflet.css',
  'https://unpkg.com/leaflet@1.9.4/dist/leaflet.js'
];

self.addEventListener('install', (e) => {
  e.waitUntil((async () => {
    const c = await caches.open(CACHE);
    // Chaque fichier est mis en cache séparément : un fichier manquant ne bloque pas l'installation
    await Promise.all(COQUILLE.concat(EXTERNES).map((u) => c.add(u).catch(() => {})));
    self.skipWaiting();
  })());
});

self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    const noms = await caches.keys();
    await Promise.all(noms.filter((n) => n !== CACHE).map((n) => caches.delete(n)));
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  // Données en direct : jamais mises en cache (Firebase, connexion, géocodage, IP, tuiles de carte)
  if (/firebaseio\.com|identitytoolkit|nominatim|ipify|tile\.openstreetmap/.test(url.hostname)) return;

  e.respondWith((async () => {
    const c = await caches.open(CACHE);
    const enCache = await c.match(req, { ignoreSearch: true });
    // Mise à jour en arrière-plan, mais on répond tout de suite avec la copie locale si elle existe
    const reseau = fetch(req).then((rep) => {
      if (rep && (rep.ok || rep.type === 'opaque')) c.put(req, rep.clone()).catch(() => {});
      return rep;
    }).catch(() => null);
    if (enCache) return enCache;
    const rep = await reseau;
    if (rep) return rep;
    if (req.mode === 'navigate') {
      const accueil = (await c.match('./index.html')) || (await c.match('./'));
      if (accueil) return accueil;
    }
    return new Response('', { status: 504, statusText: 'Hors connexion' });
  })());
});

// Toucher une notification ouvre / ramène l'application
self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  e.waitUntil((async () => {
    const fenetres = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    if (fenetres.length) return fenetres[0].focus();
    return self.clients.openWindow('./');
  })());
});
    
