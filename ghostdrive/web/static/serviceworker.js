/*
 * serviceworker.js -- Conservative offline-first service worker for GhostDrive.
 *
 * Static assets (/static/*) are served cache-first so the shell opens offline.
 * The index page is network-first with a cache fallback so deploys win quickly.
 * API responses (/api/*) and share downloads (/s/*) are NEVER cached -- they
 * carry vault data and must not linger in the browser cache.
 */

const CACHE_NAME = "ghostdrive-v1";
const OFFLINE_URL = "/";
const PRECACHE_URLS = [
  OFFLINE_URL,
  "/static/css/styles.css",
  "/static/js/app.js",
  "/static/favicon.svg",
  "/static/manifest.webmanifest",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches
      .open(CACHE_NAME)
      .then((cache) => cache.addAll(PRECACHE_URLS))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const request = event.request;
  if (request.method !== "GET") return;

  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;
  // Never cache API responses or share downloads -- vault data stays out of the cache.
  if (url.pathname.startsWith("/api/") || url.pathname.startsWith("/s/")) return;

  if (url.pathname.startsWith("/static/")) {
    // Cache-first for static assets; refresh in the background.
    event.respondWith(
      caches.open(CACHE_NAME).then(async (cache) => {
        const cached = await cache.match(request);
        const network = fetch(request)
          .then((response) => {
            if (response.ok) cache.put(request, response.clone());
            return response;
          })
          .catch(() => cached || Response.error());
        return cached || network;
      })
    );
    return;
  }

  if (request.mode === "navigate") {
    // Network-first for the app shell so a redeploy is picked up quickly.
    event.respondWith(
      fetch(request)
        .then((response) => {
          if (response.ok) {
            const copy = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(OFFLINE_URL, copy));
          }
          return response;
        })
        .catch(async () => (await caches.match(OFFLINE_URL)) || Response.error())
    );
  }
});
