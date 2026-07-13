/* Linkmoth dashboard — Web Push + offline app-shell service worker.
 *
 * Only the static shell (this page, the manifest, the icons) is cached, so
 * the app still opens instantly and works with no network. Nothing under
 * /api/ is ever cached: Linkmoth is a live network-diagnosis tool, and
 * serving a stale diagnosis while offline would be actively misleading.
 */
const SHELL_CACHE = "linkmoth-shell-v1";
const SHELL_URLS = ["/", "/manifest.webmanifest", "/linkmoth.svg", "/linkmoth-white.ico"];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(SHELL_CACHE)
      .then((cache) => cache.addAll(SHELL_URLS))
      .then(() => self.skipWaiting()),
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys()
      .then((names) => Promise.all(
        names.filter((name) => name !== SHELL_CACHE).map((name) => caches.delete(name)),
      ))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== "GET" || url.origin !== self.location.origin) return;
  if (!SHELL_URLS.includes(url.pathname)) return;

  // Stale-while-revalidate: instant load from cache, refreshed in the
  // background for next time, falling back to cache alone when offline.
  event.respondWith(
    caches.match(event.request).then((cached) => {
      const network = fetch(event.request).then((response) => {
        if (response.ok) {
          caches.open(SHELL_CACHE).then((cache) => cache.put(event.request, response.clone()));
        }
        return response;
      }).catch(() => cached);
      return cached || network;
    }),
  );
});

self.addEventListener("push", (event) => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch (e) {
    data = { title: "Linkmoth", body: event.data ? event.data.text() : "" };
  }
  const title = data.title || "Linkmoth";
  const options = {
    body: data.body || "",
    icon: "/linkmoth.svg",
    badge: "/linkmoth.svg",
    tag: data.tag || "linkmoth",
    data: { url: data.url || "/" },
    renotify: true,
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const target = (event.notification.data && event.notification.data.url) || "/";
  event.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((clients) => {
      for (const client of clients) {
        if ("focus" in client) {
          return client.focus();
        }
      }
      if (self.clients.openWindow) {
        return self.clients.openWindow(target);
      }
      return undefined;
    }),
  );
});
