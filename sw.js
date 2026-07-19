/* Linkmoth dashboard — Web Push + offline app-shell service worker.
 *
 * Only the static shell (this page, the manifest, the icons) is cached, so
 * the app still opens instantly and works with no network. Nothing under
 * /api/ is ever cached: Linkmoth is a live network-diagnosis tool, and
 * serving a stale diagnosis while offline would be actively misleading.
 */
const SHELL_CACHE = "linkmoth-shell-v3";
const SHELL_URLS = [
  "/",
  "/manifest.webmanifest",
  "/linkmoth.svg",
  "/linkmoth-white.ico",
  "/linkmoth-mark-white.svg",
  "/linkmoth-icon-192.png",
  "/linkmoth-icon-512.png",
  "/linkmoth-maskable.svg",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(SHELL_CACHE)
      .then((cache) =>
        // The document is the one asset the offline shell cannot live
        // without; a missing icon must not abort the whole install.
        cache.add("/").then(() => Promise.allSettled(
          SHELL_URLS.filter((u) => u !== "/").map((u) => cache.add(u)),
        )))
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

  // Network-first while online: always try a fresh fetch so an upgraded
  // shell shows up immediately, updating the cache as it goes. Only fall
  // back to the cached copy when the network is unavailable.
  event.respondWith(
    fetch(event.request).then((response) => {
      // Clone synchronously, before the caller starts reading the body we
      // return below — cloning after that (e.g. inside the caches.open()
      // callback) races the body stream and intermittently throws.
      const copy = response.ok ? response.clone() : null;
      if (copy) {
        caches.open(SHELL_CACHE).then((cache) => cache.put(event.request, copy));
      }
      return response;
    }).catch(() => caches.match(event.request)),
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
