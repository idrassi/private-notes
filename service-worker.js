/*!
 * Private Notes - Secure Personal Notes Manager
 * Author: Mounir IDRASSI <mounir@idrix.fr>
 * Date: 2024-11-20
 * License: MIT (https://opensource.org/license/MIT)
 */
const CACHE_NAME = "private-notes-v4";
const APP_VERSION = "1.75";
const urlsToCache = [
  "/",
  "/index.html",
  "/styles.css",
  "/script.js",
  "/manifest.json",
  "/icon-192x192.png",
  "/icon-512x512.png",
  "/favicon.ico",
  "/favicon-16x16.png",
  "/favicon-32x32.png",
  "/apple-touch-icon.png",
  "/private-notes-card.jpg",
  "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css",
  "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/webfonts/fa-solid-900.woff2",
  "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/webfonts/fa-solid-900.woff",
  "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/webfonts/fa-solid-900.ttf",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(urlsToCache)),
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    Promise.all([
      // Clean up old caches
      caches.keys().then((cacheNames) => {
        return Promise.all(
          cacheNames.map((cacheName) => {
            if (cacheName !== CACHE_NAME) {
              return caches.delete(cacheName);
            }
          }),
        );
      }),
      // Update cache with new files
      caches.open(CACHE_NAME).then((cache) => {
        return cache.addAll(urlsToCache);
      }),
      // Take control of all clients
      self.clients.claim(),
    ]),
  );
});

self.addEventListener("fetch", (event) => {
  if (event.request.url.endsWith("/version.txt")) {
    event.respondWith(
      fetch(`/version.txt?cacheBuster=${Date.now()}`)
        .then((response) => {
          if (!response.ok) {
            throw new Error("Network response was not ok");
          }
          return response;
        })
        .catch((error) => {
          console.error("Error fetching version:", error);
          return caches.match(event.request);
        }),
    );
    return;
  }

  event.respondWith(
    caches.match(event.request).then((cachedResponse) => {
      if (cachedResponse) {
        // Return cached response immediately
        return cachedResponse;
      }

      // If not in cache, fetch from network
      return fetch(event.request)
        .then((response) => {
          // Check if we received a valid response
          if (
            !response ||
            response.status !== 200 ||
            response.type !== "basic"
          ) {
            return response;
          }

          // Clone the response
          var responseToCache = response.clone();

          // Add the response to the cache
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(event.request, responseToCache);
          });

          return response;
        })
        .catch((error) => {
          console.error("Fetching failed:", error);
          // Return cached response if available, otherwise return the error
          return caches
            .match(event.request)
            .then((cachedResponse) => cachedResponse || Promise.reject(error));
        });
    }),
  );
});

// Listen for messages from the main script
self.addEventListener("message", (event) => {
  if (event.data && event.data.type === "CHECK_UPDATE") {
    fetch(`/version.txt?cacheBuster=${Date.now()}`)
      .then((response) => response.text())
      .then((serverVersion) => {
        if (serverVersion.trim() !== APP_VERSION) {
          // If versions don't match, trigger service worker update

          event.source.postMessage({
            type: "UPDATE_AVAILABLE",
            version: serverVersion.trim(),
          });
          event.source.postMessage({
            type: "updateReady",
          });
        }
      })
      .catch((error) => console.error("Error checking for updates:", error));
  }

  if (event.data === "skipWaiting") {
    self.skipWaiting();
  }
});
