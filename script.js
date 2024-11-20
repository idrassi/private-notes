/*!
 * Private Notes - Secure Personal Notes Manager
 * Author: Mounir IDRASSI <mounir@idrix.fr>
 * Date: 2024-11-20
 * License: MIT (https://opensource.org/license/MIT)
 */

(function () {
  "use strict";

  ////////////////////////////////
  // ======== Variables ========
  ////////////////////////////////

  let deferredPrompt;
  let updateNotificationShown = false;
  let refreshing = false;
  let currentSortOrder = "newest"; // Current sort order
  let currentFilterTags = [];
  let activeOptionPanel = null;
  let editNoteId = null; // Track the note being edited
  let editNoteContent = null; // Track the note content being edited
  let currentRightClickedNoteId = null;
  let touchTimeout = null;
  let activeSheet = null;
  const untitledPrefix = "Untitled Note";

  ////////////////////////////////
  // ======== Utilities ========
  ////////////////////////////////

  // Check if the app is running in an iOS device
  function isIOS() {
    return /iPad|iPhone|iPod/.test(navigator.userAgent) && !window.MSStream;
  }

  // Check if the app is running in Tauri
  function isTauri() {
    return typeof window.__TAURI__ !== "undefined";
  }

  // Simple UUID generator
  const generateUUID = () => {
    return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(
      /[xy]/g,
      function (c) {
        const r = (Math.random() * 16) | 0,
          v = c === "x" ? r : (r & 0x3) | 0x8;
        return v.toString(16);
      },
    );
  };

  // Helper function to convert ArrayBuffer to Base64 string
  function arrayBufferToBase64(buffer) {
    let binary = "";
    const bytes = new Uint8Array(buffer);
    bytes.forEach((b) => (binary += String.fromCharCode(b)));
    return window.btoa(binary);
  }

  // Helper function to convert Base64 string to Uint8Array
  function base64ToUint8Array(base64) {
    const binary = window.atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  // Debounce utility
  function debounce(func, delay) {
    let timeoutId;
    return function (...args) {
      clearTimeout(timeoutId);
      timeoutId = setTimeout(() => func.apply(this, args), delay);
    };
  }

  // Utility function to escape RegExp special characters in the query
  function escapeRegExp(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  // Adjust textarea height
  function adjustTextareaHeight(textarea) {
    textarea.style.height = "auto";
    textarea.style.height = textarea.scrollHeight + "px";
  }

  // Trap focus within a modal
  function trapFocus(modal) {
    const focusableElements = modal.querySelectorAll(
      "a[href], button, textarea, input, select",
    );
    const firstElement = focusableElements[0];
    const lastElement = focusableElements[focusableElements.length - 1];

    modal.addEventListener("keydown", function (e) {
      const isTabPressed = e.key === "Tab" || e.keyCode === 9;

      if (!isTabPressed) return;

      if (e.shiftKey) {
        // Shift + Tab
        if (document.activeElement === firstElement) {
          lastElement.focus();
          e.preventDefault();
        }
      } else {
        // Tab
        if (document.activeElement === lastElement) {
          firstElement.focus();
          e.preventDefault();
        }
      }
    });
  }

  // Convert string password to Uint8Array
  function stringToUint8Array(str) {
    return new TextEncoder().encode(str);
  }

  // Secure clearing of Uint8Array
  function secureArrayClear(array) {
    if (array) {
      array.fill(0); // Zero-fill the array
      array = null; // Remove reference
    }
  }

  ////////////////////////////////
  // ======== Encryption/Decryption Helper Functions ========
  async function encryptData(data, key) {
    const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV
    const encryptedData = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      data,
    );
    return {
      iv, // Store iv directly as Uint8Array
      data: new Uint8Array(encryptedData),
    };
  }

  async function decryptData(encryptedDataObj, key) {
    const decryptedData = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: encryptedDataObj.iv },
      key,
      encryptedDataObj.data,
    );
    return new Uint8Array(decryptedData);
  }

  // Password storage object with timeout handling
  const passwordManager = {
    currentPassword: null,
    tempPassword: null,
    timeoutId: null,
    lastSetTime: null,
    sessionKey: null,

    async initSessionKey() {
      if (this.sessionKey === null) {
        this.sessionKey = await window.crypto.subtle.generateKey(
          { name: "AES-GCM", length: 256 },
          false,
          ["encrypt", "decrypt"],
        );
      }
    },

    async clearSessionKey() {
      if (this.sessionKey) {
        this.sessionKey = null;
      }
    },

    async setPassword(password, remember = false) {
      await this.initSessionKey();
      // Convert password string to Uint8Array
      const passwordArray = stringToUint8Array(password);
      const encryptedPassword = await encryptData(
        passwordArray,
        this.sessionKey,
      );
      secureArrayClear(passwordArray); // Clear plaintext passwordArray

      if (remember) {
        // Clear any existing passwords first
        this.clearPasswords(false, true);
        this.currentPassword = encryptedPassword;
        this.lastSetTime = Date.now();
        this.setupTimeout();
      } else {
        this.clearTempPassword(true);
        this.tempPassword = encryptedPassword;
      }
    },

    getPassword(remembered = true) {
      if (remembered) {
        return this.currentPassword;
      } else {
        // Return the temp password if it exists and if not return the current password
        return this.tempPassword || this.currentPassword;
      }
    },

    clearPasswords(skipTemp = false, skipsessionKey = false) {
      if (this.currentPassword) {
        secureArrayClear(this.currentPassword.iv);
        secureArrayClear(this.currentPassword.data);
        this.currentPassword = null;
      }
      if (!skipTemp && this.tempPassword) {
        secureArrayClear(this.tempPassword.iv);
        secureArrayClear(this.tempPassword.data);
        this.tempPassword = null;
      }
      this.lastSetTime = null;
      if (this.timeoutId) {
        clearTimeout(this.timeoutId);
        this.timeoutId = null;
      }

      if (!skipsessionKey && !this.isPasswordAvailable()) {
        this.clearSessionKey();
      }
    },

    clearTempPassword(skipSessionKey = false) {
      if (this.tempPassword) {
        secureArrayClear(this.tempPassword.iv);
        secureArrayClear(this.tempPassword.data);
        this.tempPassword = null;
      }
      if (!skipSessionKey && !this.isPasswordAvailable()) {
        this.clearSessionKey();
      }
    },

    isPasswordExpired() {
      if (!this.lastSetTime) return true;
      const ONE_HOUR = 60 * 60 * 1000; // 1 hour in milliseconds
      return Date.now() - this.lastSetTime > ONE_HOUR;
    },

    setupTimeout() {
      if (this.timeoutId) {
        clearTimeout(this.timeoutId);
      }
      const ONE_HOUR = 60 * 60 * 1000;
      this.timeoutId = setTimeout(() => this.clearPasswords(true), ONE_HOUR);
    },

    isPasswordAvailable() {
      return !!this.currentPassword || !!this.tempPassword;
    },
  };

  ////////////////////////////////
  // ======== Storage ========
  ////////////////////////////////

  const db = {
    name: "PrivateNotesDB",
    version: 3, // Increased version to trigger onupgradeneeded for existing databases
    storeName: "notes",
    connection: null,

    async open() {
      return new Promise((resolve, reject) => {
        const request = indexedDB.open(this.name, this.version);
        request.onerror = () => reject(request.error);
        request.onsuccess = () => {
          this.connection = request.result;
          resolve();
        };
        request.onupgradeneeded = (event) => {
          const db = event.target.result;
          if (!db.objectStoreNames.contains(this.storeName)) {
            const store = db.createObjectStore(this.storeName, {
              keyPath: "id",
            });
            store.createIndex("_order", "_order", { unique: false });
          }
          if (!db.objectStoreNames.contains("settings")) {
            db.createObjectStore("settings");
          }
        };
      });
    },

    async getNotes() {
      return new Promise((resolve, reject) => {
        const transaction = this.connection.transaction(
          [this.storeName],
          "readonly",
        );
        const store = transaction.objectStore(this.storeName);
        const request = store.getAll();
        request.onerror = () => reject(request.error);
        request.onsuccess = () => {
          const notes = request.result;
          notes.sort((a, b) => a._order - b._order); // Sort by _order
          const cleanedNotes = notes.map(({ _order, ...note }) => note); // Remove _order
          resolve(cleanedNotes);
        };
      });
    },

    async saveNotes(notes) {
      return new Promise((resolve, reject) => {
        const transaction = this.connection.transaction(
          [this.storeName],
          "readwrite",
        );
        const store = transaction.objectStore(this.storeName);
        store.clear();
        notes.forEach((note, index) => {
          const noteWithOrder = { ...note, _order: index };
          store.add(noteWithOrder);
        });
        transaction.oncomplete = () => resolve();
        transaction.onerror = () => reject(transaction.error);
      });
    },

    async getSortOrderFromDB() {
      return new Promise((resolve, reject) => {
        const transaction = this.connection.transaction(
          ["settings"],
          "readonly",
        );
        const store = transaction.objectStore("settings");
        const request = store.get("sortOrder");
        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve(request.result || "newest");
      });
    },

    async saveSortOrderToDB(sortOrder) {
      return new Promise((resolve, reject) => {
        const transaction = this.connection.transaction(
          ["settings"],
          "readwrite",
        );
        const store = transaction.objectStore("settings");
        const request = store.put(sortOrder, "sortOrder");
        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve();
      });
    },

    async getIntroVisibilityFromDB() {
      return new Promise((resolve, reject) => {
        const transaction = this.connection.transaction(
          ["settings"],
          "readonly",
        );
        const store = transaction.objectStore("settings");
        const request = store.get("introHidden");
        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve(request.result || false);
      });
    },

    async saveIntroVisibilityToDB(isHidden) {
      return new Promise((resolve, reject) => {
        const transaction = this.connection.transaction(
          ["settings"],
          "readwrite",
        );
        const store = transaction.objectStore("settings");
        const request = store.put(isHidden, "introHidden");
        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve();
      });
    },
  };

  const storage = {
    db: null,

    async init() {
      if ("indexedDB" in window) {
        try {
          await db.open();
          this.db = db;
          console.log("Using IndexedDB for storage");
        } catch (error) {
          console.error("Error opening IndexedDB:", error);
          console.log("Falling back to localStorage");
          this.db = null;
        }
      } else {
        console.log("IndexedDB not supported, using localStorage");
        this.db = null;
      }
    },

    async getNotes() {
      if (this.db) {
        return await this.db.getNotes();
      } else {
        try {
          const notes = JSON.parse(localStorage.getItem("notes") || "[]");
          return notes;
        } catch (error) {
          throw new Error("Failed to parse notes from localStorage");
        }
      }
    },

    async saveNotes(notes) {
      if (this.db) {
        return await this.db.saveNotes(notes);
      } else {
        localStorage.setItem("notes", JSON.stringify(notes));
      }
    },

    async getSortOrder() {
      if (this.db) {
        return await this.db.getSortOrderFromDB();
      } else {
        return localStorage.getItem("currentSortOrder") || "newest";
      }
    },

    async saveSortOrder(sortOrder) {
      if (this.db) {
        await this.db.saveSortOrderToDB(sortOrder);
      } else {
        localStorage.setItem("currentSortOrder", sortOrder);
      }
    },

    async getIntroVisibility() {
      if (this.db) {
        return await this.db.getIntroVisibilityFromDB();
      } else {
        return localStorage.getItem("introHidden") === "true";
      }
    },

    async saveIntroVisibility(isHidden) {
      if (this.db) {
        await this.db.saveIntroVisibilityToDB(isHidden);
      } else {
        localStorage.setItem("introHidden", isHidden.toString());
      }
    },
  };

  ////////////////////////////////
  // ======== Encryption ========
  ////////////////////////////////

  const defaultPbkdf2Iterations = 1000000; // Default value
  const defaultPbkdf2Hash = "SHA-256"; // Default value

  async function deriveKey(
    password,
    salt,
    iterations = defaultPbkdf2Iterations,
    hash = defaultPbkdf2Hash,
  ) {
    // decrypt password
    const passwordBuffer = await decryptData(
      password,
      passwordManager.sessionKey,
    );

    try {
      const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        passwordBuffer,
        { name: "PBKDF2" },
        false,
        ["deriveBits", "deriveKey"],
      );

      return window.crypto.subtle.deriveKey(
        {
          name: "PBKDF2",
          salt: salt,
          iterations: iterations,
          hash: hash,
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"],
      );
    } finally {
      secureArrayClear(passwordBuffer);
    }
  }

  async function encryptNoteContent(content, key) {
    const encoder = new TextEncoder();
    const data = encoder.encode(content);
    const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV for AES-GCM

    const encryptedContent = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      key,
      data,
    );

    return {
      iv: arrayBufferToBase64(iv.buffer), // Encode IV as Base64
      encryptedData: arrayBufferToBase64(new Uint8Array(encryptedContent)), // Encode encrypted data as Base64
    };
  }

  async function encryptNote(note, password) {
    const salt = window.crypto.getRandomValues(new Uint8Array(32)); // 256-bit salt
    const pbkdf2Iterations = defaultPbkdf2Iterations;
    const pbkdf2Hash = defaultPbkdf2Hash;
    const key = await deriveKey(password, salt, pbkdf2Iterations, pbkdf2Hash);
    const encryptedContent = await encryptNoteContent(note.content, key);

    return {
      ...note,
      content: encryptedContent,
      salt: arrayBufferToBase64(salt.buffer), // Encode salt as Base64
      encrypted: true,
      pbkdf2Iterations: pbkdf2Iterations,
      pbkdf2Hash: pbkdf2Hash,
    };
  }

  async function decryptNoteContent(encryptedContent, key) {
    const iv = base64ToUint8Array(encryptedContent.iv); // Decode IV from Base64
    const encryptedData = base64ToUint8Array(encryptedContent.encryptedData); // Decode encrypted data from Base64

    const decryptedContent = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      key,
      encryptedData,
    );

    const decoder = new TextDecoder();
    return decoder.decode(decryptedContent);
  }

  ////////////////////////////////
  // ======== Notifications ========
  ////////////////////////////////

  // Notification System
  const notificationContainer = document.createElement("div");
  notificationContainer.id = "notification-container";
  document.body.appendChild(notificationContainer);

  const showNotification = (message, type = "info") => {
    const notification = document.createElement("div");
    notification.classList.add("notification", type);
    notification.textContent = message;

    notificationContainer.appendChild(notification);

    setTimeout(() => {
      notification.classList.add("fade-out");
      notification.addEventListener("animationend", () => {
        notificationContainer.removeChild(notification);
      });
    }, 3000);
  };

  ////////////////////////////////
  // ======== Modals ========
  ////////////////////////////////

  // Custom Confirm Modal
  function customConfirm(title, messageHTML) {
    return new Promise((resolve) => {
      const confirmModal = document.getElementById("confirm-modal");
      const confirmTitle = document.getElementById("confirm-title");
      const confirmMessage = document.getElementById("confirm-message");
      const confirmButton = document.getElementById("confirm-confirm");
      const cancelButton = document.getElementById("confirm-cancel");

      confirmTitle.textContent = title;
      confirmMessage.innerHTML = messageHTML;
      confirmModal.style.display = "flex";

      const handleConfirm = () => {
        cleanup();
        resolve(true);
      };

      const handleCancel = () => {
        cleanup();
        resolve(false);
      };

      const cleanup = () => {
        confirmModal.style.display = "none";
        confirmButton.removeEventListener("click", handleConfirm);
        cancelButton.removeEventListener("click", handleCancel);
      };

      confirmButton.addEventListener("click", handleConfirm);
      cancelButton.addEventListener("click", handleCancel);
    });
  }

  function clearStoredPassword() {
    passwordManager.clearPasswords();
  }

  // Password Modal Handling
  async function getPassword(
    requireConfirmation = true,
    forceUI = false,
    showError = false,
  ) {
    if (!forceUI) {
      const existingPassword = passwordManager.getPassword(false);
      if (existingPassword) {
        return { password: existingPassword, fromUI: false }; // true if using currentPassword, false if using tempPassword
      }
    }
    return await requestPassword(requireConfirmation, showError);
  }

  function requestPassword(requireConfirmation = true, showError = false) {
    return new Promise((resolve) => {
      const passwordModal = document.createElement("div");
      passwordModal.id = "password-modal";
      // Only show remember password checkbox when not requiring confirmation (i.e., for decryption)
      const rememberPasswordField = !requireConfirmation
        ? `
                <div>
                    <input type="checkbox" id="remember-password">
                    <label for="remember-password">Remember password</label>
                </div>
            `
        : "";
      // Conditionally render confirm password field
      const confirmPasswordField = requireConfirmation
        ? `
                <input type="password" id="password-confirm" placeholder="Confirm password">
                <span id="password-match-error" style="color: red; display: none;">Passwords do not match</span>
            `
        : "";

      passwordModal.innerHTML = `
            <div class="password-modal-content">
                <h2>Enter Password</h2>
                <input type="password" id="password-input" placeholder="Enter password">
                ${confirmPasswordField}
                <span id="password-error" style="color: red; ${showError ? "" : "display: none;"}">Incorrect password</span>
                <div style="display: flex; justify-content: space-between; margin-top: 10px;">
                    <button id="cancel-password">Cancel</button>
                    <button id="submit-password" disabled>Submit</button>
                </div>
                ${rememberPasswordField}
            </div>
            `;

      document.body.appendChild(passwordModal);

      const passwordInput = document.getElementById("password-input");
      const passwordConfirm = document.getElementById("password-confirm");
      const submitButton = document.getElementById("submit-password");
      const passwordMatchError = document.getElementById(
        "password-match-error",
      );
      const passwordError = document.getElementById("password-error");

      // Set focus on the password input
      setTimeout(() => passwordInput.focus(), 0);

      function checkPasswordsMatch() {
        if (requireConfirmation) {
          const match = passwordInput.value === passwordConfirm.value;
          // Show error message if passwords do not match only if confirmation is required
          passwordMatchError.style.display = match ? "none" : "block";
          submitButton.disabled = !match || passwordInput.value === "";
        } else {
          // Disable submit button if password is empty
          submitButton.disabled = passwordInput.value === "";
        }
      }

      async function handleSubmit() {
        const password = passwordInput.value;
        const rememberCtrl = document.getElementById("remember-password");
        const remember = rememberCtrl ? rememberCtrl.checked : false;

        await passwordManager.setPassword(password, remember);
        cleanup();
        resolve({
          password: passwordManager.getPassword(remember),
          fromUI: true,
        });
      }

      function handleOutsideClick(event) {
        if (event.target === passwordModal) {
          cleanup();
          resolve({ password: null, fromUI: true }); // Resolve with null password if cancelled
        }
      }

      function handleKeyDown(event) {
        if (event.key === "Escape") {
          cleanup();
          resolve({ password: null, fromUI: true }); // Resolve with null password if cancelled
        } else if (event.key === "Enter" && !submitButton.disabled) {
          handleSubmit();
        }
      }

      function cleanup() {
        passwordInput.removeEventListener("input", checkPasswordsMatch);
        // Remove event listener for confirm password field if it is present
        if (requireConfirmation) {
          passwordConfirm.removeEventListener("input", checkPasswordsMatch);
        }
        submitButton.removeEventListener("click", handleSubmit);
        passwordModal.removeEventListener("click", handleOutsideClick);
        document.removeEventListener("keydown", handleKeyDown);
        passwordModal.remove();
      }

      passwordInput.addEventListener("input", () => {
        checkPasswordsMatch(); // If applicable
        passwordError.style.display = "none"; // Hide error on typing
      });

      document
        .getElementById("cancel-password")
        .addEventListener("click", () => {
          cleanup();
          resolve({ password: null, fromUI: true }); // Resolve with null password if cancelled
        });

      // Add event listener to confirm password field if applicable
      if (requireConfirmation) {
        passwordConfirm.addEventListener("input", checkPasswordsMatch);
      }
      submitButton.addEventListener("click", handleSubmit);
      passwordModal.addEventListener("click", handleOutsideClick);
      document.addEventListener("keydown", handleKeyDown);
    });
  }

  ////////////////////////////////
  // ======== PWA Handling ========
  ////////////////////////////////

  // Install PWA
  window.addEventListener("beforeinstallprompt", (e) => {
    e.preventDefault();
    deferredPrompt = e;
    showInstallButton();
  });

  function showInstallButton() {
    const installButton = document.createElement("button");
    installButton.textContent = "Install App";
    installButton.id = "install-app-btn";
    installButton.className = "btn btn-install"; // Add appropriate classes
    installButton.addEventListener("click", () => {
      if (deferredPrompt) {
        deferredPrompt.prompt();
        deferredPrompt.userChoice.then((choiceResult) => {
          if (choiceResult.outcome === "accepted") {
            console.log("User accepted the install prompt");
          }
          deferredPrompt = null;
        });
      }
    });

    const header = document.querySelector("header");
    header.appendChild(installButton);
  }

  // Update Notification
  function showUpdateNotification(version) {
    const updateNotification = document.createElement("div");
    updateNotification.className = "update-notification";
    updateNotification.innerHTML = `
            <p>A new version (${version}) is available. Update now?</p>
            <button id="update-now">Update Now</button>
            <button id="update-later">Later</button>
        `;

    document.body.appendChild(updateNotification);

    document
      .getElementById("update-now")
      .addEventListener("click", async () => {
        updateNotification.remove();
        // Get the registration and tell the waiting service worker to skip waiting
        const registration = await navigator.serviceWorker.ready;
        if (registration.waiting) {
          registration.waiting.postMessage("skipWaiting");
        }
      });

    document.getElementById("update-later").addEventListener("click", () => {
      updateNotification.remove();
      updateNotificationShown = false;
    });
  }

  // Check for Updates
  function checkForUpdates() {
    if ("serviceWorker" in navigator && navigator.serviceWorker.controller) {
      navigator.serviceWorker.controller.postMessage({ type: "CHECK_UPDATE" });
    }
  }

  ////////////////////////////////
  // ======== Search ========
  ////////////////////////////////

  // Search functionality
  const searchInput = document.getElementById("search-input");
  const searchButton = document.getElementById("search-button");

  searchInput.addEventListener("input", debounce(performSearch, 300));
  searchButton.addEventListener("click", performSearch);

  async function performSearch() {
    const query = searchInput.value.toLowerCase().trim();
    if (query.length === 0) {
      hideSearchResults();
      return;
    }

    const notes = await getNotes();
    const searchResults = notes.filter((note) => {
      const titleMatch = note.title.toLowerCase().includes(query);
      const contentMatch = note.encrypted
        ? false
        : note.content.toLowerCase().includes(query);
      const tagMatch = note.tags.some((tag) =>
        tag.toLowerCase().includes(query),
      );
      return titleMatch || contentMatch || tagMatch;
    });

    displaySearchResults(searchResults, query);
  }

  function displaySearchResults(results, query) {
    let searchResultsContainer = document.getElementById("search-results");
    const searchContainer = document.querySelector(".search-container");

    if (!searchResultsContainer) {
      searchResultsContainer = document.createElement("div");
      searchResultsContainer.id = "search-results";
      searchResultsContainer.className = "search-results";
      searchContainer.appendChild(searchResultsContainer); // Append to search-container
    }

    searchResultsContainer.innerHTML = "";

    if (results.length === 0) {
      searchResultsContainer.innerHTML =
        '<div class="search-result-item">No results found</div>';
    } else {
      results.forEach((note) => {
        const resultItem = document.createElement("div");
        resultItem.className = "search-result-item";
        resultItem.innerHTML = `
                    <div class="search-result-title">${highlightMatch(note.title, query)}</div>
                    <div class="search-result-preview">${getPreview(note, query)}</div>
                `;
        resultItem.addEventListener("click", () => {
          viewNote(note.id);
          hideSearchResults();
        });
        searchResultsContainer.appendChild(resultItem);
      });
    }

    searchResultsContainer.style.display = "block";
  }

  function highlightMatch(text, query) {
    const regex = new RegExp(`(${escapeRegExp(query)})`, "gi");
    return text.replace(regex, "<mark>$1</mark>");
  }

  function getPreview(note, query) {
    if (note.encrypted) {
      return "[Encrypted]";
    }
    const index = note.content.toLowerCase().indexOf(query.toLowerCase());
    if (index === -1) {
      return note.content.substring(0, 50) + "...";
    }
    const start = Math.max(0, index - 20);
    const end = Math.min(note.content.length, index + query.length + 20);
    return (
      "..." + highlightMatch(note.content.substring(start, end), query) + "..."
    );
  }

  function hideSearchResults() {
    const container = document.getElementById("search-results");
    if (container) {
      container.style.display = "none";
    }
  }

  // Hide search results when clicking outside
  document.addEventListener("click", (event) => {
    const searchContainer = document.querySelector(".search-container");
    const searchResults = document.getElementById("search-results");
    if (searchResults && !searchContainer.contains(event.target)) {
      hideSearchResults();
    }
  });

  ////////////////////////////////
  // ======== Buttom Sheet ========
  ////////////////////////////////

  // Function to show a specific sheet
  function showSheet(sheetId) {
    const sheet = document.getElementById(`info-sheet-${sheetId}`);
    if (sheet) {
      // Reset scroll position of the sheet content
      const sheetContent = document.getElementById(`sheet-${sheetId}-content`);
      sheetContent.scrollTop = 0;
      // Force a reflow before adding the active class
      sheet.offsetHeight;
      sheet.classList.add("active");
      activeSheet = sheet;
      document.body.style.overflow = "hidden";
      // set focus to the div 'sheet-${sheetId}-content'
      sheetContent.focus();

      // Add event listener for clicking outside
      sheet.addEventListener("click", (e) => {
        if (e.target === sheet) {
          hideSheet();
        }
      });

      hideFAB();
    }
  }

  // Function to hide the active sheet
  function hideSheet() {
    if (activeSheet) {
      activeSheet.classList.remove("active");
      document.body.style.overflow = "";
      activeSheet = null;

      showFAB();
    }
  }

  function addBottomSheetHandlers() {
    // Handle bottom sheet interactions
    const sheets = document.querySelectorAll(".bottom-sheet");

    // Handle close buttons with both click and touch events
    const closeButtons = [
      document.getElementById("close-about-sheet"),
      document.getElementById("close-privacy-sheet"),
    ];

    closeButtons.forEach((button) => {
      if (!button) return; // Skip if button not found
      let touchStartTime;

      // Remove existing listeners
      button.removeEventListener("click", hideSheet);

      // Add touch feedback class
      button.addEventListener(
        "touchstart",
        (e) => {
          e.preventDefault();
          e.stopPropagation();
          touchStartTime = Date.now();
          button.classList.add("touch-active");
        },
        { passive: false },
      );

      button.addEventListener(
        "touchend",
        (e) => {
          e.preventDefault();
          e.stopPropagation();
          button.classList.remove("touch-active");

          // Prevent accidental double-taps
          const touchDuration = Date.now() - touchStartTime;
          if (touchDuration < 500) {
            hideSheet();
          }
        },
        { passive: false },
      );

      button.addEventListener("click", (e) => {
        e.stopPropagation();
        hideSheet();
      });

      // Handle touch cancel
      button.addEventListener("touchcancel", () => {
        button.classList.remove("touch-active");
      });
    });

    // Handle clicks outside the sheet content
    sheets.forEach((sheet) => {
      sheet.addEventListener("click", (e) => {
        if (e.target === sheet) {
          hideSheet();
        }
      });
    });

    // Handle escape key
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && activeSheet) {
        hideSheet();
      }
    });

    sheets.forEach((sheet) => {
      let startY = 0;
      let currentY = 0;
      let isDragging = false;

      function handleTouchStart(e) {
        if (!e.target.closest(".sheet-header")) return;
        isDragging = true;
        startY = e.touches[0].clientY;
        sheet.style.transition = "none";
        e.preventDefault();
      }

      function handleTouchMove(e) {
        if (!isDragging) return;

        currentY = e.touches[0].clientY;
        let deltaY = currentY - startY;

        // Only allow dragging down and limit the movement
        if (deltaY > 0) {
          isDragging = false;
          e.preventDefault();
          sheet.style.transition = "transform 0.3s ease-out";
          hideSheet();
        }
      }

      function handleTouchEnd() {
        if (!isDragging) return;

        isDragging = false;
        sheet.style.transition = "transform 0.3s ease-out";

        const deltaY = currentY - startY;

        if (deltaY > 0) {
          e.preventDefault();
          hideSheet();
        }
      }

      // Remove old listeners first
      sheet.removeEventListener("touchstart", handleTouchStart);
      sheet.removeEventListener("touchmove", handleTouchMove);
      sheet.removeEventListener("touchend", handleTouchEnd);

      // Add new listeners
      sheet.addEventListener("touchstart", handleTouchStart, {
        passive: false,
      });
      sheet.addEventListener("touchmove", handleTouchMove, { passive: false });
      sheet.addEventListener("touchend", handleTouchEnd);

      // Handle touch cancel
      sheet.addEventListener("touchcancel", handleTouchEnd);
    });
  }

  // Function to create and handle scroll indicators for bottom sheets
  function initializeScrollIndicators() {
    const sheets = ["about", "privacy"];

    sheets.forEach((sheetName) => {
      const sheetContent = document.getElementById(
        `sheet-${sheetName}-content`,
      );
      const sheet = document.getElementById(`info-sheet-${sheetName}`);

      // Create scroll indicator button
      const scrollIndicator = document.createElement("button");
      scrollIndicator.className = "scroll-indicator";
      scrollIndicator.innerHTML = '<i class="fas fa-arrow-down"></i>';
      scrollIndicator.setAttribute("aria-label", "Scroll to bottom");

      // Add to sheet content for relative positioning
      sheet.appendChild(scrollIndicator);

      // Function to check scroll position and toggle button visibility
      function updateScrollIndicator() {
        const isScrollable =
          sheetContent.scrollHeight > sheetContent.clientHeight;
        const isBottom =
          Math.ceil(sheetContent.scrollTop + sheetContent.clientHeight) >=
          sheetContent.scrollHeight;
        const isSheetActive = sheet.classList.contains("active");

        if (isScrollable && !isBottom && isSheetActive) {
          scrollIndicator.classList.add("visible");
        } else {
          scrollIndicator.classList.remove("visible");
        }
      }

      // Scroll to bottom when indicator is clicked
      scrollIndicator.addEventListener("click", () => {
        sheetContent.scrollTo({
          top: sheetContent.scrollHeight,
          behavior: "smooth",
        });
      });

      // Update indicator visibility on scroll
      sheetContent.addEventListener("scroll", updateScrollIndicator);

      // Update indicator when sheet visibility changes
      const observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
          if (
            mutation.type === "attributes" &&
            mutation.attributeName === "class"
          ) {
            if (!sheet.classList.contains("active")) {
              scrollIndicator.classList.remove("visible");
            } else {
              updateScrollIndicator();
            }
          }
        });
      });

      observer.observe(sheet, { attributes: true });

      // Update indicator visibility when sheet content might change
      const contentObserver = new ResizeObserver(updateScrollIndicator);
      contentObserver.observe(sheetContent);

      // Initial check
      updateScrollIndicator();

      // Clean up when sheet is hidden
      function onSheetHide() {
        scrollIndicator.classList.remove("visible");
      }

      // Add cleanup to hideSheet function
      const originalHideSheet = window.hideSheet;
      window.hideSheet = function () {
        originalHideSheet();
        onSheetHide();
      };
    });
  }

  ////////////////////////////////
  // ======== FAB Menu ========
  ////////////////////////////////

  function closeFABMenu() {
    const fabMenu = document.getElementById("fab-menu");
    fabMenu.classList.remove("show");
  }

  function hideFAB() {
    const fab = document.getElementById("main-fab");
    if (fab) {
      fab.style.display = "none";
    }
  }

  function showFAB() {
    const fab = document.getElementById("main-fab");
    if (fab) {
      fab.style.display = "block";
    }
  }

  function createFAB() {
    const fab = document.createElement("button");
    fab.id = "main-fab";
    fab.className = "fab";
    fab.innerHTML = '<i class="fas fa-plus"></i>';
    document.body.appendChild(fab);

    fab.addEventListener("click", toggleFABMenu);

    const fabMenu = document.createElement("div");
    fabMenu.id = "fab-menu";
    fabMenu.className = "fab-menu";
    fabMenu.innerHTML = `
            <button id="add-note-fab" class="fab-item" aria-label="Add Note">
                <i class="fas fa-plus"></i> Add Note
            </button>
            <button id="filter-fab" class="fab-item" aria-label="Filter">
                <i class="fas fa-filter"></i> Filter
            </button>
            <button id="export-notes-fab" class="fab-item" aria-label="Export Notes">
                <i class="fas fa-file-export"></i> Export Notes
            </button>
            <button id="import-notes-fab" class="fab-item" aria-label="Import Notes">
                <i class="fas fa-file-import"></i> Import Notes
            </button>
            <button id="clear-password-fab" class="fab-item" aria-label="Clear Remembered Password">
                <i class="fas fa-key"></i> Clear Password
            </button>
            <button id="about-fab" class="fab-item" aria-label="About">
                <i class="fas fa-info-circle"></i> About
            </button>
            <button id="privacy-fab" class="fab-item" aria-label="Privacy Policy">
                <i class="fas fa-shield-alt"></i> Privacy Policy
            </button>
        `;
    document.body.appendChild(fabMenu);

    // Add event listeners for existing FAB menu items
    document
      .getElementById("add-note-fab")
      .addEventListener("click", (event) => {
        event.stopPropagation();
        closeFilterMenu();
        addNote();
        closeFABMenu();
      });

    document.getElementById("filter-fab").addEventListener("click", (event) => {
      event.stopPropagation();
      toggleFilterMenu(event);
      closeFABMenu();
    });

    document
      .getElementById("export-notes-fab")
      .addEventListener("click", (event) => {
        event.stopPropagation();
        closeFilterMenu();
        exportNotes();
        closeFABMenu();
      });

    document
      .getElementById("import-notes-fab")
      .addEventListener("click", (event) => {
        event.stopPropagation();
        closeFilterMenu();
        const fileInput = document.createElement("input");
        fileInput.type = "file";
        fileInput.accept = "application/json";
        fileInput.onchange = importNotes;
        fileInput.click();
        closeFABMenu();
      });

    document
      .getElementById("clear-password-fab")
      .addEventListener("click", (event) => {
        event.stopPropagation();
        closeFilterMenu();
        clearStoredPassword();
        showNotification("Remembered password has been cleared.", "success");
        closeFABMenu();
      });

    // Add event listeners for new FAB menu items
    document.getElementById("about-fab").addEventListener("click", (event) => {
      event.stopPropagation();
      closeFilterMenu();
      showSheet("about");
      closeFABMenu();
    });

    document
      .getElementById("privacy-fab")
      .addEventListener("click", (event) => {
        event.stopPropagation();
        closeFilterMenu();
        showSheet("privacy");
        closeFABMenu();
      });
  }

  function toggleFABMenu(event) {
    event.stopPropagation();
    // Hide the filter menu if it's open
    closeFilterMenu();
    // Hide the active sheet if it's open
    hideSheet();
    // Hide search results if they are visible
    hideSearchResults();
    // Toggle the FAB menu
    const fabMenu = document.getElementById("fab-menu");
    // Show the "clear-password-fab" button only if a password is remembered
    const clearPasswordFab = document.getElementById("clear-password-fab");
    if (passwordManager.isPasswordAvailable()) {
      clearPasswordFab.style.display = "block";
    } else {
      clearPasswordFab.style.display = "none";
    }
    fabMenu.classList.toggle("show");
  }

  ////////////////////////////////
  // ======== Filter Menu ========
  ////////////////////////////////

  function toggleFilterMenu(event) {
    event.stopPropagation();
    const filterMenu = document.getElementById("filter-menu");
    const filterFab = document.getElementById("filter-fab");

    filterMenu.classList.toggle("show");
    filterFab.classList.toggle("active");

    // Close the main FAB menu
    document.getElementById("fab-menu").classList.remove("show");
  }

  function closeFilterMenu() {
    const filterMenu = document.getElementById("filter-menu");
    const filterFab = document.getElementById("filter-fab");
    filterMenu.classList.remove("show");
    filterFab.classList.remove("active");
  }

  function createFilterMenu() {
    const filterMenu = document.createElement("div");
    filterMenu.id = "filter-menu";
    filterMenu.className = "filter-menu";
    filterMenu.innerHTML = `
            <input type="text" id="tag-search" placeholder="Search tags...">
            <div id="popular-tags"></div>
            <div id="sort-options">
                <h3>Sort by</h3>
                <label><input type="radio" name="sort" value="newest"> Newest</label>
                <label><input type="radio" name="sort" value="oldest"> Oldest</label>
                <label><input type="radio" name="sort" value="a-z"> A-Z</label>
                <label><input type="radio" name="sort" value="z-a"> Z-A</label>
                <label><input type="radio" name="sort" value="manual"> Manual</label>
            </div>
            <button id="close-filter-menu">Close</button>
        `;
    document.body.appendChild(filterMenu);

    document
      .getElementById("tag-search")
      .addEventListener("input", handleTagSearch);
    document
      .querySelectorAll('#sort-options input[type="radio"]')
      .forEach((radio) => {
        radio.addEventListener("change", handleSortChange);
      });
    document
      .getElementById("close-filter-menu")
      .addEventListener("click", toggleFilterMenu);
  }

  // Handle tag search
  async function handleTagSearch(event) {
    const searchTerm = event.target.value.toLowerCase();
    const allTags = await getAllTags();
    const filteredTags = allTags.filter((tag) =>
      tag.toLowerCase().includes(searchTerm),
    );
    renderPopularTags(filteredTags);
  }

  // Handle sort change
  async function handleSortChange(event) {
    const sortValue = event.target.value;
    currentSortOrder = sortValue;
    await saveSortOrder(sortValue);
    // Implement sorting logic here
    await renderNotes(sortValue);
    // Save the current sort order (you might want to implement this function)
    await saveSortOrder(sortValue);
  }

  // Get all unique tags from notes
  async function getAllTags() {
    const notes = await getNotes();
    const tagsSet = new Set(notes.flatMap((note) => note.tags || []));
    return Array.from(tagsSet);
  }

  // Render popular tags
  function renderPopularTags(tags) {
    const popularTagsContainer = document.getElementById("popular-tags");
    if (popularTagsContainer) {
      popularTagsContainer.innerHTML = "";
      tags.forEach((tag) => {
        const tagChip = document.createElement("span");
        tagChip.className = "tag-chip";
        if (currentFilterTags.includes(tag)) {
          tagChip.classList.add("selected");
        }
        tagChip.textContent = tag;
        tagChip.addEventListener("click", (event) => filterByTag(event, tag));
        popularTagsContainer.appendChild(tagChip);
      });
    }
  }

  // Filter notes by tag
  async function filterByTag(event, tag) {
    event.stopPropagation();
    const tagIndex = currentFilterTags.indexOf(tag);
    if (tagIndex === -1) {
      currentFilterTags.push(tag);
    } else {
      currentFilterTags.splice(tagIndex, 1);
    }
    await renderNotes();
    updateActiveFilters();
  }

  // Update active filters display
  function updateActiveFilters() {
    const activeFiltersContainer = document.getElementById("active-filters");
    activeFiltersContainer.innerHTML = "";
    currentFilterTags.forEach((tag) => {
      const filterChip = document.createElement("span");
      filterChip.className = "filter-chip";
      filterChip.textContent = tag;
      filterChip.innerHTML += '<i class="fas fa-times"></i>';
      filterChip.addEventListener("click", async () => {
        const tagIndex = currentFilterTags.indexOf(tag);
        if (tagIndex !== -1) {
          currentFilterTags.splice(tagIndex, 1);
          await renderNotes();
          updateActiveFilters();
        }
      });
      activeFiltersContainer.appendChild(filterChip);
    });
  }

  ////////////////////////////////
  // ======== UI Rendering ========
  ////////////////////////////////

  // Function to handle intro section visibility
  async function handleIntroSection() {
    const introSection = document.getElementById("intro-text");
    const closeButton = introSection.querySelector(".close-intro");

    // Check if user has previously closed the intro
    const isIntroClosed = await storage.getIntroVisibility();

    if (isIntroClosed) {
      introSection.classList.add("hidden");
    }

    // Add click handler for close button
    closeButton.addEventListener("click", async () => {
      introSection.classList.add("hidden");
      await storage.saveIntroVisibility(true);
    });
  }

  // Render tags
  const renderTags = (tags) => {
    const tagsContainer = document.createElement("div");
    tagsContainer.classList.add("note-tags");
    tags.forEach((tag) => {
      const tagElement = document.createElement("span");
      tagElement.classList.add("tag");
      tagElement.textContent = tag;
      tagsContainer.appendChild(tagElement);
    });
    return tagsContainer;
  };

  // Function to compare tags arrays for equality
  const compareTags = (tags1, tags2) => {
    if (tags1.length !== tags2.length) return false;
    return tags1.every((tag) => tags2.includes(tag));
  };

  // Render Notes
  const renderNotes = async (sortBy = currentSortOrder) => {
    try {
      const allNotes = await getNotes();
      let notesToRender =
        currentFilterTags.length > 0
          ? allNotes.filter((note) =>
              currentFilterTags.every(
                (tag) => note.tags && note.tags.includes(tag),
              ),
            )
          : allNotes;

      // Sorting logic
      switch (sortBy) {
        case "newest":
          notesToRender.sort(
            (a, b) => new Date(b.lastModified) - new Date(a.lastModified),
          );
          break;
        case "oldest":
          notesToRender.sort(
            (a, b) => new Date(a.lastModified) - new Date(b.lastModified),
          );
          break;
        case "a-z":
          notesToRender.sort((a, b) => a.title.localeCompare(b.title));
          break;
        case "z-a":
          notesToRender.sort((a, b) => b.title.localeCompare(a.title));
          break;
        case "manual":
          // For manual sorting, we don't need to do anything as the notes are already in the desired order
          break;
      }

      const fragment = document.createDocumentFragment();
      for (const note of notesToRender) {
        const noteElement = document.createElement("div");
        noteElement.classList.add("note");
        noteElement.dataset.id = note.id;
        noteElement.style.backgroundColor = note.color || "#ffffff";

        const noteTitle = document.createElement("div");
        noteTitle.classList.add("note-preview-title");
        noteTitle.textContent = note.title;

        // Add lock icon for encrypted notes
        if (note.encrypted) {
          const lockIcon = document.createElement("i");
          lockIcon.classList.add("fas", "fa-lock", "encrypted-icon");
          lockIcon.setAttribute("aria-label", "Encrypted");
          noteTitle.appendChild(lockIcon);
        }

        const notePreview = document.createElement("div");
        notePreview.classList.add("note-preview");

        if (note.encrypted) {
          notePreview.textContent = "[Encrypted]";
          noteElement.classList.add("encrypted");
        } else {
          notePreview.textContent =
            note.content.substring(0, 50) +
            (note.content.length > 50 ? "..." : "");
        }

        // Add last modified date
        const lastModified = document.createElement("div");
        lastModified.classList.add("note-last-modified");
        lastModified.textContent = `Last modified: ${note.lastModified ? new Date(note.lastModified).toLocaleString() : "Never"}`;

        const noteActions = document.createElement("div");
        noteActions.classList.add("note-actions");

        // Add view button
        const viewButton = document.createElement("button");
        viewButton.type = "button";
        viewButton.textContent = "View";
        viewButton.classList.add("btn-note-action");
        viewButton.addEventListener("click", () => viewNote(note.id));

        const editButton = document.createElement("button");
        editButton.type = "button";
        editButton.textContent = "Edit";
        editButton.classList.add("btn-note-action");
        editButton.addEventListener("click", () => editNote(note.id));

        const duplicateButton = document.createElement("button");
        duplicateButton.type = "button";
        duplicateButton.textContent = "Duplicate";
        duplicateButton.classList.add("btn-note-action");
        duplicateButton.addEventListener("click", () => duplicateNote(note.id));

        const deleteButton = document.createElement("button");
        deleteButton.type = "button";
        deleteButton.textContent = "Delete";
        deleteButton.classList.add("btn-note-action");
        deleteButton.addEventListener("click", () => deleteNote(note.id));

        noteActions.appendChild(viewButton);
        noteActions.appendChild(editButton);
        noteActions.appendChild(duplicateButton);
        noteActions.appendChild(deleteButton);

        noteElement.appendChild(noteTitle);
        noteElement.appendChild(notePreview);
        if (note.tags && note.tags.length > 0) {
          noteElement.appendChild(renderTags(note.tags));
        }
        noteElement.appendChild(lastModified);
        noteElement.appendChild(noteActions);
        noteElement.addEventListener("dblclick", () => viewNote(note.id));

        fragment.appendChild(noteElement);
      }

      const notesContainer = document.getElementById("notes-container");
      notesContainer.innerHTML = "";
      notesContainer.appendChild(fragment);
      addDragAndDropHandlers(); // Re-add drag and drop handlers after rendering
      // Only call renderPopularTags if the filter menu exists
      if (document.getElementById("filter-menu")) {
        renderPopularTags(await getAllTags());
      }
      updateActiveFilters();
    } catch (error) {
      console.error("Error rendering notes:", error);
      showNotification("An error occurred while rendering notes.", "error");
    }
  };

  ////////////////////////////////
  // ======== Modals UI ========
  ////////////////////////////////

  // Note Modal Elements
  const noteModal = document.getElementById("note-modal");
  const noteModalContent = document.getElementById("note-modal-content");
  const closeModalButton = document.getElementById("close-modal");
  const noteForm = document.getElementById("note-form");
  const noteContentInput = document.getElementById("note-content");
  const noteColorInput = document.getElementById("note-color");
  const noteTagsInput = document.getElementById("note-tags-input");
  const encryptedCheckbox = document.getElementById("note-encrypted");
  const viewModal = document.getElementById("view-modal");
  const noteTitleInput = document.getElementById("note-title");

  // Function to show/hide option panels
  function toggleOptionPanel(panelId) {
    const panel = document.getElementById(panelId);
    if (activeOptionPanel && activeOptionPanel !== panel) {
      activeOptionPanel.style.display = "none";
    }
    panel.style.display = panel.style.display === "none" ? "block" : "none";
    activeOptionPanel = panel.style.display === "block" ? panel : null;

    // If the panel is encryption checkbox, update the button appearance
    if (panelId === "encrypt-checkbox") {
      updateEncryptButton();
    }

    // If the panel is tag input, focus on the input field
    if (panelId === "tag-input") {
      noteTagsInput.focus();
    }
  }

  // Function to hide all option panels: 'color-picker', 'tag-input', 'encrypt-checkbox'
  function hideAllOptionPanels() {
    const optionPanels = document.getElementsByClassName("option-panel");
    for (const panel of optionPanels) {
      panel.style.display = "none";
    }
    activeOptionPanel = null;
  }

  // Function to update the encryption button based on the checkbox state
  function updateEncryptButton() {
    const encryptButton = document.getElementById("encrypt-option");
    const isEncrypted = encryptedCheckbox.checked;

    if (isEncrypted) {
      encryptButton.classList.add("active-encryption");
      encryptButton.setAttribute("aria-label", "Encryption Enabled");
    } else {
      encryptButton.classList.remove("active-encryption");
      encryptButton.setAttribute("aria-label", "Encrypt Note");
    }
  }

  // Event listeners for option buttons
  document
    .getElementById("color-option")
    .addEventListener("click", () => toggleOptionPanel("color-picker"));
  document
    .getElementById("tag-option")
    .addEventListener("click", () => toggleOptionPanel("tag-input"));
  document
    .getElementById("encrypt-option")
    .addEventListener("click", () => toggleOptionPanel("encrypt-checkbox"));

  // Add event listener to the encryption checkbox to update the button in real-time
  encryptedCheckbox.addEventListener("change", () => {
    updateEncryptButton();
    toggleOptionPanel("encrypt-checkbox"); // Hide the encrypted checkbox panel
  });

  // Event listener to update the background color of the note content input
  // hide 'color-picker' panel when user cancels color selection
  noteColorInput.addEventListener("input", (e) => {
    noteContentInput.style.backgroundColor = e.target.value;
    noteModalContent.style.backgroundColor =
      noteContentInput.style.backgroundColor;

    if (!isIOS() && e.target.value === "") {
      hideAllOptionPanels();
    }
  });

  // Event listener to hide 'color-picker' panel when user finished picking a color
  noteColorInput.addEventListener("change", () => {
    if (!isIOS()) {
      hideAllOptionPanels();
    }
  });

  // Event listener to hide 'tag-input' panel when user presses ENTER
  noteTagsInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault(); // Prevent form submission when pressing ENTER in the tags input
      hideAllOptionPanels();
    }
  });

  // Show Note Modal
  const showModal = () => {
    hideAllOptionPanels();
    noteModal.style.display = "flex";
    noteContentInput.focus();
    // Reset and adjust textarea height
    noteContentInput.style.height = "auto";
    adjustTextareaHeight(noteContentInput);
    hideFAB(); // Hide the FAB when opening the modal

    // Update encryption button state based on the checkbox
    updateEncryptButton();
    trapFocus(noteModal);
  };

  // Hide Note Modal
  const hideModal = () => {
    noteModal.style.display = "none";
    showFAB(); // Show the FAB when closing the modal
  };

  // Add Note
  const addNote = () => {
    noteContentInput.value = "";
    noteColorInput.value = "#ffffff";
    noteContentInput.style.backgroundColor = "#ffffff";
    noteModalContent.style.backgroundColor =
      noteContentInput.style.backgroundColor;
    noteTagsInput.value = "";
    encryptedCheckbox.checked = false;
    editNoteId = null;
    editNoteContent = null;
    noteTitleInput.value = ""; // Clear title input
    showModal();
  };

  // Close Note Modal with saving
  const closeModal = async () => {
    if (await saveNote()) {
      hideModal();
      editNoteId = null;
      editNoteContent = null;
      passwordManager.clearTempPassword(); // Clear the temporary password
    }
  };

  // View Modal Close
  const closeViewModal = () => {
    viewModal.style.display = "none";
    showFAB(); // Show the FAB when closing the modal
    passwordManager.clearTempPassword(); // Clear the temporary password
  };

  // Close Modal When Clicking Outside Content
  noteModal.addEventListener("click", (event) => {
    if (event.target === noteModal) {
      closeModal();
    } else {
      // if the click is not within any of the option panels or
      if (
        !event.target.closest(".option-panel") &&
        !event.target.closest(".icon-button")
      ) {
        hideAllOptionPanels();
      }
    }
  });

  // Close View Modal When Clicking Outside Content
  viewModal.addEventListener("click", (event) => {
    if (event.target === viewModal) {
      closeViewModal();
    }
  });

  // Handle Escape Key to Close Modals
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      if (noteModal.style.display === "flex") {
        closeModal();
      }
      const confirmModal = document.getElementById("confirm-modal");
      if (confirmModal.style.display === "flex") {
        confirmModal.style.display = "none";
        // Additional cleanup if necessary
      }

      if (viewModal.style.display === "flex") {
        closeViewModal();
      }
    }
  });

  ////////////////////////////////
  // ======== Notes CRUD ========
  ////////////////////////////////

  // Retrieve notes from storage
  const getNotes = async () => await storage.getNotes();

  // Save notes to storage
  const saveNotes = async (notes) => await storage.saveNotes(notes);

  async function saveSortOrder(sortOrder) {
    await storage.saveSortOrder(sortOrder);
  }

  async function getSortOrder() {
    return await storage.getSortOrder();
  }

  // Save Note
  async function saveNote() {
    const content = noteContentInput.value;
    const title = noteTitleInput.value.trim();
    const color = noteColorInput.value;
    const inputTags = noteTagsInput.value
      .split(",")
      .map((tag) => tag.trim())
      .filter((tag) => tag !== "");
    const encrypted = encryptedCheckbox.checked;
    // ensure tags don't contain duplicates
    const tags = [...new Set(inputTags)];

    if (content) {
      try {
        let note = {
          id: editNoteId ? editNoteId : generateUUID(),
          title: title,
          content: content,
          color: color,
          tags: tags,
          lastModified: new Date().toISOString(),
          encrypted: encrypted,
        };

        const allNotes = await getNotes();
        const noteIndex = allNotes.findIndex((n) => n.id === note.id);
        const existingNote = noteIndex !== -1 ? allNotes[noteIndex] : null;
        if (title === "") {
          if (existingNote && existingNote.title.startsWith(untitledPrefix)) {
            note.title = existingNote.title;
          } else {
            note.title = getDefaultTitle(allNotes);
          }
        }

        if (editNoteId && existingNote) {
          // Skip saving if content, title, tags, color and encryption didn't change
          if (
            editNoteContent === note.content &&
            existingNote.title === note.title &&
            compareTags(existingNote.tags, note.tags) &&
            note.color === existingNote.color &&
            note.encrypted === existingNote.encrypted
          ) {
            return true;
          }
        }

        if (encrypted) {
          try {
            const { password, fromUI } = await getPassword();
            if (!password) {
              throw new Error("Password prompt cancelled by user");
            }
            note = await encryptNote(note, password);
          } catch (error) {
            console.error("Error encrypting note:", error);
            if (error.message !== "Password prompt cancelled by user") {
              showNotification(
                "Failed to encrypt note. Please check your password and try again.",
                "error",
              );
            }
            return false;
          }
        } else {
          note.content = content;
        }

        if (noteIndex !== -1) {
          allNotes[noteIndex] = note;
          showNotification("Note updated successfully.", "success");
        } else {
          allNotes.push(note);
          showNotification("Note added successfully.", "success");
        }

        await saveNotes(allNotes);
        await renderNotes();
        return true;
      } catch (error) {
        console.error("Error saving note:", error);
        showNotification("An error occurred while saving the note.", "error");
        return false;
      }
    } else {
      // if we are editing a note, ask for confirmation to delete the note
      // if we are creating a new note, just close the modal and return true
      if (editNoteId) {
        const confirmed = await customConfirm(
          "Confirm Deletion",
          "The new content of the note is empty. Do you want to delete it?",
        );
        if (confirmed) {
          await deleteNote(editNoteId, true);
          return true;
        }
      } else {
        return true;
      }
    }
  }

  // Get default title
  function getDefaultTitle(notes) {
    const untitledSet = new Set(
      notes
        .filter((note) => note.title.startsWith(untitledPrefix))
        .map((note) => note.title),
    );

    if (!untitledSet.has(untitledPrefix)) return untitledPrefix;

    let i = 1;
    while (untitledSet.has(`${untitledPrefix} ${i}`)) i++;
    return `${untitledPrefix} ${i}`;
  }

  // Export Notes
  const exportNotes = async () => {
    console.log("Export function called");
    try {
      const notes = await getNotes();
      console.log("Notes retrieved:", notes);

      if (notes.length === 0) {
        console.log("No notes to export");
        showNotification("There are no notes to export.", "warning");
        return;
      }

      const blob = new Blob([JSON.stringify(notes, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);

      const link = document.createElement("a");
      const now = new Date();
      const formattedDate = now
        .toLocaleString()
        .replace(/[:/]/g, "-")
        .replace(/, /g, "_"); // Format date to avoid invalid filename characters and include local time
      link.href = url;
      link.download = `PrivateNotes_${formattedDate}.json`;

      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);

      setTimeout(() => URL.revokeObjectURL(url), 100);

      console.log("Download triggered");
      showNotification("Notes exported successfully.", "success");
    } catch (error) {
      console.error("Error in exportNotes:", error);
      showNotification("Error occurred while exporting notes.", "error");
    }
  };

  // Import Notes
  const importNotes = async (event) => {
    const file = event.target.files[0];
    if (file && file.type === "application/json") {
      const reader = new FileReader();
      reader.onload = async (e) => {
        try {
          const importedNotes = JSON.parse(e.target.result);
          if (!Array.isArray(importedNotes)) {
            throw new Error("Invalid format: Expected an array of notes.");
          }
          const currentNotes = await getNotes();
          let overwriteAll = false;
          let skipAll = false;

          const processImport = async (index = 0) => {
            if (index >= importedNotes.length) {
              saveNotes(currentNotes);
              await renderNotes();
              showNotification("Notes imported successfully.", "success");
              return;
            }

            const importedNote = importedNotes[index];
            const existingNoteIndex = currentNotes.findIndex(
              (note) => note.id === importedNote.id,
            );

            const processNote = async (overwrite = false) => {
              if (overwrite || existingNoteIndex === -1) {
                const sanitizedNote = {
                  id: importedNote.id || generateUUID(),
                  title: importedNote.title,
                  content: null,
                  color: importedNote.color || "#ffffff",
                  tags: importedNote.tags,
                  lastModified:
                    importedNote.lastModified || new Date().toISOString(),
                  encrypted: importedNote.encrypted || false,
                };

                if (sanitizedNote.encrypted) {
                  sanitizedNote.salt = importedNote.salt;
                  (sanitizedNote.pbkdf2Iterations =
                    importedNote.pbkdf2Iterations || defaultPbkdf2Iterations), // Default value
                    (sanitizedNote.pbkdf2Hash =
                      importedNote.pbkdf2Hash || defaultPbkdf2Hash); // Default value
                }

                if (importedNote.encrypted) {
                  // Ensure content.iv and content.encryptedData are Base64 strings
                  sanitizedNote.content = {
                    iv: importedNote.content.iv,
                    encryptedData: importedNote.content.encryptedData,
                  };
                } else {
                  sanitizedNote.content = importedNote.content;
                }

                if (existingNoteIndex !== -1) {
                  currentNotes[existingNoteIndex] = sanitizedNote;
                } else {
                  currentNotes.push(sanitizedNote);
                }
              }
              await processImport(index + 1);
            };

            if (existingNoteIndex !== -1 && !overwriteAll && !skipAll) {
              const existingNote = currentNotes[existingNoteIndex];

              // Format dates
              const formatDate = (dateString) => {
                const options = {
                  year: "numeric",
                  month: "short",
                  day: "numeric",
                  hour: "2-digit",
                  minute: "2-digit",
                };
                return new Date(dateString).toLocaleString(undefined, options);
              };

              const existingNoteDate = formatDate(existingNote.lastModified);
              const importedNoteDate = formatDate(importedNote.lastModified);

              const confirmMessageHTML = `
                                <div style="text-align: left; margin-bottom: 15px;">
                                    A note with the title "<strong>${importedNote.title}</strong>" already exists.
                                </div>
                                
                                <div style="display: flex; justify-content: space-between; margin-bottom: 15px;">
                                    <div style="width: 48%;">
                                        <strong>Existing note:</strong>
                                        <div style="background-color: #f0f0f0; padding: 10px; border-radius: 5px; margin-bottom: 10px;">
                                            <div style="font-size: 0.9em; color: #666; margin-bottom: 5px;">
                                                Date: ${existingNoteDate}
                                            </div>
                                            <div style="max-height: 100px; overflow-y: auto;">
                                                ${existingNote.title}${existingNote.content.length > 100 ? "..." : ""}
                                            </div>
                                        </div>
                                    </div>
                                    <div style="width: 48%;">
                                        <strong>Imported note:</strong>
                                        <div style="background-color: #f0f0f0; padding: 10px; border-radius: 5px; margin-bottom: 10px;">
                                            <div style="font-size: 0.9em; color: #666; margin-bottom: 5px;">
                                                Date: ${importedNoteDate}
                                            </div>
                                            <div style="max-height: 100px; overflow-y: auto;">
                                                ${importedNote.title}${importedNote.content.length > 100 ? "..." : ""}
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                
                                <div>Do you want to overwrite the existing note with the imported one?</div>
                            `;

              const confirmOverwrite = await customConfirm(
                "Conflict Detected",
                confirmMessageHTML,
              );

              if (confirmOverwrite) {
                const applyToAll = await customConfirm(
                  "Apply to All Conflicts",
                  "<p>Do you want to overwrite all conflicting notes?</p>",
                );
                if (applyToAll) overwriteAll = true;
                await processNote(true);
              } else {
                const skipAllConflicts = await customConfirm(
                  "Skip All Conflicts",
                  "<p>Do you want to skip all conflicting notes?</p>",
                );
                if (skipAllConflicts) skipAll = true;
                await processNote(false);
              }
            } else {
              await processNote(overwriteAll);
            }
          };

          await processImport();
        } catch (error) {
          console.error("Error importing notes:", error);
          showNotification(
            "Failed to import notes. Please ensure the file is valid.",
            "error",
          );
        }
      };
      reader.readAsText(file);
    } else {
      showNotification("Please select a valid JSON file.", "warning");
    }
  };

  // Delete Note
  window.deleteNote = async (id, skipConfirmation = false) => {
    const allNotes = await getNotes();
    const noteToDelete = allNotes.find((note) => note.id === id);

    if (!noteToDelete) {
      showNotification("Note not found.", "error");
      return;
    }

    const confirmed =
      skipConfirmation ||
      (await customConfirm(
        "Confirm Deletion",
        `Are you sure you want to delete the note "${noteToDelete.title}"?`,
      ));

    if (confirmed) {
      try {
        const updatedNotes = allNotes.filter((note) => note.id !== id);
        await saveNotes(updatedNotes);
        await renderNotes();
        showNotification("Note deleted successfully.", "success");
      } catch (error) {
        console.error("Error deleting note:", error);
        showNotification("An error occurred while deleting the note.", "error");
      }
    }
  };

  // Duplicate Note
  window.duplicateNote = async (id) => {
    try {
      const allNotes = await getNotes();
      const noteToDuplicate = allNotes.find((note) => note.id === id);
      if (noteToDuplicate) {
        const duplicatedNote = {
          ...noteToDuplicate,
          id: generateUUID(),
          title: `${noteToDuplicate.title} (Copy)`,
          lastModified: new Date().toISOString(),
        };
        const sanitizedNote = {
          ...duplicatedNote,
          title: duplicatedNote.title,
          content: duplicatedNote.content,
          tags: duplicatedNote.tags,
        };
        allNotes.push(sanitizedNote);
        await saveNotes(allNotes);
        await renderNotes();
        showNotification("Note duplicated successfully.", "success");
      } else {
        showNotification("Note to duplicate not found.", "error");
      }
    } catch (error) {
      console.error("Error duplicating note:", error);
      showNotification(
        "An error occurred while duplicating the note.",
        "error",
      );
    }
  };

  // View Note
  async function viewNote(id) {
    const notes = await getNotes();
    const noteToView = notes.find((note) => note.id === id);
    if (noteToView) {
      const viewContent = document.getElementById("view-note-content");
      const viewTags = document.getElementById("view-note-tags");
      const viewLastModified = document.getElementById("view-note-modified");

      // Apply note color to textarea background
      viewContent.style.backgroundColor = noteToView.color || "#ffffff";

      if (noteToView.encrypted) {
        let decryptedContent = null;
        let decryptionFailed = false;
        let forceUI = false;
        let fromUIState = false;
        while (decryptedContent === null) {
          // Retry loop
          try {
            const { password, fromUI } = await getPassword(
              false,
              forceUI,
              decryptionFailed,
            ); // No confirmation, show error if previous attempt failed
            if (!password) {
              throw new Error("Password prompt cancelled by user");
            }
            fromUIState = fromUI;
            const salt = base64ToUint8Array(noteToView.salt);
            const iterations =
              noteToView.pbkdf2Iterations || defaultPbkdf2Iterations; // Default if not present
            const hash = noteToView.pbkdf2Hash || defaultPbkdf2Hash; // Default if not present
            const key = await deriveKey(password, salt, iterations, hash);
            decryptedContent = await decryptNoteContent(
              noteToView.content,
              key,
            );
          } catch (error) {
            console.error("Error decrypting note:", error);
            if (error.message === "Password prompt cancelled by user") {
              return;
            } else {
              forceUI = true;
              if (fromUIState) {
                decryptionFailed = true;
                passwordManager.clearTempPassword(); // Clear the temporary password
                showNotification(
                  "Incorrect password. Please try again.",
                  "error",
                );
              }
            }
          }
        }
        viewContent.textContent = decryptedContent; // Set content after successful decryption
      } else {
        viewContent.textContent = noteToView.content;
      }

      viewLastModified.textContent = `Last modified: ${new Date(noteToView.lastModified).toLocaleString()}`;
      document.getElementById("view-note-title").textContent = noteToView.title;
      // Clear previous tags
      viewTags.innerHTML = "";
      // Add each tag as a separate element
      noteToView.tags.forEach((tag) => {
        const tagElement = document.createElement("span");
        tagElement.classList.add("tag");
        tagElement.textContent = tag;
        viewTags.appendChild(tagElement);
      });

      // Add lock icon if encrypted
      if (noteToView.encrypted) {
        const lockIcon = document.createElement("i");
        lockIcon.classList.add("fas", "fa-lock", "encrypted-icon");
        lockIcon.setAttribute("aria-label", "Encrypted");
        document.getElementById("view-note-title").appendChild(lockIcon);
      }

      hideFAB(); // Hide the FAB when opening the modal
      viewModal.style.display = "flex";

      const editButton = document.getElementById("edit-note-btn");
      editButton.onclick = () => {
        editNote(id);
        viewModal.style.display = "none";
      };
    } else {
      showNotification("Note not found.", "error");
    }
  }

  // Edit Note
  async function editNote(id) {
    try {
      const notes = await getNotes();
      const noteToEdit = notes.find((note) => note.id === id);
      if (noteToEdit) {
        if (noteToEdit.encrypted) {
          let decryptedContent = null;
          let decryptionFailed = false;
          let forceUI = false;
          let fromUIState = false;
          while (decryptedContent === null) {
            // Retry loop
            try {
              const { password, fromUI } = await getPassword(
                false,
                forceUI,
                decryptionFailed,
              ); // No confirmation, show error if previous attempt failed
              if (!password) {
                return; // User cancelled, exit edit mode
              }
              fromUIState = fromUI;
              const salt = base64ToUint8Array(noteToEdit.salt);
              const iterations =
                noteToEdit.pbkdf2Iterations || defaultPbkdf2Iterations; // Default if not present
              const hash = noteToEdit.pbkdf2Hash || defaultPbkdf2Hash; // Default if not present
              const key = await deriveKey(password, salt, iterations, hash);
              decryptedContent = await decryptNoteContent(
                noteToEdit.content,
                key,
              );
            } catch (error) {
              console.error("Error decrypting note:", error);
              if (error.message !== "Password prompt cancelled by user") {
                forceUI = true;
                if (fromUIState) {
                  decryptionFailed = true;
                  passwordManager.clearTempPassword(); // Clear the temporary password
                  showNotification(
                    "Incorrect password. Please try again.",
                    "error",
                  );
                }
              } else {
                return; // User cancelled from password prompt
              }
            }
          }
          editNoteContent = decryptedContent;
        } else {
          editNoteContent = noteToEdit.content;
        }

        noteColorInput.value = noteToEdit.color || "#ffffff"; // Fixed color value
        noteContentInput.style.backgroundColor = noteToEdit.color || "#ffffff";
        noteModalContent.style.backgroundColor =
          noteContentInput.style.backgroundColor;
        noteTagsInput.value = noteToEdit.tags ? noteToEdit.tags.join(", ") : "";
        encryptedCheckbox.checked = noteToEdit.encrypted;
        noteTitleInput.value = noteToEdit.title;
        noteContentInput.value = editNoteContent;
        editNoteId = id;
        showModal();
        adjustTextareaHeight(noteContentInput);
      } else {
        showNotification("Note to edit not found.", "error");
      }
    } catch (error) {
      console.error("Error editing note:", error);
      showNotification("An error occurred while editing the note.", "error");
    }
  }

  ////////////////////////////////
  // ======== Context Menu ========
  ////////////////////////////////

  // Create references to context menus
  const noteContextMenu = document.getElementById("note-context-menu");

  // Function to determine if system context menu should be allowed
  function shouldAllowSystemContextMenu(event) {
    // Define selectors for elements where custom context menu should be disabled
    const excludedSelectors = [
      "#search-input",
      "#note-title",
      "#note-content",
      "#note-tags-input",
      "#view-note-title",
      "#view-note-content",
      "#password-input",
      "#password-confirm",
      "#tag-search",
    ];

    // Check if the event target or any of its parents match the excluded selectors
    for (const selector of excludedSelectors) {
      const matchedElement = event.target.closest(selector);
      if (matchedElement) {
        return true; // Allow system context menu on excluded elements
      }
    }

    return false; // Use custom context menu
  }

  // Function to show context menu at the specified coordinates
  function showContextMenu(menu, x, y) {
    // First hide all context menus
    hideContextMenus();

    // Then show and position the requested menu
    menu.style.display = "block";
    menu.style.left = "0";
    menu.style.top = "0";

    // Get menu dimensions
    const menuWidth = menu.offsetWidth;
    const menuHeight = menu.offsetHeight;

    // Get viewport dimensions
    const viewportWidth = window.innerWidth;
    const viewportHeight = window.innerHeight;

    // Get scroll position
    const scrollY = window.scrollY;
    const scrollX = window.scrollX;

    // Calculate positions ensuring menu stays within viewport
    let finalX = x;
    let finalY = y;

    // Adjust horizontal position if menu would overflow viewport
    if (x + menuWidth > viewportWidth + scrollX) {
      finalX = viewportWidth + scrollX - menuWidth;
    }

    // Adjust vertical position if menu would overflow viewport
    if (y + menuHeight > viewportHeight + scrollY) {
      finalY = y - menuHeight;
    }

    // Ensure menu doesn't go off the left or top of the viewport
    finalX = Math.max(scrollX, finalX);
    finalY = Math.max(scrollY, finalY);

    // Apply the calculated position
    menu.style.left = `${finalX}px`;
    menu.style.top = `${finalY}px`;
  }

  // Function to hide all context menus
  function hideContextMenus() {
    noteContextMenu.style.display = "none";
    currentRightClickedNoteId = null;
    if (touchTimeout) {
      clearTimeout(touchTimeout);
      touchTimeout = null;
    }
  }

  // Event listener to hide context menus on click elsewhere
  document.addEventListener("click", (event) => {
    hideContextMenus();
    closeFABMenu(); // Close FAB menu if open
    // hide sheet if clicked outside
    if (event.target.closest(".bottom-sheet") === null) {
      // don't hide the sheet if the click is on the scroll indicator
      if (event.target.closest(".scroll-indicator") === null) {
        hideSheet();
      }
    }
  });

  // Prevent the default context menu from appearing
  document.addEventListener("contextmenu", (event) => {
    hideContextMenus();
    closeFABMenu(); // Close FAB menu if open
    // hide sheet if clicked outside
    if (event.target.closest(".bottom-sheet") === null) {
      hideSheet();
    }
    // hide search results if clicked outside
    if (event.target.closest(".search-results") === null) {
      hideSearchResults();
    }
    if (shouldAllowSystemContextMenu(event)) {
      return; // Allow system context menu
    }
    event.preventDefault();

    // if the right-clicked element is a note action button, don't show the context menu
    if (event.target.closest(".btn-note-action")) {
      return;
    }

    const target = event.target.closest(".note");
    const isNote = !!target;

    const x = event.pageX;
    const y = event.pageY;

    if (isNote) {
      showContextMenu(noteContextMenu, x, y);
      currentRightClickedNoteId = target.dataset.id;
    }
  });

  // ===== Mobile Long-Press Handling ===== //

  document.addEventListener(
    "touchstart",
    (event) => {
      // Only handle touch events on notes or areas where we want context menu
      const target =
        event.target.closest(".note") ||
        event.target.closest("#notes-container");

      // If not touching a note or the notes container, allow default behavior
      if (!target) {
        return;
      }

      if (event.touches.length !== 1) {
        return;
      }

      if (shouldAllowSystemContextMenu(event)) {
        return;
      }

      const touch = event.touches[0];
      let moved = false;

      // Track if the touch moves
      const touchMoveHandler = () => {
        moved = true;
        if (touchTimeout) {
          clearTimeout(touchTimeout);
          touchTimeout = null;
        }
      };

      // Clean up event listeners
      const cleanupHandlers = () => {
        document.removeEventListener("touchmove", touchMoveHandler);
        document.removeEventListener("touchend", cleanupHandlers);
        document.removeEventListener("touchcancel", cleanupHandlers);
        if (touchTimeout) {
          clearTimeout(touchTimeout);
          touchTimeout = null;
        }
      };

      // Add temporary event listeners
      document.addEventListener("touchmove", touchMoveHandler, {
        passive: true,
      });
      document.addEventListener("touchend", cleanupHandlers, { passive: true });
      document.addEventListener("touchcancel", cleanupHandlers, {
        passive: true,
      });

      touchTimeout = setTimeout(() => {
        if (!moved) {
          const x = touch.clientX + window.scrollX;
          const y = touch.clientY + window.scrollY;

          if (target.classList.contains("note")) {
            showContextMenu(noteContextMenu, x, y);
            currentRightClickedNoteId = target.dataset.id;
          }
        }
      }, 500);
    },
    { passive: true },
  ); // Make the touchstart handler passive

  // ===== Bind Context Menu Actions ===== //

  // Note Context Menu Actions
  function bindContextMenuActions() {
    document.getElementById("context-view").addEventListener("click", () => {
      if (currentRightClickedNoteId) {
        viewNote(currentRightClickedNoteId);
        hideContextMenus();
      }
    });

    document.getElementById("context-edit").addEventListener("click", () => {
      if (currentRightClickedNoteId) {
        editNote(currentRightClickedNoteId);
        hideContextMenus();
      }
    });

    document
      .getElementById("context-duplicate")
      .addEventListener("click", () => {
        if (currentRightClickedNoteId) {
          duplicateNote(currentRightClickedNoteId);
          hideContextMenus();
        }
      });

    document
      .getElementById("context-delete")
      .addEventListener("click", async () => {
        if (currentRightClickedNoteId) {
          await deleteNote(currentRightClickedNoteId);
          hideContextMenus();
        }
      });
  }

  ////////////////////////////////
  // ======== Drag & Drop ========
  ////////////////////////////////

  function addDragAndDropHandlers() {
    const notesContainer = document.getElementById("notes-container");
    let draggedItem = null;
    const notes = document.querySelectorAll(".note");
    notes.forEach((note) => {
      note.setAttribute("draggable", "true");

      note.addEventListener("dragstart", (e) => {
        draggedItem = note;
        setTimeout(() => {
          note.classList.add("dragging");
        }, 0);
      });

      note.addEventListener("dragend", () => {
        setTimeout(() => {
          note.classList.remove("dragging");
          draggedItem = null;
        }, 0);
      });

      note.addEventListener("dragover", (e) => {
        e.preventDefault();
      });

      note.addEventListener("dragenter", (e) => {
        e.preventDefault();
        if (note !== draggedItem) {
          note.classList.add("drag-over");
        }
      });

      note.addEventListener("dragleave", () => {
        note.classList.remove("drag-over");
      });

      const saveNotesOrder = async () => {
        const noteElements = document.querySelectorAll(".note");
        const orderedNoteIds = Array.from(noteElements).map(
          (note) => note.dataset.id,
        );
        const allNotes = await getNotes();

        // Create a new array with the correct order
        const orderedNotes = orderedNoteIds.map((id) =>
          allNotes.find((note) => note.id === id),
        );

        // Add any notes that aren't currently displayed (due to filtering) to the end
        allNotes.forEach((note) => {
          if (!orderedNotes.some((orderedNote) => orderedNote.id === note.id)) {
            orderedNotes.push(note);
          }
        });

        await saveNotes(orderedNotes);
      };

      note.addEventListener("drop", async (e) => {
        e.preventDefault();
        note.classList.remove("drag-over");
        if (note !== draggedItem) {
          const allNotes = [...notesContainer.querySelectorAll(".note")];
          const draggedIndex = allNotes.indexOf(draggedItem);
          const targetIndex = allNotes.indexOf(note);

          if (draggedIndex < targetIndex) {
            notesContainer.insertBefore(draggedItem, note.nextSibling);
          } else {
            notesContainer.insertBefore(draggedItem, note);
          }

          // Set sort order to manual
          currentSortOrder = "manual";

          // Update the sort option in the UI
          document.querySelector('input[name="sort"][value="manual"]').checked =
            true;

          // Save the new order
          await saveSortOrder("manual");

          // Save the new order
          await saveNotesOrder();

          // Re-render notes to ensure consistency
          await renderNotes();
        }
      });
    });
  }

  ////////////////////////////////
  // ======== Event Listeners ========
  ////////////////////////////////

  function startUpdateCheck() {
    // Check immediately
    checkForUpdates();

    // Then check every 30 minutes
    setInterval(checkForUpdates, 30 * 60 * 1000);
  }

  // Event listeners for note modal buttons
  document.addEventListener("DOMContentLoaded", async () => {
    // Service Worker Registration. Only register if not running in Tauri otherwise a startup delay wil be introduced
    if (!isTauri() && "serviceWorker" in navigator) {
      try {
        const registration =
          await navigator.serviceWorker.register("/service-worker.js");
        console.log(
          "Service Worker registered successfully:",
          registration.scope,
        );

        // Handle updates to the registered service worker
        registration.addEventListener("updatefound", () => {
          const newWorker = registration.installing;
          newWorker.addEventListener("statechange", () => {
            if (
              newWorker.state === "installed" &&
              navigator.serviceWorker.controller
            ) {
              // New service worker is installed but waiting
              checkForUpdates();
            }
          });
        });

        // If there's already a waiting worker, check for updates
        if (registration.waiting) {
          checkForUpdates();
        }

        // Handle controller changes
        navigator.serviceWorker.addEventListener("controllerchange", () => {
          if (!refreshing) {
            refreshing = true;
            window.location.reload();
          }
        });

        startUpdateCheck();
      } catch (error) {
        console.log("Service Worker registration failed:", error);
      }

      // Handle messages from service worker
      navigator.serviceWorker.addEventListener("message", (event) => {
        if (
          event.data.type === "UPDATE_AVAILABLE" &&
          !updateNotificationShown
        ) {
          updateNotificationShown = true;
          showUpdateNotification(event.data.version);
        }
      });
    }

    document.getElementById("read-more").addEventListener("click", function () {
      var fullIntro = document.getElementById("intro-full");
      var readMoreBtn = document.getElementById("read-more");
      if (fullIntro.style.display === "none") {
        fullIntro.style.display = "inline";
        readMoreBtn.textContent = "Read Less";
      } else {
        fullIntro.style.display = "none";
        readMoreBtn.textContent = "Read More";
      }
    });

    closeModalButton.addEventListener("click", async () => {
      await closeModal();
    });

    document
      .getElementById("close-view-modal")
      .addEventListener("click", () => {
        closeViewModal();
      });

    // Add auto-resize for note content textarea
    noteContentInput.addEventListener("input", function () {
      adjustTextareaHeight(this);
    });

    // Add event listener for buttom sheets
    addBottomSheetHandlers();

    initializeScrollIndicators();
    document.addEventListener('dblclick', (event) => {
      // Allow double click only if the clicked element is a note or is inside a note
      if (!event.target.closest('.note')) {
          event.preventDefault();
          event.stopPropagation();
      }
    }, true);
    try {
      await initializeApp();
      console.log("App initialized successfully");

      // ===== Bind Context Menu Actions ===== //
      bindContextMenuActions();
    } catch (error) {
      console.error("Error initializing app:", error);
      showNotification(
        "An error occurred while initializing the app.",
        "error",
      );
    }
  });

  window.addEventListener("beforeunload", () => {
    clearStoredPassword();
  });

  ////////////////////////////////
  // ======== Initialization ========
  ////////////////////////////////

  async function initializeApp() {
    createFAB();
    createFilterMenu();
    updateActiveFilters();
    try {
      await storage.init();
      console.log("Storage initialized");
      await handleIntroSection();
      currentSortOrder = await getSortOrder();
      await renderNotes(currentSortOrder);
      console.log("Notes rendered");
    } catch (error) {
      console.error("Error initializing storage or rendering notes:", error);
      showNotification(
        "An error occurred while initializing the app.",
        "error",
      );
      throw error;
    }

    // Bind note modal submit
    noteForm.addEventListener("submit", async (e) => {
      e.preventDefault(); // Always prevent default form submission
    });
  }

  ////////////////////////////////
  // ======== Additional Handlers ========
  ////////////////////////////////

  // Notification Modal
  const confirmModal = document.getElementById("confirm-modal");
  confirmModal.addEventListener("click", (event) => {
    if (event.target === confirmModal) {
      confirmModal.style.display = "none";
    }
  });
})();
