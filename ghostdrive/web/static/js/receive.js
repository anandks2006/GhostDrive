/*
 * receive.js -- Zero-knowledge envelope receiver for /e/{token} share links.
 *
 * Decrypts the GDSHARE1 envelope entirely in this browser with WebCrypto:
 *
 *   passphrase --PBKDF2-SHA256(600k)--> wrap key --AES-GCM--> envelope key
 *   envelope key --AES-256-GCM per 64 KiB segment--> plaintext Blob -> download
 *
 * The server only ever sees ciphertext; the passphrase never leaves the page.
 *
 * Byte layout MUST stay in sync with ghostdrive/services/sharing.py:
 *
 *   "GDSHARE1" | uint32-BE header length | canonical JSON header |
 *   for each segment i: ciphertext(<= 65536 bytes) || 16-byte GCM tag
 *
 *   nonce_i = nonce_prefix (4 bytes) || uint64-BE(i)
 *   aad_i   = uint64-BE(i)   -- per-segment AAD: a reordered, dropped or
 *                               duplicated segment fails to authenticate
 *                               instead of silently decoding wrong.
 *
 * Vanilla JS, no build step, no dependencies.
 */
(function () {
  "use strict";

  var MAGIC = "GDSHARE1";
  var textEnc = new TextEncoder();
  var textDec = new TextDecoder();

  var statusEl = document.getElementById("gd-status");
  var form = document.getElementById("gd-unlock");
  var passInput = document.getElementById("gd-passphrase");
  var button = document.getElementById("gd-decrypt");

  function setStatus(message, kind) {
    statusEl.textContent = message;
    statusEl.className = kind || ""; // "", "error" or "ok"
  }

  // Burned / revoked / expired links: surface the server's own message in a
  // dedicated <div> so the failure is readable even though decryption never
  // started (plain DOM, no framework).  Burn-after-read links answer 410
  // here the moment a second party tries a second fetch.
  function showHeaderError(message) {
    setStatus(message, "error");
    var box = document.getElementById("gd-error");
    if (!box) {
      box = document.createElement("div");
      box.id = "gd-error";
      box.setAttribute("role", "alert");
      document.body.appendChild(box);
    }
    box.textContent = message;
  }

  // base64 -> Uint8Array (atob is synchronous and fine for these sizes).
  function b64bytes(s) {
    var bin = atob(s);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  // PBKDF2 is cheap enough here because it only has to protect 32 bytes of
  // uniformly random key — not hundreds of megabytes of file data.
  async function deriveWrapBits(passphrase, salt, iterations) {
    var base = await crypto.subtle.importKey(
      "raw", textEnc.encode(passphrase), "PBKDF2", false, ["deriveBits"]
    );
    return crypto.subtle.deriveBits(
      { name: "PBKDF2", salt: salt, iterations: iterations, hash: "SHA-256" },
      base,
      256
    );
  }

  form.addEventListener("submit", async function (event) {
    event.preventDefault();
    var passphrase = passInput.value;
    if (!passphrase) {
      setStatus("Enter the share passphrase.", "error");
      return;
    }
    button.disabled = true;
    var wrapBits = null;      // raw PBKDF2 output (wiped in finally)
    var envelopeKeyRaw = null; // unwrapped AES key bytes (wiped in finally)
    try {
      setStatus("Fetching encrypted envelope…", "");
      var token = document.body.dataset.token;
      var headerRes = await fetch(
        "/api/public/envelope/" + encodeURIComponent(token)
      );
      var served = await headerRes.json().catch(function () { return {}; });
      if (!headerRes.ok) {
        // Burned (410), revoked/expired (403) or unknown (404): show the
        // server's own message instead of attempting decryption.
        showHeaderError(served.detail || "This share link is unavailable.");
        return;
      }

      var blobRes = await fetch(served.envelope_url);
      if (!blobRes.ok) {
        // A burn-after-read link can be burned between the header fetch and
        // the blob fetch (410 raced us) — surface the server's detail if any.
        var blobErr = await blobRes.json().catch(function () { return {}; });
        throw new Error(blobErr.detail || "Could not download the encrypted envelope.");
      }
      var raw = await blobRes.arrayBuffer();

      // The header embedded in the blob is the single source of truth for
      // the crypto parameters (the JSON above only supplies envelope_url).
      if (raw.byteLength < 12 ||
          textDec.decode(new Uint8Array(raw, 0, 8)) !== MAGIC) {
        throw new Error("Not a GhostDrive share envelope.");
      }
      var view = new DataView(raw);
      var headerLen = view.getUint32(8, false); // big-endian
      if (headerLen <= 0 || headerLen > 65536 || 12 + headerLen > raw.byteLength) {
        throw new Error("Corrupt envelope header.");
      }
      var header = JSON.parse(textDec.decode(new Uint8Array(raw, 12, headerLen)));
      if (header.v !== 1 || header.alg !== "A256GCM" ||
          header.kdf !== "PBKDF2-SHA256") {
        throw new Error("Unsupported envelope format.");
      }
      var body = new Uint8Array(raw, 12 + headerLen);
      var prefix = b64bytes(header.nonce_prefix);
      if (prefix.length !== 4) {
        throw new Error("Corrupt envelope header.");
      }

      // Layer 1: stretch the passphrase, then unwrap the server-generated key.
      setStatus("Deriving key…", "");
      wrapBits = await deriveWrapBits(passphrase, b64bytes(header.wrap_salt), header.iterations);
      var wrapKey = await crypto.subtle.importKey(
        "raw", wrapBits, { name: "AES-GCM" }, false, ["decrypt"]
      );
      try {
        envelopeKeyRaw = await crypto.subtle.decrypt(
          {
            name: "AES-GCM",
            iv: b64bytes(header.wrap_nonce),
            additionalData: textEnc.encode(MAGIC), // wrap bound to the format
          },
          wrapKey,
          b64bytes(header.wrapped_key)
        );
      } catch (badPassphrase) {
        throw new Error("Wrong passphrase or corrupted file.");
      }
      var envelopeKey = await crypto.subtle.importKey(
        "raw", envelopeKeyRaw, { name: "AES-GCM" }, false, ["decrypt"]
      );

      // Layer 2: decrypt each segment with nonce/AAD bound to its index.
      setStatus("Decrypting " + header.segments + " segment(s)…", "");
      var nonce = new Uint8Array(12);
      var nonceView = new DataView(nonce.buffer);
      var aad = new Uint8Array(8);
      var aadView = new DataView(aad.buffer);
      var offset = 0;
      var parts = [];
      for (var i = 0; i < header.segments; i++) {
        var plainLen = (i === header.segments - 1)
          ? header.size - i * header.seg_size
          : header.seg_size;
        // Each segment payload ends with its 16-byte GCM tag.
        var piece = body.subarray(offset, offset + plainLen + 16);
        offset += plainLen + 16;
        nonce.set(prefix, 0);
        nonceView.setBigUint64(4, BigInt(i), false); // nonce = prefix || index(BE)
        aadView.setBigUint64(0, BigInt(i), false);   // AAD   = index(BE)
        try {
          parts.push(await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: nonce, additionalData: aad },
            envelopeKey,
            piece
          ));
        } catch (badSegment) {
          // Wrong passphrase (caught above) or tampered/reordered ciphertext.
          throw new Error("Wrong passphrase or corrupted file.");
        }
      }
      if (offset !== body.length) {
        throw new Error("Envelope size mismatch.");
      }

      // Hand the plaintext Blob to the browser's own downloader.
      var file = new Blob(parts, {
        type: header.mime_type || "application/octet-stream",
      });
      var url = URL.createObjectURL(file);
      var anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = header.filename || "download.bin";
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      setTimeout(function () { URL.revokeObjectURL(url); }, 60000);
      setStatus("Decrypted locally — download started.", "ok");
    } catch (err) {
      setStatus(err.message || "Decryption failed.", "error");
    } finally {
      // Best-effort: zero the key buffers and drop the passphrase input.
      // (JS strings cannot be wiped reliably, so this is defense in depth.)
      if (wrapBits) new Uint8Array(wrapBits).fill(0);
      if (envelopeKeyRaw) new Uint8Array(envelopeKeyRaw).fill(0);
      passphrase = "";
      passInput.value = "";
      button.disabled = false;
    }
  });
})();
