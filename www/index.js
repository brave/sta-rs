import { create_share, group_shares } from "star-wasm";

/* Encodes a Uint8Array as a base64 string */
function toBase64Fast(data) {
  return btoa(_toString(toByteArray(data)));
}

/* Decodes a base64 string as a Uint8Array */
function fromBase64Fast(data) {
  return _fromString(atob(data));
}

function toByteArray(data) {
  if (data.buffer) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  return new Uint8Array(data);
}

function _toString(data) {
  const CHUNK_SIZE = 16383; // 32767 is too much for MS Edge in 2 Gb virtual machine
  const c = [];
  const len = data.length;
  for (let i = 0; i < len; i += CHUNK_SIZE) {
    c.push(String.fromCharCode.apply(null, data.subarray(i, i + CHUNK_SIZE)));
  }
  return c.join("");
}

function _fromString(data) {
  const res = new Uint8Array(data.length);
  const len = data.length;
  for (let i = 0; i < len; i += 1) {
    res[i] = data.charCodeAt(i);
  }
  return res;
}

// http://ecmanaut.blogspot.de/2006/07/encoding-decoding-utf8-in-javascript.html
function _toUTF8(s) {
  return _fromString(unescape(encodeURIComponent(s)));
}

function _fromUTF8(s) {
  return decodeURIComponent(escape(_toString(s)));
}

/* Returns a string given a Uint8Array UTF-8 encoding */
const decoder = TextDecoder ? new TextDecoder() : { decode: _fromUTF8 };
function fromUTF8(bytes) {
  return decoder.decode(toByteArray(bytes));
}

/* Returns a Uint8Array UTF-8 encoding of the given string */
const encoder = TextEncoder ? new TextEncoder() : { encode: _toUTF8 };
function toUTF8(str) {
  return encoder.encode(str);
}

const EPOCH = "1";
const THRESHOLD = 2;

/**
 * Given a `url` and `page` message to send to the backend, create a random
 * STAR share and wrap it into a JSON message which can be sent to the backend.
 * The backend then collects all shares and decrypts the ones which have reached
 * the threshold.
 */
async function prepareMessage(url, page) {
  // `tag`, `key` and `share` are base64-encoded strings.
  const t0 = Date.now();
  const { tag, key, share } = JSON.parse(create_share(url, THRESHOLD, EPOCH));
  const t1 = Date.now();
  console.log("create_share:", t1 - t0);

  // Prepare page message to be encrypted -> Uint8Array
  // NOTE: eventually this will be the HPN-encrypted payload instead.
  const payload = toUTF8(JSON.stringify(page));

  // importKey: get actual encryption key from `key`
  const aesKey = await window.crypto.subtle.importKey(
    "raw",
    fromBase64Fast(key),
    {
      name: "AES-GCM",
    },
    false,
    ["encrypt"]
  );

  // Generate random `iv`
  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  // Encrypt `payload` with `aesKey`
  const encrypted = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
    },
    aesKey,
    payload
  );

  return {
    // Constants: backend will need them to stay in sync with clients.
    // NOTE: the value of `tag` should be sensitive to both of these values,
    // which means that changing `EPOCH` or `THRESHOLD` will result in a
    // different tag. It should thus be safe for the backend to group by `tag`
    // and expect that values of all constants will match.
    threshold: THRESHOLD,
    epoch: EPOCH,

    // Information about the STAR share
    tag,
    share,

    // Information about encrypted accompanying data (i.e. page message)
    encrypted: toBase64Fast(encrypted),
    iv: toBase64Fast(iv),
  };
}

async function recoverEncryptionKey(messages) {
  const epoch = messages[0].epoch;
  const t0 = Date.now();
  const key = group_shares(
    messages.map(({ share }) => share).join("\n"),
    epoch
  );
  const t1 = Date.now();
  console.log("group_shares:", t1 - t0);

  return await window.crypto.subtle.importKey(
    "raw",
    fromBase64Fast(key),
    {
      name: "AES-GCM",
    },
    false,
    ["decrypt", "encrypt"]
  );
}

async function recoverPageMessages(messages, aesKey) {
  const decrypted = [];

  for (const { encrypted, iv } of messages) {
    decrypted.push(
      JSON.parse(
        fromUTF8(
          await window.crypto.subtle.decrypt(
            {
              name: "AES-GCM",
              iv: fromBase64Fast(iv),
            },
            aesKey,
            fromBase64Fast(encrypted)
          )
        )
      )
    );
  }

  return decrypted;
}

async function processMessages(messages) {
  // Group all messages per tag
  const grouped = new Map();
  for (const message of messages) {
    let bucket = grouped.get(message.tag);
    if (bucket === undefined) {
      bucket = [];
      grouped.set(message.tag, bucket);
    }
    bucket.push(message);
  }

  // Load data from groups which have reached threshold.
  for (const bucket of grouped.values()) {
    const threshold = bucket[0].threshold;
    if (bucket.length >= threshold) {
      // 1. Retrieve encryption key.
      const aesKey = await recoverEncryptionKey(bucket);

      // 2. Decrypt all messages.
      const pages = await recoverPageMessages(bucket, aesKey);

      console.error("Got pages", pages);
    }
  }
}

(async () => {
  const messages = [];

  // Will not be decrypted! 1 share
  messages.push(
    await prepareMessage("https://brave.com/internal", {
      url: "https://brave.com/internal",
      x: 0,
    })
  );

  // Ok! 2 shares
  messages.push(
    await prepareMessage("https://brave.com", {
      url: "https://brave.com",
      x: 1,
    })
  );
  messages.push(
    await prepareMessage("https://brave.com", {
      url: "https://brave.com",
      x: 2,
    })
  );

  // Ok! 3 shares
  messages.push(
    await prepareMessage("https://github.com", {
      url: "https://github.com",
      x: 0,
    })
  );
  messages.push(
    await prepareMessage("https://github.com", {
      url: "https://github.com",
      x: 1,
    })
  );
  messages.push(
    await prepareMessage("https://github.com", {
      url: "https://github.com",
      x: 2,
    })
  );

  processMessages(messages);
})();
