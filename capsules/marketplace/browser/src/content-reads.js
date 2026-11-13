// Marketplace reads item covers and metadata from this Home's own content
// store at `/content/<cid>[/<path>]`, with its Home token. The gateway serves
// that store to this Home's own apps only, so a raw `/ipfs/` route or a plain
// `<img src>`, which carries no token, is refused on an ordinary Home.

const CID_RE = /^(Qm[1-9A-HJ-NP-Za-km-z]{44}|b[a-z2-7]{45,95})$/;
// As many reads at once as the card access watch allows.
export const CONTENT_READ_CONCURRENCY = 4;

export function contentReadPath(cid, path = "") {
  const value = String(cid || "").trim();
  if (!CID_RE.test(value)) {
    return "";
  }
  const file = String(path || "")
    .split("/")
    .filter(Boolean)
    .map(encodeURIComponent)
    .join("/");
  return file ? `/content/${value}/${file}` : `/content/${value}`;
}

// One reader per page: each CID's cover is read once and kept as a blob URL
// for the life of the page, and at most `limit` reads run at a time. Home
// renews the page's token (`setToken`); each read carries the current one.
export function createContentReader({
  token: launchToken,
  fetchImpl = (...args) => fetch(...args),
  createObjectURL = (blob) => URL.createObjectURL(blob),
  limit = CONTENT_READ_CONCURRENCY,
}) {
  let token = launchToken;
  let active = 0;
  const waiting = [];
  const images = new Map();
  const ready = new Map();

  async function withSlot(task) {
    if (active >= limit) {
      // A finished read hands its slot straight to the next one waiting.
      await new Promise((resolve) => waiting.push(resolve));
    } else {
      active += 1;
    }
    try {
      return await task();
    } finally {
      const next = waiting.shift();
      if (next) {
        next();
      } else {
        active -= 1;
      }
    }
  }

  async function read(cid, path, accept) {
    const route = contentReadPath(cid, path);
    if (!route) {
      return null;
    }
    return withSlot(async () => {
      const response = await fetchImpl(route, {
        headers: { accept, "x-elastos-home-token": token },
      });
      return response.ok ? response : null;
    });
  }

  return {
    setToken(value) {
      token = value;
    },
    // The parsed document, or null when this Home cannot read it.
    async json(cid, path) {
      try {
        const response = await read(cid, path, "application/json");
        return response ? await response.json() : null;
      } catch {
        return null;
      }
    },
    // A blob URL for the image, or "" when this Home cannot read it.
    imageUrl(cid) {
      const key = String(cid || "").trim();
      if (!images.has(key)) {
        images.set(key, (async () => {
          let url = "";
          try {
            const response = await read(key, "", "image/*");
            url = response ? createObjectURL(await response.blob()) : "";
          } catch {
            url = "";
          }
          ready.set(key, url);
          return url;
        })());
      }
      return images.get(key);
    },
    // The answer already read for this cover, if any, so a repaint shows it
    // at once instead of waiting a turn.
    readyImageUrl(cid) {
      return ready.get(String(cid || "").trim());
    },
  };
}

// Gives every `<img data-content-cid>` under `root` its cover. An image this
// Home cannot read fails like any broken image, so the card shows its glyph.
export function hydrateContentImages(root, reader) {
  for (const image of root.querySelectorAll("img[data-content-cid]")) {
    if (image.dataset.contentRequested === "true") {
      continue;
    }
    image.dataset.contentRequested = "true";
    const show = (url) => {
      if (url) {
        image.src = url;
      } else {
        image.dispatchEvent(new Event("error"));
      }
    };
    const known = reader.readyImageUrl?.(image.dataset.contentCid);
    if (known === undefined) {
      reader.imageUrl(image.dataset.contentCid).then(show);
    } else {
      show(known);
    }
  }
}
