import assert from "node:assert/strict";
import test from "node:test";

import { MAX_CHAPTER_NODES, openBook, sanitizeChapter } from "./epub.js";
import { createTargetDocument, findAll, parseMarkup, serialize, textOf } from "./dom.test-helper.mjs";
import { buildStoredZip, text } from "./zip-fixture.test-helper.mjs";

const IMAGE_BYTES = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3]);

function sanitize(body, options = {}) {
  const document = createTargetDocument();
  const fragment = sanitizeChapter(parseMarkup(`<html><body>${body}</body></html>`), {
    document,
    resolveImage: options.resolveImage ?? (() => ""),
  });
  return { fragment, markup: serialize(fragment), text: textOf(fragment) };
}

function bookDeps() {
  const revoked = [];
  return {
    parseMarkup,
    document: createTargetDocument(),
    createObjectURL: (blob) => URL.createObjectURL(blob),
    revokeObjectURL: (url) => {
      revoked.push(url);
      URL.revokeObjectURL(url);
    },
    revoked,
  };
}

const CONTAINER_XML = `<?xml version="1.0" encoding="UTF-8"?>
<container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container">
  <rootfiles>
    <rootfile full-path="OEBPS/content.opf" media-type="application/oebps-package+xml"/>
  </rootfiles>
</container>`;

// The manifest lists chapter two first on purpose: the reading order has to
// come from the spine, not from the order the files happen to be declared in.
const CONTENT_OPF = `<?xml version="1.0" encoding="UTF-8"?>
<package xmlns="http://www.idpf.org/2007/opf" version="3.0" unique-identifier="uid">
  <metadata><dc:title xmlns:dc="http://purl.org/dc/elements/1.1/">A Book</dc:title></metadata>
  <manifest>
    <item id="ch2" href="ch2.xhtml" media-type="application/xhtml+xml"/>
    <item id="ch1" href="ch1.xhtml" media-type="application/xhtml+xml"/>
    <item id="back" href="back.xhtml" media-type="application/xhtml+xml"/>
    <item id="cover" href="images/cover.png" media-type="image/png"/>
  </manifest>
  <spine>
    <itemref idref="ch1"/>
    <itemref idref="ch2"/>
    <itemref idref="back" linear="no"/>
  </spine>
</package>`;

const CHAPTER_ONE = `<?xml version="1.0" encoding="UTF-8"?>
<html xmlns="http://www.w3.org/1999/xhtml"><head><title>One</title></head><body>
  <h1>Chapter one</h1>
  <script>window.alert("pwned")</script>
  <p>The <em>first</em> chapter.</p>
  <img src="images/cover.png" alt="Cover"/>
  <img src="./sub/../images/cover.png" alt="Cover again"/>
  <img src="https://tracker.example/pixel.png" alt="Remote"/>
  <img src="../../etc/passwd.png" alt="Escape"/>
</body></html>`;

const CHAPTER_TWO = `<?xml version="1.0" encoding="UTF-8"?>
<html xmlns="http://www.w3.org/1999/xhtml"><body><p>Chapter two</p></body></html>`;

function bookFiles(overrides = {}) {
  return {
    mimetype: "application/epub+zip",
    "META-INF/container.xml": CONTAINER_XML,
    "OEBPS/content.opf": CONTENT_OPF,
    "OEBPS/ch1.xhtml": CHAPTER_ONE,
    "OEBPS/ch2.xhtml": CHAPTER_TWO,
    "OEBPS/back.xhtml": "<html><body><p>Back matter</p></body></html>",
    "OEBPS/images/cover.png": IMAGE_BYTES,
    ...overrides,
  };
}

async function rejects(run, expected) {
  await assert.rejects(async () => run(), (error) => {
    assert.ok(error instanceof Error, "a plain Error must reach the reader");
    assert.match(error.message, expected);
    return true;
  });
}

test("openBook reads the spine order out of the package, not the manifest order", async () => {
  const book = await openBook(buildStoredZip(bookFiles()), bookDeps());
  assert.equal(book.opfPath, "OEBPS/content.opf");
  assert.equal(book.chapterCount, 2);
  assert.deepEqual(
    book.chapters.map((chapter) => chapter.path),
    ["OEBPS/ch1.xhtml", "OEBPS/ch2.xhtml"],
  );
  assert.match(textOf((await book.readChapter(0)).fragment), /Chapter one/);
  assert.match(textOf((await book.readChapter(1)).fragment), /Chapter two/);
  book.release();
});

test("openBook strips a chapter script and resolves its images to blob sources", async () => {
  const deps = bookDeps();
  const book = await openBook(buildStoredZip(bookFiles()), deps);
  const { fragment } = await book.readChapter(0);
  const markup = serialize(fragment);
  assert.doesNotMatch(markup, /<script/i);
  assert.doesNotMatch(markup, /alert/i);
  assert.doesNotMatch(markup, /pwned/i);
  const images = findAll(fragment, "img");
  // The remote image and the one pointing outside the book are both gone.
  assert.equal(images.length, 2);
  for (const image of images) {
    assert.match(image.getAttribute("src"), /^blob:/);
  }
  // The same file behind two different spellings is fetched once.
  assert.equal(images[0].getAttribute("src"), images[1].getAttribute("src"));
  assert.equal(images[0].getAttribute("alt"), "Cover");
  book.release();
  assert.equal(deps.revoked.length, 1);
});

test("openBook refuses to mint a source for a drawing the book carries", async () => {
  // A drawing file is markup, and its type would make the source the reader
  // mints openable on its own in a new tab, where that markup would run. The
  // reader never mints one, whatever the book declares the file to be.
  const drawing = '<svg xmlns="http://www.w3.org/2000/svg" onload="window.alert(1)"/>';
  const opf = CONTENT_OPF.replace(
    '<item id="cover" href="images/cover.png" media-type="image/png"/>',
    '<item id="cover" href="images/cover.png" media-type="image/svg+xml"/>' +
      '<item id="art" href="images/art.svg" media-type="image/svg+xml"/>',
  );
  const chapter = `<?xml version="1.0" encoding="UTF-8"?>
<html xmlns="http://www.w3.org/1999/xhtml"><body>
  <img src="images/art.svg" alt="Art"/>
  <img src="images/cover.png" alt="Cover"/>
</body></html>`;
  const deps = bookDeps();
  const book = await openBook(
    buildStoredZip(
      bookFiles({
        "OEBPS/content.opf": opf,
        "OEBPS/ch1.xhtml": chapter,
        "OEBPS/images/art.svg": drawing,
      }),
    ),
    deps,
  );
  const { fragment } = await book.readChapter(0);
  assert.equal(findAll(fragment, "img").length, 0);
  book.release();
  assert.equal(deps.revoked.length, 0);
});

test("openBook keeps a chapter the spine marks as out of the reading order", async () => {
  const book = await openBook(buildStoredZip(bookFiles()), bookDeps());
  assert.ok(book.chapters.every((chapter) => chapter.path !== "OEBPS/back.xhtml"));
  await rejects(() => book.readChapter(2), /chapter/i);
  await rejects(() => book.readChapter(-1), /chapter/i);
  await rejects(() => book.readChapter(1.5), /chapter/i);
});

test("openBook refuses a book whose parts do not line up", async () => {
  const missingContainer = bookFiles();
  delete missingContainer["META-INF/container.xml"];
  await rejects(() => openBook(buildStoredZip(missingContainer), bookDeps()), /damaged/i);

  await rejects(
    () =>
      openBook(
        buildStoredZip(
          bookFiles({
            "META-INF/container.xml": CONTAINER_XML.replace(
              "application/oebps-package+xml",
              "text/plain",
            ),
          }),
        ),
        bookDeps(),
      ),
    /damaged/i,
  );

  await rejects(
    () =>
      openBook(
        buildStoredZip(
          bookFiles({
            "META-INF/container.xml": CONTAINER_XML.replace(
              'full-path="OEBPS/content.opf"',
              'full-path="../outside/content.opf"',
            ),
          }),
        ),
        bookDeps(),
      ),
    /damaged/i,
  );

  const missingOpf = bookFiles();
  delete missingOpf["OEBPS/content.opf"];
  await rejects(() => openBook(buildStoredZip(missingOpf), bookDeps()), /damaged/i);

  await rejects(
    () =>
      openBook(
        buildStoredZip(
          bookFiles({ "OEBPS/content.opf": CONTENT_OPF.replace('idref="ch1"', 'idref="nope"') }),
        ),
        bookDeps(),
      ),
    /damaged/i,
  );

  await rejects(
    () =>
      openBook(
        buildStoredZip(
          bookFiles({ "OEBPS/content.opf": CONTENT_OPF.replace('linear="no"', 'linear="maybe"') }),
        ),
        bookDeps(),
      ),
    /damaged/i,
  );
});

test("openBook refuses a book with nothing to read", async () => {
  const opf = CONTENT_OPF.replace('<itemref idref="ch1"/>', '<itemref idref="ch1" linear="no"/>')
    .replace('<itemref idref="ch2"/>', '<itemref idref="ch2" linear="no"/>');
  await rejects(
    () => openBook(buildStoredZip(bookFiles({ "OEBPS/content.opf": opf })), bookDeps()),
    /no readable pages/i,
  );
});

test("openBook reads which way the pages run and refuses a direction it cannot read", async () => {
  const spineWith = (direction) =>
    bookFiles({
      "OEBPS/content.opf": CONTENT_OPF.replace(
        "<spine>",
        `<spine page-progression-direction="${direction}">`,
      ),
    });
  const plain = await openBook(buildStoredZip(bookFiles()), bookDeps());
  assert.equal(plain.pageProgressionDirection, "default");
  const rightToLeft = await openBook(buildStoredZip(spineWith("rtl")), bookDeps());
  assert.equal(rightToLeft.pageProgressionDirection, "rtl");
  await rejects(() => openBook(buildStoredZip(spineWith("sideways")), bookDeps()), /damaged/i);
});

test("openBook passes an unreadable archive straight through", async () => {
  await rejects(() => openBook(text("not a book"), bookDeps()), /not a readable archive/i);
});

test("the sanitizer keeps the block and inline tags a book is made of", () => {
  const { markup } = sanitize(
    "<h2>Title</h2><p>Some <em>emphasis</em>, <strong>weight</strong> and <code>code</code>.</p>" +
      "<blockquote><p>Quoted</p></blockquote><ul><li>One</li><li>Two</li></ul>" +
      "<table><tbody><tr><th scope='col'>H</th><td colspan='2'>Cell</td></tr></tbody></table>" +
      "<pre>literal</pre><hr/><br/>",
  );
  assert.match(markup, /<h2>Title<\/h2>/);
  assert.match(markup, /<em>emphasis<\/em>/);
  assert.match(markup, /<strong>weight<\/strong>/);
  assert.match(markup, /<code>code<\/code>/);
  assert.match(markup, /<blockquote><p>Quoted<\/p><\/blockquote>/);
  assert.match(markup, /<ul><li>One<\/li><li>Two<\/li><\/ul>/);
  assert.match(markup, /<th scope="col">H<\/th>/);
  assert.match(markup, /<td colspan="2">Cell<\/td>/);
  assert.match(markup, /<pre>literal<\/pre>/);
  assert.match(markup, /<hr\/>/);
});

test("the sanitizer drops a script and everything inside it", () => {
  const { markup, text: content } = sanitize(
    "<p>before</p><script>window.alert(1)</script><p>after</p>",
  );
  assert.doesNotMatch(markup, /script/i);
  assert.doesNotMatch(content, /alert/);
  assert.equal(content, "beforeafter");
});

test("the sanitizer drops a style block, a base tag and document head tags", () => {
  for (const [body, needle] of [
    ["<style>body{background:url(https://x.example/a)}</style><p>ok</p>", /background|style/i],
    ['<base href="https://evil.example/"/><p>ok</p>', /base|evil/i],
    ['<link rel="stylesheet" href="https://evil.example/a.css"/><p>ok</p>', /link|evil/i],
    ['<meta http-equiv="refresh" content="0;url=https://evil.example"/><p>ok</p>', /meta|evil/i],
    ["<title>hidden</title><p>ok</p>", /title|hidden/i],
  ]) {
    const { markup } = sanitize(body);
    assert.doesNotMatch(markup, needle, body);
    assert.match(markup, /<p>ok<\/p>/, body);
  }
});

test("the sanitizer drops framing, plugin and media tags with their contents", () => {
  for (const body of [
    '<iframe src="https://evil.example/"></iframe>',
    '<object data="x.swf"><param name="a" value="b"/></object>',
    '<embed src="x.swf"/>',
    "<frameset><frame src='x'/></frameset>",
    "<applet code='x'></applet>",
    "<noscript><p>fallback</p></noscript>",
    "<template><p>inert</p></template>",
    '<canvas id="c"></canvas>',
    '<video src="x.mp4"><source src="y.mp4"/></video>',
    '<audio src="x.mp3"></audio>',
    '<portal src="https://evil.example/"></portal>',
  ]) {
    const { markup } = sanitize(`${body}<p>ok</p>`);
    assert.equal(markup, "<p>ok</p>", body);
  }
});

test("the sanitizer drops a form and its controls", () => {
  const { markup } = sanitize(
    '<form action="https://evil.example/steal"><input name="a"/>' +
      "<button>Send</button><textarea>t</textarea>" +
      "<select><option>x</option></select></form><p>ok</p>",
  );
  assert.equal(markup, "<p>ok</p>");
});

test("the sanitizer drops an svg subtree, nested script and foreignObject included", () => {
  for (const body of [
    "<svg><script>window.alert(1)</script></svg>",
    "<svg><foreignObject><body><script>window.alert(1)</script></body></foreignObject></svg>",
    '<svg><a xlink:href="javascript:alert(1)"><text>click</text></a></svg>',
    '<svg><image href="https://evil.example/p.png"/></svg>',
    "<math><mtext><script>window.alert(1)</script></mtext></math>",
  ]) {
    const { markup } = sanitize(`${body}<p>ok</p>`);
    assert.equal(markup, "<p>ok</p>", body);
  }
});

test("the sanitizer drops every event handler attribute", () => {
  const { markup } = sanitize(
    '<p onclick="steal()" onmouseover="steal()" ONLOAD="steal()">text</p>' +
      '<img onerror="steal()" src="cover.png"/>',
    { resolveImage: () => "blob:test/1" },
  );
  assert.doesNotMatch(markup, /on[a-z]+=/i);
  assert.doesNotMatch(markup, /steal/);
  assert.match(markup, /<p>text<\/p>/);
});

test("the sanitizer drops a script URL wherever a link can carry one", () => {
  for (const href of [
    "javascript:alert(1)",
    "JaVaScRiPt:alert(1)",
    "  javascript:alert(1)",
    "java\tscript:alert(1)",
    "java\nscript:alert(1)",
    "jav\u0000ascript:alert(1)",
    "vbscript:msgbox(1)",
    "data:text/html;base64,PHNjcmlwdD4=",
    "blob:https://evil.example/abc",
    "file:///etc/passwd",
  ]) {
    const { markup } = sanitize(`<p><a href="${href}">click</a></p>`);
    assert.equal(markup, "<p><a>click</a></p>", href);
  }
  const { markup } = sanitize('<blockquote cite="javascript:alert(1)"><p>q</p></blockquote>');
  assert.equal(markup, "<blockquote><p>q</p></blockquote>");
});

test("the sanitizer keeps an ordinary link and makes it open away from the book", () => {
  for (const href of ["https://example.com/a", "http://example.com/a", "mailto:a@example.com"]) {
    const { markup } = sanitize(`<p><a href="${href}">click</a></p>`);
    assert.match(markup, new RegExp(`href="${href.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"`), href);
    assert.match(markup, /rel="noopener noreferrer"/, href);
    assert.match(markup, /target="_blank"/, href);
  }
  // A link inside the book has nowhere to go once the chapter is a fragment.
  assert.equal(sanitize('<p><a href="ch2.xhtml">next</a></p>').markup, "<p><a>next</a></p>");
  assert.equal(sanitize('<p><a href="#note">note</a></p>').markup, "<p><a>note</a></p>");
});

test("the sanitizer drops attributes that are not on the allowlist", () => {
  const { markup } = sanitize(
    '<p style="position:fixed;top:0" class="x" id="config" data-x="1" contenteditable="true"' +
      ' srcset="https://evil.example/a.png" xml:base="https://evil.example/"' +
      ' xlink:href="javascript:alert(1)" dir="rtl" lang="fr" title="hint">text</p>',
  );
  assert.equal(markup, '<p dir="rtl" lang="fr" title="hint">text</p>');
});

test("the sanitizer refuses attribute values it cannot vouch for", () => {
  assert.equal(sanitize('<p dir="expression(1)">t</p>').markup, "<p>t</p>");
  assert.equal(sanitize('<p lang="fr\\"onload=x">t</p>').markup, "<p>t</p>");
  assert.equal(
    sanitize("<table><tbody><tr><td colspan='999999'>c</td></tr></tbody></table>").markup,
    "<table><tbody><tr><td>c</td></tr></tbody></table>",
  );
  assert.equal(sanitize("<ol start='abc'><li>i</li></ol>").markup, "<ol><li>i</li></ol>");
});

test("the sanitizer only keeps an image the book itself carries", () => {
  const resolveImage = (raw) => (raw === "images/cover.png" ? "blob:test/cover" : "");
  const { markup } = sanitize(
    '<p><img src="images/cover.png" alt="Cover"/>' +
      '<img src="https://evil.example/pixel.png" alt="Remote"/>' +
      '<img src="javascript:alert(1)" alt="Script"/>' +
      '<img src="data:image/svg+xml,<svg onload=alert(1)/>" alt="Inline"/>' +
      "<img alt=\"None\"/></p>",
    { resolveImage },
  );
  assert.equal(markup, '<p><img src="blob:test/cover" alt="Cover"/></p>');
});

test("the sanitizer drops comments and keeps text out of them", () => {
  const { markup } = sanitize("<p>a<!-- <script>alert(1)</script> -->b</p>");
  assert.equal(markup, "<p>ab</p>");
});

test("the sanitizer unwraps a tag it does not know and keeps the words", () => {
  const { markup } = sanitize("<p>a <unknownwrapper>kept <em>words</em></unknownwrapper> b</p>");
  assert.equal(markup, "<p>a kept <em>words</em> b</p>");
});

test("the sanitizer survives deeply nested markup without running out of stack", () => {
  const depth = 5000;
  const { text: content } = sanitize(`${"<div>".repeat(depth)}deep${"</div>".repeat(depth)}`);
  assert.equal(content, "deep");
});

test("the sanitizer refuses a chapter with more nodes than it will show", () => {
  const body = "<p>x</p>".repeat(MAX_CHAPTER_NODES);
  assert.throws(() => sanitize(body), (error) => {
    assert.ok(error instanceof Error);
    assert.match(error.message, /too large/i);
    return true;
  });
});

test("the sanitizer refuses to run without a document to build into", () => {
  assert.throws(
    () => sanitizeChapter(parseMarkup("<html><body><p>a</p></body></html>"), { document: null }),
    /cannot be shown/i,
  );
});

// PR4-F2: images are expanded only after the chapter's limits, only for the
// images the rebuild keeps, and within a budget of live expanded bytes.

function countingDeps(extra = {}) {
  const deps = { ...bookDeps(), ...extra };
  let minted = 0;
  deps.createObjectURL = (blob) => {
    minted += 1;
    return URL.createObjectURL(blob);
  };
  deps.minted = () => minted;
  return deps;
}

function imageChapter(body) {
  return `<?xml version="1.0" encoding="UTF-8"?>
<html xmlns="http://www.w3.org/1999/xhtml"><body>${body}</body></html>`;
}

function picturedBook(chapterOne, chapterTwo = CHAPTER_TWO) {
  return buildStoredZip(
    bookFiles({
      "OEBPS/ch1.xhtml": chapterOne,
      "OEBPS/ch2.xhtml": chapterTwo,
      "OEBPS/images/a.png": IMAGE_BYTES,
      "OEBPS/images/b.png": IMAGE_BYTES,
      "OEBPS/images/c.png": IMAGE_BYTES,
    }),
  );
}

const THREE_IMAGES = imageChapter(
  '<img src="images/a.png"/><img src="images/b.png"/><img src="images/c.png"/>',
);

test("a chapter whose images together pass the live budget is refused before the last is expanded", async () => {
  const deps = countingDeps({ maxLiveImageBytes: 2 * IMAGE_BYTES.length + 1 });
  const book = await openBook(picturedBook(THREE_IMAGES), deps);
  await rejects(() => book.readChapter(0), /too large/i);
  assert.equal(deps.minted(), 2, "the over-budget image is never expanded");
  book.release();
  assert.equal(deps.revoked.length, 2);
});

test("a chapter whose images fit the live budget shows all of them", async () => {
  const deps = countingDeps({ maxLiveImageBytes: 3 * IMAGE_BYTES.length });
  const book = await openBook(picturedBook(THREE_IMAGES), deps);
  const { fragment } = await book.readChapter(0);
  assert.equal(findAll(fragment, "img").length, 3);
  assert.equal(deps.minted(), 3);
  book.release();
});

test("a chapter with more image nodes than it will show is refused before any image is expanded", async () => {
  const deps = countingDeps();
  const body = '<img src="images/a.png"/>'.repeat(MAX_CHAPTER_NODES + 1);
  const book = await openBook(picturedBook(imageChapter(body)), deps);
  await rejects(() => book.readChapter(0), /too large/i);
  assert.equal(deps.minted(), 0);
});

test("an image inside a subtree the rebuild drops is never expanded", async () => {
  const deps = countingDeps();
  const book = await openBook(
    picturedBook(imageChapter('<p>kept</p><button><img src="images/a.png"/></button>')),
    deps,
  );
  const { fragment } = await book.readChapter(0);
  assert.equal(findAll(fragment, "img").length, 0);
  assert.equal(deps.minted(), 0);
});

test("moving to the next chapter gives back the previous chapter's images and budget", async () => {
  const deps = countingDeps({ maxLiveImageBytes: IMAGE_BYTES.length });
  const book = await openBook(
    picturedBook(imageChapter('<img src="images/a.png"/>'), imageChapter('<img src="images/b.png"/>')),
    deps,
  );
  await book.readChapter(0);
  // Without the release the second chapter's image would not fit.
  await rejects(() => book.readChapter(1), /too large/i);
  book.release();
  const { fragment } = await book.readChapter(1);
  assert.equal(findAll(fragment, "img").length, 1);
  assert.equal(deps.revoked.length, 1);
});

// A read the test holds open, so a release can arrive while an image is
// still being expanded.
function heldReads() {
  const held = [];
  const read = (bytes, entry) =>
    new Promise((resolve, reject) => {
      held.push({ entry, resolve, reject });
    });
  return { held, read };
}

async function settle() {
  for (let turn = 0; turn < 5; turn += 1) await new Promise((resolve) => setImmediate(resolve));
}

test("a release while an image is expanding keeps its charge until it finishes and leaks no source", async () => {
  const { readEntry } = await import("./zip.js");
  const gate = heldReads();
  const deps = countingDeps({
    maxLiveImageBytes: IMAGE_BYTES.length,
    readEntry: (bytes, entry) => (/\.png$/.test(entry.name) ? gate.read(bytes, entry) : readEntry(bytes, entry)),
  });
  const book = await openBook(
    picturedBook(imageChapter('<img src="images/a.png"/>'), imageChapter('<img src="images/b.png"/>')),
    deps,
  );
  const first = book.readChapter(0);
  await settle();
  assert.equal(gate.held.length, 1, "chapter one's image is being expanded");
  // The reader moves on: release, then the next chapter. The image still
  // expanding holds the whole budget, so the next one does not fit yet.
  book.release();
  await rejects(() => book.readChapter(1), /too large/i);
  gate.held[0].resolve(IMAGE_BYTES);
  const stale = await first;
  assert.equal(findAll(stale.fragment, "img").length, 0, "the overtaken read shows no image");
  assert.equal(deps.minted(), 1);
  assert.equal(deps.revoked.length, 1, "its source was given back at once");
  // Its charge is gone, so the next chapter now fits.
  const next = book.readChapter(1);
  await settle();
  gate.held[1].resolve(IMAGE_BYTES);
  assert.equal(findAll((await next).fragment, "img").length, 1);
  book.release();
  assert.equal(deps.revoked.length, deps.minted(), "every source is given back");
});

test("a failed expansion overtaken by a release gives back only its own charge", async () => {
  const { readEntry } = await import("./zip.js");
  const gate = heldReads();
  const deps = countingDeps({
    maxLiveImageBytes: IMAGE_BYTES.length,
    readEntry: (bytes, entry) => (/\.png$/.test(entry.name) ? gate.read(bytes, entry) : readEntry(bytes, entry)),
  });
  const book = await openBook(
    picturedBook(imageChapter('<img src="images/a.png"/>'), imageChapter('<img src="images/b.png"/>')),
    deps,
  );
  const first = book.readChapter(0);
  await settle();
  book.release();
  gate.held[0].reject(new Error("This book is damaged."));
  await rejects(() => first, /damaged/i);
  // The account is back to empty, not below it: exactly one image fits.
  const next = book.readChapter(1);
  await settle();
  gate.held[1].resolve(IMAGE_BYTES);
  assert.equal(findAll((await next).fragment, "img").length, 1);
  await rejects(() => book.readChapter(0).then(() => book.readChapter(0)), /too large/i);
  book.release();
  assert.equal(deps.revoked.length, deps.minted());
});
