/**
 * Separates "the message the reader was sent" from "everything else in the
 * body element".
 *
 * Gmail renders a reply as *reply text + the entire previous message quoted
 * underneath it*, with a signature below that. Scoring the body element as-is
 * means a one-line reply ("Thanks, noted") inherits every indicator of the
 * original — and when the original is the phishing email, the **reply** is what
 * gets flagged, on the reply's own badge and banner. That is a false positive
 * the user cannot argue with, so quoted material and signatures are dropped
 * before the text is scored and before links are collected.
 *
 * Because "content inside a container I decided to ignore" is also a way to
 * hide something, removal is deliberately conservative:
 *
 *   - only containers the **provider itself** uses for quoting are considered
 *     (Gmail's `gmail_quote`, Outlook's forward header, Yahoo, Proton, Apple's
 *     `blockquote[type=cite]`) — never a bare `blockquote`, which a sender can
 *     write for styling;
 *   - a container is removed only when it carries an **attribution line** ("On …
 *     wrote:", "Original Message", "From: … Sent: …") or is an explicit client
 *     citation, so a message that merely wears a `gmail_quote` class with its
 *     payload inside is still scored;
 *   - if removal would leave nothing behind, the original text is kept: an
 *     empty body is worse than a noisy one.
 */

/** Containers the mail providers (and common clients) use for quoted replies. */
const QUOTE_CONTAINERS = [
  ".gmail_quote",
  ".gmail_quote_container",
  ".gmail_attr",
  ".yahoo_quoted",
  ".protonmail_quote",
  ".moz-cite-prefix",
  "#divRplyFwdMsg",
  ".OutlookMessageHeader",
  "blockquote[type='cite']",
  'blockquote[type="cite"]',
];

/**
 * Outlook Web inserts an empty marker and then *siblings* holding the appended
 * original, so this one removes the marker and everything after it.
 */
const APPEND_MARKERS = ["#appendonsend"];

/** Rendering of a stored signature, not message content. */
const SIGNATURE_CONTAINERS = [".gmail_signature", ".apple-mail-signature"];

/** The markers that make a container a *quoted reply* rather than a style. */
const ATTRIBUTION =
  /(\bwrote:|\bwrites:|-{2,}\s*original message\s*-{2,}|\bfrom:.*\bsent:|\bsent:.*\bto:)/im;

/** RFC 3676: a signature starts after a line containing exactly "-- ". */
const SIGNATURE_DELIMITER = /^--\s?$/m;

/** Tags whose text belongs on its own line. */
const BLOCK_TAGS = new Set([
  "ADDRESS",
  "ARTICLE",
  "BLOCKQUOTE",
  "BR",
  "DD",
  "DIV",
  "DL",
  "DT",
  "FIGCAPTION",
  "FOOTER",
  "H1",
  "H2",
  "H3",
  "H4",
  "H5",
  "H6",
  "HEADER",
  "HR",
  "LI",
  "OL",
  "P",
  "PRE",
  "SECTION",
  "TABLE",
  "TD",
  "TR",
  "UL",
]);

export interface CleanBody {
  /** The cleaned clone, so link collection sees only the new message. */
  node: HTMLElement | null;
  /** Scorable text (not length-capped — the caller decides that). */
  text: string;
  /** True when quoted material or a signature was left out of `text`. */
  excluded: boolean;
  /** Characters dropped, for the evidence line. */
  removedChars: number;
}

/**
 * `textContent` alone glues block elements together ("Thanks" + "Noted" becomes
 * "ThanksNoted"), which loses the line structure the attribution and signature
 * rules depend on. Equivalent to `innerText`, without a layout engine.
 */
export function textWithLineBreaks(root: Node): string {
  const parts: string[] = [];

  const walk = (node: Node): void => {
    if (node.nodeType === 3) {
      parts.push(node.nodeValue ?? "");
      return;
    }
    if (node.nodeType !== 1) return;
    const element = node as Element;
    const block = BLOCK_TAGS.has(element.tagName);
    if (block) parts.push("\n");
    for (const child of Array.from(element.childNodes)) walk(child);
    if (block) parts.push("\n");
  };

  walk(root);
  return parts.join("");
}

function isCitation(node: Element): boolean {
  return node.matches("blockquote[type='cite'], blockquote[type=\"cite\"]");
}

/** Only the outer-most match is removed, so nested markup is not double-counted. */
function outermost(node: Element, candidates: Set<Element>): boolean {
  let parent = node.parentElement;
  while (parent) {
    if (candidates.has(parent)) return false;
    parent = parent.parentElement;
  }
  return true;
}

function stripContainers(
  root: HTMLElement,
  selector: string,
  requireAttribution: boolean,
): { removedChars: number } {
  const found = Array.from(root.querySelectorAll(selector));
  const candidates = new Set(found);
  let removedChars = 0;

  for (const element of found) {
    if (!outermost(element, candidates)) continue;
    if (requireAttribution && !isCitation(element)) {
      const hasAttribution = ATTRIBUTION.test(textWithLineBreaks(element));
      const hasCitation = Boolean(element.querySelector("blockquote[type='cite']"));
      if (!hasAttribution && !hasCitation) continue;
    }
    removedChars += (element.textContent ?? "").length;
    element.remove();
  }

  return { removedChars };
}

/** Outlook's `#appendonsend` marker plus the appended original after it. */
function stripAppendedOriginal(root: HTMLElement): { removedChars: number } {
  let removedChars = 0;

  for (const selector of APPEND_MARKERS) {
    for (const marker of Array.from(root.querySelectorAll(selector))) {
      let sibling = marker.nextElementSibling;
      while (sibling) {
        const next = sibling.nextElementSibling;
        removedChars += (sibling.textContent ?? "").length;
        sibling.remove();
        sibling = next;
      }
      removedChars += (marker.textContent ?? "").length;
      marker.remove();
    }
  }

  return { removedChars };
}

/** Drop a trailing RFC 3676 signature block from plain text. */
export function stripSignatureBlock(text: string): { text: string; removedChars: number } {
  const match = SIGNATURE_DELIMITER.exec(text);
  if (!match) return { text, removedChars: 0 };
  // Only a delimiter when real content precedes it: a body that is nothing but
  // a signature line has nothing else to score.
  const head = text.slice(0, match.index).trim();
  if (!head) return { text, removedChars: 0 };
  return { text: head, removedChars: text.length - head.length };
}

/**
 * The scorable body for an open message: quoted replies and signatures removed,
 * with a clone for link collection.
 */
export function extractScorableBody(body: HTMLElement | null): CleanBody {
  if (!body) return { node: null, text: "", excluded: false, removedChars: 0 };

  const untouched: CleanBody = {
    node: body,
    text: textWithLineBreaks(body),
    excluded: false,
    removedChars: 0,
  };

  const clone = body.cloneNode(true) as HTMLElement;
  let removedChars = stripAppendedOriginal(clone).removedChars;
  for (const selector of QUOTE_CONTAINERS) {
    removedChars += stripContainers(clone, selector, true).removedChars;
  }
  for (const selector of SIGNATURE_CONTAINERS) {
    removedChars += stripContainers(clone, selector, false).removedChars;
  }

  // The delimiter rule is text-level, so it also applies when no container was
  // removed at all — a plain-text signature is not wrapped in a class.
  const signature = stripSignatureBlock(textWithLineBreaks(clone));
  removedChars += signature.removedChars;

  if (removedChars === 0) return untouched;

  // Nothing left means the "quote" was the whole message, or the only content
  // was a signature: keep the original rather than analyse an empty body.
  if (!signature.text.trim()) return untouched;

  return { node: clone, text: signature.text, excluded: true, removedChars };
}
