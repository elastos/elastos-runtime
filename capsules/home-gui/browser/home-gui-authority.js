export function projectHomeGuiAuthority(body, summary) {
  body.dataset.homeAuthority =
    summary?.authority?.signed_in === true ? "signed" : "unsigned";
}

export function isTrustedHomeGuiMessage(event, expectedSource, expectedOrigin) {
  return event.source === expectedSource && event.origin === expectedOrigin;
}

// Desktop owns its envelope token; payload tokens have separate names.
export function homeGuiReply(message, homeToken) {
  return { ...message, homeToken };
}
