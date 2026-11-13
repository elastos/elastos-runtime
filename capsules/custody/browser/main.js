// Custody's browser entry. Home serves its clipboard and navigation clients at
// absolute paths, so the imports live here and custody.js stays importable in
// tests.
import { createHomeClipboardClient } from "/apps/home/home-clipboard-client.js?v=home-20261111a";
import { createHomeNavigationClient } from "/apps/home/home-navigation-client.js";
import { bootCustodyApp } from "./custody.js?v=custody-20261113e";

bootCustodyApp({
  createClipboard({ homeOrigin, homeToken }) {
    const homeClipboard = createHomeClipboardClient({
      targetId: "custody",
      homeOrigin,
      homeToken,
    });
    homeClipboard.start();
    return homeClipboard;
  },
  createNavigation: createHomeNavigationClient,
});
