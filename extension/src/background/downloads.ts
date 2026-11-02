// Downloads that bypass the page's click handler: right-click "Save link
// as…", Ctrl/⌘-click, middle-click. With the "downloads" permission (granted
// at install) the service worker sees them start; the ManualsLib download page that
// offered the link (it checks the URL against its own links) fetches the file
// again and preserves it. The user's own download is left alone.
import { canUpload, getSettings } from "../core/config.ts";

const FILE_HOST = /^https:\/\/([a-z0-9-]+\.)*manualslib\.com\//i;
const PAGES = ["*://*.manualslib.com/download/*"];

/** Listen for downloads (at the top level of the service worker, so a download wakes it). */
export function installDownloadWatch(): void {
  chrome.downloads?.onCreated.addListener((item) => void onCreated(item));
}

export async function onCreated(item: { url: string; finalUrl?: string; byExtensionId?: string }): Promise<number> {
  const url = item.finalUrl || item.url;
  if (!FILE_HOST.test(url) || item.byExtensionId) return 0;
  if (!canUpload(await getSettings())) return 0;
  // Every open ManualsLib download page is asked; only the one offering this exact link acts.
  const tabs = await chrome.tabs.query({ url: PAGES });
  let asked = 0;
  for (const t of tabs) {
    if (t.id === undefined) continue;
    asked++;
    void chrome.tabs.sendMessage(t.id, { type: "capturedDownload", url }).catch(() => {});
  }
  return asked;
}
