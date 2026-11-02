// An id for this build, injected by build.mjs (`define`). The settings page
// compares its own with the service worker's: Chrome keeps running an old
// service worker after a rebuild until the extension is reloaded.
declare const __OM_BUILD__: string | undefined;
export const BUILD_ID: string = typeof __OM_BUILD__ === "string" ? __OM_BUILD__ : "dev";
