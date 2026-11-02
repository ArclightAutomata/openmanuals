// How a proof (claim URI) is shown in the options page: the service's name and
// logo, a short label, and the link. Logos are Simple Icons (CC0); only the
// ones imported here are bundled.
import {
  siActivitypub, siBluesky, siCodeberg, siDevdotto, siDiscord, siDiscourse, siForgejo, siGitea, siGithub, siGitlab,
  siKeybase, siLiberapay, siLichess, siLobsters, siMastodon, siMatrix, siOpencollective, siOrcid, siPronounsdotpage,
  siReddit, siSourcehut, siStackexchange, siTelegram, siX, siXmpp, siYcombinator,
} from "simple-icons";

/** An icon as an SVG path in a 24×24 box. */
export interface Icon { path: string; color: string }

const brand = (i: { path: string; hex: string }): Icon => ({ path: i.path, color: `#${i.hex}` });

// Generic outline icons (drawn with a stroke) for services without a logo.
export const GLOBE: Icon = { path: "M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18M3 12h18M12 3c2.5 2.5 3.6 5.6 3.6 9s-1.1 6.5-3.6 9c-2.5-2.5-3.6-5.6-3.6-9S9.5 5.5 12 3", color: "#5f6b66" };
export const KEY: Icon = { path: "M14 10a4 4 0 1 1 0-.01M11.2 12.8L4 20M7 17l2 2M5 19l2 2", color: "#5f6b66" };
export const LINK: Icon = { path: "M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1", color: "#5f6b66" };
/** Outline icons are stroked; brand logos are filled. */
export const isOutline = (i: Icon) => i === GLOBE || i === KEY || i === LINK;

/** doipjs provider id → name and logo. */
const PROVIDERS: Record<string, { name: string; icon: Icon }> = {
  activitypub: { name: "Fediverse", icon: brand(siActivitypub) },
  aspe: { name: "Keyoxide", icon: KEY },
  bsky: { name: "Bluesky", icon: brand(siBluesky) },
  discord: { name: "Discord", icon: brand(siDiscord) },
  discourse: { name: "Discourse", icon: brand(siDiscourse) },
  dns: { name: "DNS", icon: GLOBE },
  forem: { name: "Forem", icon: brand(siDevdotto) },
  forgejo: { name: "Forgejo", icon: brand(siForgejo) },
  gitea: { name: "Gitea", icon: brand(siGitea) },
  github: { name: "GitHub", icon: brand(siGithub) },
  gitlab: { name: "GitLab", icon: brand(siGitlab) },
  hackernews: { name: "Hacker News", icon: brand(siYcombinator) },
  irc: { name: "IRC", icon: LINK },
  keybase: { name: "Keybase", icon: brand(siKeybase) },
  liberapay: { name: "Liberapay", icon: brand(siLiberapay) },
  lichess: { name: "Lichess", icon: brand(siLichess) },
  lobsters: { name: "Lobsters", icon: brand(siLobsters) },
  matrix: { name: "Matrix", icon: brand(siMatrix) },
  opencollective: { name: "Open Collective", icon: brand(siOpencollective) },
  openpgp: { name: "OpenPGP", icon: KEY },
  orcid: { name: "ORCID", icon: brand(siOrcid) },
  owncast: { name: "Owncast", icon: LINK },
  pronounscc: { name: "pronouns.cc", icon: LINK },
  pronounspage: { name: "Pronouns.page", icon: brand(siPronounsdotpage) },
  reddit: { name: "Reddit", icon: brand(siReddit) },
  sourcehut: { name: "SourceHut", icon: brand(siSourcehut) },
  stackexchange: { name: "Stack Exchange", icon: brand(siStackexchange) },
  telegram: { name: "Telegram", icon: brand(siTelegram) },
  twitter: { name: "X", icon: brand(siX) },
  xmpp: { name: "XMPP", icon: brand(siXmpp) },
};

export interface ClaimDisplay {
  /** The service's name ("GitHub"), or "Website" / "Link" when unknown. */
  service: string;
  icon: Icon;
  /** Short text for the link: the URL without its scheme (or the URI as is). */
  label: string;
  /** Where clicking goes; null for URIs that aren't web pages (dns:, aspe:, …). */
  href: string | null;
}

/** When a URI matches several providers (Forgejo, Gitea, Forem, ActivityPub… all match any https URL), the likelier first. */
const PREFERENCE = ["github", "gitlab", "forgejo", "gitea", "activitypub", "discourse", "forem", "owncast"];

/**
 * Which of doipjs's candidate providers a claim most likely is: the one its
 * check confirmed (`confirmed`, a provider name like "Forgejo"), else the one
 * whose proof-repo naming the URL follows, else by PREFERENCE.
 */
export function pickProvider(uri: string, candidates: string[], confirmed?: string | null): string | undefined {
  if (candidates.length <= 1) return candidates[0];
  if (confirmed) {
    const byName = candidates.find((id) => PROVIDERS[id]?.name.toLowerCase() === confirmed.toLowerCase() || id === confirmed.toLowerCase());
    if (byName) return byName;
  }
  const path = (() => { try { return new URL(uri).pathname; } catch { return ""; } })();
  for (const [suffix, id] of [["/forgejo_proof", "forgejo"], ["/gitea_proof", "gitea"], ["/gitlab_proof", "gitlab"]] as const) {
    if (path.replace(/\/$/, "").endsWith(suffix) && candidates.includes(id)) return id;
  }
  return [...candidates].sort((a, b) => rank(a) - rank(b))[0];
}
const rank = (id: string) => { const i = PREFERENCE.indexOf(id); return i < 0 ? PREFERENCE.length : i; };

/**
 * How to show a claim. `providerId` is the provider it was matched to
 * (pickProvider), when any; Mastodon and Codeberg get their own logos on top
 * of the generic fediverse / Forgejo match.
 */
export function claimDisplay(uri: string, providerId?: string): ClaimDisplay {
  let url: URL | null = null;
  try { url = new URL(uri); } catch { /* not a URL */ }
  const web = url && (url.protocol === "https:" || url.protocol === "http:") ? url : null;
  const href = web ? web.href : null;
  const label = web ? (web.host.replace(/^www\./, "") + web.pathname.replace(/\/$/, "") + web.search + web.hash) : uri.replace(/^(dns|aspe|openpgp4fpr):/i, (m) => m.toLowerCase());
  let p = providerId ? PROVIDERS[providerId] : undefined;
  if (providerId === "forgejo" && web?.host === "codeberg.org") p = { name: "Codeberg", icon: brand(siCodeberg) };
  if (providerId === "activitypub" && web && /\/@[^/]+\/?$/.test(web.pathname)) p = { name: "Mastodon", icon: brand(siMastodon) };
  if (!p && /^dns:/i.test(uri)) p = PROVIDERS.dns;
  if (!p && /^aspe:/i.test(uri)) p = PROVIDERS.aspe;
  if (!p && /^openpgp4fpr:/i.test(uri)) p = PROVIDERS.openpgp;
  return { service: p?.name ?? (web ? "Website" : "Link"), icon: p?.icon ?? (web ? GLOBE : LINK), label, href };
}
