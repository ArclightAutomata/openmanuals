// Shapes shared between the service worker, content scripts and pages.
import type { Fact, UnsignedFact } from "./facts.ts";

export interface SourcePage { source: string; source_id: string; kind: string; slug: string; candidates: string[] }

export interface Copy {
  url: string;
  kind: string;
  host: string;
  status: string;
  verified_at?: string;
  author?: string;
  ia?: { identifier: string; filename: string } | null;
}
export interface KnownFile {
  sha256: string;
  size?: number;
  mime?: string;
  derived_from?: string | null;
  transform?: string | null;
  canonical?: boolean;
  copies: Copy[];
}

/** What a tab's page resolves to; consumed by the banner and popup. */
export interface LookupResult {
  page: SourcePage;
  archived: boolean;
  /** "openmanuals" when the server knew the page; "legacy" when the archive.org identifier check found it. */
  via: "openmanuals" | "legacy" | "none";
  /** Set when the server was unreachable and a snapshot mirror answered instead. */
  mirror?: string;
  known: boolean;
  manual: { id: string; title: string; url: string } | null;
  files: KnownFile[];
  /** Best copy to hand the user (verified, not muted), when archived. */
  copy: Copy | null;
  title: string | null;
  archive_url: string | null;
  download_url: string | null;
  filename: string | null;
  size: number | null;
  /** Legacy identifier that would be used for lookups (informational). */
  identifier: string | null;
  openmanuals_url: string | null;
  uploadEnabled: boolean;
  hasCredentials: boolean;
  canUpload: boolean;
  hasKey: boolean;
  serverConfigured: boolean;
  error?: string;
}

export interface UploadJob {
  type: "begin";
  filename: string;
  contentType: string;
  size: number;
  metadata: { title: string; description?: string; language?: string; products: { brand: string; model: string }[] };
  sourceInfo: { source: string; sourceId: string; sourceUrl: string };
  /** True when the user asked for another copy of an already-archived file. */
  addCopy: boolean;
}

export type UploadStage = "receiving" | "hashing" | "stripping" | "checking" | "uploading" | "facts" | "done" | "exists" | "error";
export interface UploadStatus {
  type: "status";
  stage: UploadStage;
  message?: string;
  size?: number;
  archive_url?: string;
  download_url?: string;
  sha256?: string;
  stripped?: boolean;
  facts?: number;
  pending?: boolean;
  openmanuals_url?: string | null;
}

export interface OutboxEntry {
  id: string;
  createdAt: string;
  attempts: number;
  nextTry: number;
  label: string;
  facts: Fact[];
  lastError?: string;
}
export interface HistoryEntry {
  id: string;
  createdAt: string;
  acceptedAt: string;
  label: string;
  accepted: string[];
  duplicate: string[];
  rejected: { index: number; error: string }[];
}

export interface Identity {
  hasKey: boolean;
  fingerprint: string | null;
  alg: string | null;
  reason: string | null;
  aspe: string | null;
  profile: { name: string; claims: string[]; description?: string; jws: string; savedAt: string } | null;
}

export type Message =
  | { type: "lookup"; url: string }
  | { type: "lookupMany"; source: string; sourceIds: string[] }
  | { type: "getTabStatus"; tabId: number }
  | { type: "isSourcePage"; tabId: number }
  | { type: "checkCredentials"; credentials: { accessKey: string; secretKey: string } }
  | { type: "checkServer"; apiBase: string }
  | { type: "iaFetchKeys" }
  | { type: "iaStatus"; force?: boolean }
  | { type: "iaSignOut" }
  | { type: "buildId" }
  | { type: "iaSaveKeys"; accessKey: string; secretKey: string }
  | { type: "iaPasswordLogin"; email: string; password: string }
  | { type: "getIdentity" }
  | { type: "submitFacts"; facts: UnsignedFact[]; label: string }
  | { type: "saveProfile"; name: string; claims: string[]; description?: string }
  | { type: "report"; sha256?: string; target?: string; author?: string; url?: string; value: string }
  | { type: "siteHello" }
  | ({ type: "siteAction" } & import("./site.ts").SiteAction)
  | { type: "sitePage"; items: import("./site.ts").SiteAction[] }
  | { type: "siteBulk"; ops: import("./panel.ts").BulkOp[] }
  | { type: "siteHighlight"; tabId: number; key: string | null }
  | { type: "addCopy"; sha256: string; url: string }
  | { type: "avatarState" }
  | { type: "setAvatar"; body: import("./avatar.ts").AvatarBody; bytes?: string }
  | { type: "outboxState" }
  | { type: "flushOutbox" }
  | { type: "openOptions" };
