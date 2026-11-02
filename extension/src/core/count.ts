// Short counts for tight spaces: 13, 1.3K, 134K, 2.5M (in the browser's locale).
const compact = new Intl.NumberFormat(undefined, { notation: "compact" });
const full = new Intl.NumberFormat();

export function compactCount(n: number): string { return compact.format(n); }
export function fullCount(n: number): string { return full.format(n); }
/** "1 fact", "134K facts". */
export function factsLabel(n: number): string { return `${compactCount(n)} ${n === 1 ? "fact" : "facts"}`; }
