// turuta.md listing rows, kept pure so they're tested without a page.

export interface RowProduct { brand: string; model: string }

/** A placeholder brand that names no maker. */
export const NO_BRAND = /^(?:none|unknown|miscellaneous|various|misc|[^\p{L}\p{N}]*)$/iu;

/**
 * A listing row's product from its cells' text: [marker, model, brand, category, link].
 * Null for rows that aren't manuals (headers, a placeholder brand, an empty model).
 */
export function rowProduct(cells: string[]): RowProduct | null {
  if (cells.length < 4) return null;
  const clean = (s: string) => s.replace(/\s+/g, " ").trim();
  const model = clean(cells[1]), brand = clean(cells[2]);
  if (!model || NO_BRAND.test(brand)) return null;
  return { brand, model };
}
