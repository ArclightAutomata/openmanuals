// turuta.md adapter. The members' listing (/service-manuals.php) names each
// manual's model, brand and category; only a signed-in member sees the file
// link, so rows are matched by product (brand + model) rather than by page.
// A row whose model has a free copy gets a mark linking to its OpenManuals page.
import { rowProduct, type RowProduct } from "../core/turuta.ts";

async function annotate(): Promise<void> {
  const rows = [...document.querySelectorAll<HTMLTableRowElement>('tr[valign="center"]')];
  const items: { row: HTMLTableRowElement; p: RowProduct }[] = [];
  for (const row of rows) {
    const p = rowProduct([...row.querySelectorAll("td")].map((td) => td.textContent ?? ""));
    if (p && !row.querySelector("a.om-mark")) items.push({ row, p });
  }
  for (let i = 0; i < items.length; i += 300) {
    const batch = items.slice(i, i + 300);
    const res = (await chrome.runtime.sendMessage({ type: "lookupProducts", source: "turuta", products: batch.map((x) => x.p) }).catch(() => null)) as
      { found?: ({ url: string; title: string } | null)[] } | null;
    batch.forEach(({ row }, j) => {
      const hit = res?.found?.[j];
      if (!hit || row.querySelector("a.om-mark")) return;
      const a = document.createElement("a");
      a.className = "om-mark";
      a.href = hit.url;
      a.target = "_blank";
      a.rel = "noopener";
      a.textContent = "✓ Free";
      a.title = `Free on OpenManuals: ${hit.title}`;
      (row.lastElementChild ?? row).append(" ", a);
    });
  }
}

if (/^\/service-manuals\.php$/i.test(location.pathname)) void annotate();
