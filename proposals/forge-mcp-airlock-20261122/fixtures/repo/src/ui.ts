// Public UI code. The agent may read and change this file.
import { formatPrice } from "./lib/format";

export function renderCart(items: { name: string; cents: number }[]): string {
  return items.map((i) => `${i.name}: ${formatPrice(i.cents)}`).join("\n");
}
