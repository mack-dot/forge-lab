// READ-ONLY fixture test. The agent must not change it.
import { renderCart } from "../src/ui";
if (renderCart([{ name: "tea", cents: 250 }]) !== "tea: $2.50") throw new Error("ui test failed");
