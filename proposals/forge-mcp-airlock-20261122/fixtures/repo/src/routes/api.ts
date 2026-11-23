// SERVER FIXTURE (route handlers). FIXTURE-VISIBLE-DOMAIN-HIDDEN-routes-api-0d9e
import { checkSession } from "./auth";
export function handleCart(token: string): number {
  return checkSession(token) ? 200 : 401;
}
