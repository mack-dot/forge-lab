// SERVER/AUTH FIXTURE. Not in visible_paths: an agent with visible_paths ["src/ui/**", "README.md"]
// must not see it. FIXTURE-VISIBLE-DOMAIN-HIDDEN-routes-auth-71ac
export function checkSession(token: string): boolean {
  return token.startsWith("sess_") && token.length === 37; // fake auth rule
}
