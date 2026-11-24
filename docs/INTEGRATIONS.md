# External integrations — what is connected and how to switch each one on

Every integration is optional. Without its key it shows **Not configured** on the **Integrations** page
(admins), and nothing is faked. A service shows **Connected** only after a real request succeeds
(press **Run checks**). "Not listed", "unavailable" and "error" never mean "safe".

| Service | What 3B uses it for | Where the key goes | Status today |
|---|---|---|---|
| Firebase Authentication | Email sign-up / sign-in / password reset; the server verifies the Firebase ID token (RS256, audience, issuer, expiry) and issues a 3B session. Roles stay in 3B (new accounts = employee). An unverified email can't take over an existing account. | `FIREBASE_PROJECT_ID` (backend), web config in `frontend/.env.local` | Project `threebees-3b-2026` created, web app registered, token verification **connected** (live check). **Email/Password sign-in must be switched on in the console** (step 1). |
| Cloudflare Tunnel | Public https link to the laptop (site + API on one address; Next forwards `/api`) | none (quick tunnel) | Working — the address changes every time the tunnel starts |
| Cloudflare Turnstile | Bot check on Report a Scam, verified by the backend (fails closed when configured) | site key → `frontend/.env.local`, secret → `backend/.env` | Code done; live round trip verified with Cloudflare's published **test** keys. Needs your own widget (step 3). |
| URLhaus (abuse.ch) | Known malware-distribution URLs | `URLHAUS_AUTH_KEY` | Code + mocked tests; needs your free key |
| VirusTotal | Multi-engine URL verdicts (lookup only — nothing is submitted) | `VIRUSTOTAL_API_KEY` | Code + mocked tests; needs your free key (≈4 lookups/min) |
| Google Safe Browsing | Google phishing/malware lists (non-commercial; Web Risk is the commercial API) | `GOOGLE_SAFE_BROWSING_API_KEY` | Code + mocked tests; needs your key |
| Google Gemini | Second AI provider, same rules and JSON schema as Claude; malformed answers are rejected | `GEMINI_API_KEY`, `THREEB_AI_PROVIDER=gemini` | Code + mocked tests; needs your free key |

Reputation lookups send the link to the provider, so they run only when **External lookups** is switched on
(with consent) in Settings. Only the first three links in a message are checked (provider quotas). Results are
cached (6 h for listed, 1 h for not listed; errors are not cached).

## Setup steps (each takes a few minutes; you create the keys yourself)

1. **Firebase email sign-in** — open
   https://console.firebase.google.com/project/threebees-3b-2026/authentication/providers →
   *Get started* → *Email/Password* → *Enable* → *Save*.
2. **Public link** — `cloudflared tunnel --url http://localhost:3000` prints a `https://….trycloudflare.com`
   address. Put it in `THREEB_PUBLIC_URL` if you want it on the Integrations page. For a fixed address use a
   named tunnel on your own Cloudflare domain.
3. **Turnstile** — Cloudflare dashboard → *Turnstile* → *Add widget* → add the hostnames you use (`localhost`
   and the tunnel host) → copy the **site key** to `NEXT_PUBLIC_TURNSTILE_SITE_KEY` (frontend) and the
   **secret key** to `CLOUDFLARE_TURNSTILE_SECRET_KEY` (backend).
4. **URLhaus** — https://auth.abuse.ch/ → sign in → create an *Auth-Key* → `URLHAUS_AUTH_KEY`.
5. **VirusTotal** — https://www.virustotal.com/ → sign up → profile → *API key* → `VIRUSTOTAL_API_KEY`.
6. **Google Safe Browsing** — Google Cloud console → enable *Safe Browsing API* → *Credentials* → *API key*
   (restrict it to that API) → `GOOGLE_SAFE_BROWSING_API_KEY`.
7. **Gemini** — https://aistudio.google.com/ → *Get API key* → `GEMINI_API_KEY` (and `THREEB_AI_PROVIDER=gemini`).

After editing `backend/.env` restart the backend; after editing `frontend/.env.local` restart the frontend.
Then open **Integrations → Run checks**.

## Not done (on purpose, for now)
- Moving data and evidence to Firestore / Firebase Storage, App Check, Cloud Functions: 3B's database and
  inert evidence storage already work; a migration is a separate project.
- Cloudflare WAF, R2 and Workers: only meaningful once 3B runs on a domain in your Cloudflare account.
- Custom claims for roles: roles live in 3B's users table and are changed by an administrator on the server.
