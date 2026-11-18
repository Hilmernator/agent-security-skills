# Request plans and evidence

The agent writes a plan after reading the relevant handlers. The plan is data; it cannot contain commands, launch hooks or external URLs. The one exception is the `target` of a [remote run](remote.md), which must equal the origin given to `--remote`. Keep it in a private temporary directory outside the target repo. Use synthetic IDs and expected values.

```json
{
  "target": "http://127.0.0.1:48173",
  "cases": [
    {"id": "anonymous-health", "path": "/health", "expect_status": [200]},
    {
      "id": "peer-identity",
      "path": "/api/me",
      "headers_env": {"Authorization": "DAST_PEER_AUTH"},
      "expect_status": [200],
      "expect_json": {"id": "synthetic-peer"}
    },
    {
      "id": "peer-cannot-read-owner-document",
      "path": "/api/documents/synthetic-owner-document",
      "headers_env": {"Authorization": "DAST_PEER_AUTH"},
      "requires": ["peer-identity"],
      "expect_status": [403, 404]
    }
  ]
}
```

Use the app's actual routes and policy. Add an owner identity and allowed-read control, and verify the fixture exists; otherwise a missing object can make an authorization test pass for the wrong reason. Each access case can depend on both the owner's successful read and the peer's identity check. For tests with a 200 response, assert concrete synthetic fields with `expect_json`.

Only `target` and `cases` are accepted at the top level. Cases require unique lowercase `id`, origin-relative ASCII `path`, and a nonempty array of expected status codes. Optional fields:

- `headers_env`: header names mapped to `DAST_` environment variable names. Supply complete header values via the process environment without printing them. Values must belong to disposable test accounts. Missing/invalid values reject the whole plan before the first request, and the error names the case and the variable. Transport headers cannot be overridden.
- `headers`: 1 to 10 header names mapped to a short printable text that is not a credential: `{"Origin": "https://other.example", "Accept": "text/html"}`. A `{name}` anywhere in the text is filled from a `take`, which is how a CSRF token from the sign-in answer goes back as `{"X-CSRF-Token": "{csrf}"}`, and how a cookie that was taken is sent again as `{"Cookie": "sid={sid}"}` on a case without a `session`. A name stands once in a case, in `headers` or in `headers_env`. On a loopback target `Host` may be set here, to ask what the app builds from it (a reset link); the connection still goes to 127.0.0.1. In remote mode it may not.
- `expect_json`: a nonempty object of fields the answer must hold. A nested object is compared field by field, so `{"data": {"admin": false}}` passes when the answer's `data` has other fields as well; every other value, a list included, must be equal with the same type. A value that is `{name}` and nothing else is a taken value, with its type: `{"version": "{v}"}` says the version is still the one read earlier. An answer sent as `text/event-stream` (MCP's streamable HTTP) is read as the data of its last event that has any. Returned values are never projected.
- `requires`: IDs of preceding cases that must pass without a coverage gap. Failed identity checks therefore prevent dependent access tests from running.
- `expect_text` and `forbid_text`: 1 to 20 short strings that the response body must contain, or must not contain. Use synthetic canaries (a fixture's title, another user's document ID): `forbid_text` is how a list or search case proves that the peer does not see the owner's rows. A text that is `{name}` and nothing else is a taken value, so `forbid_text: ["{old}"]` says that the answer no longer shows it. The report gives the boolean result and, when it is false, the places in the list of the texts that failed (`text (2)`), never the texts.
- `expect_canary` and `forbid_canary`: 1 to 20 SHA-256 digests (64 lowercase hex) of canary markers. The runner cuts the body into runs of letters, digits, `_` and `-` of 8 characters or more, hashes each, and checks that every expected digest is among them (`canary`), or that no forbidden one is (`canary_absent`). Prefer a marker the app's own seed data already holds; otherwise seed one in the disposable copy, such as `dast-` and 24 random hex digits. The plan holds only the digest: `printf %s MARK-acme-doc-a1 | shasum -a 256`. A marker must stand in the body with no letter, digit, `_` or `-` beside it.
- `policy`: the cell of the access policy that the case tests; see [Access policy cases](#access-policy-cases).
- `expect_headers` and `forbid_headers`: 1 to 10 response header names, each mapped to a short text. `expect_headers` passes when the header is present and its value contains the text; `forbid_headers` passes when no such header contains it. An empty text means the header itself: present, or absent. Names and texts compare without regard to case. A text that is `{name}` and nothing else is a taken value: a sign-in that must give a new session cookie expects `{"Set-Cookie": "sid="}` and forbids `{"Set-Cookie": "{before}"}`, where `before` was taken from the cookie the browser held before signing in. Use them for what an answer must announce (`{"WWW-Authenticate": "resource_metadata"}` on a 401) or must not serve (`{"Access-Control-Allow-Origin": "*"}`). Only the boolean result is projected.
- `session`: a lowercase label. The cookies a response sets are kept in memory under that label and sent with every later case that names it, whatever their `Path` and `Secure` say, so a `Secure` cookie works on `http://127.0.0.1`. A cookie the server clears is dropped. A login case and the cases of that identity share one label. An `Mcp-Session-Id` header in a response is kept and sent on the same way. Cookie values and session IDs reach only the private HAR.
- `session_token`: on a case with a `session`, the field names that lead to a token in the JSON answer, such as `["data", "auth_token"]`. The token is kept in memory under the session's label and sent as `Authorization: Bearer <token>` with every later case of that session; a case's own `Authorization` from `headers_env` wins. The case fails its `token` check when the answer holds no token there, or one that could not stand in a header. The token reaches only the private HAR.

- `same_as`: the ID of one preceding case. The case passes its `same` check when its answer has the same status and the same body, byte for byte, as that case's answer. Use it for two answers that must not differ: a failed sign-in for an account that exists and for one that does not. An answer that carries a timestamp or a request ID never compares equal; assert on its text instead.
- `take`: 1 to 4 new names, each mapped to the field names and list positions that lead to a value in the case's JSON answer, such as `{"doc": ["data", "id"]}`. A later case uses the value by writing `{doc}` in its `path` or in a `headers` text, or as a whole value in its `json` (there it keeps its type, so a number stays a number), `form` or `multipart`, or in one of its checks (`expect_json`, `expect_text`, `forbid_text`, `expect_headers`, `forbid_headers`). A value is taken from a case that fails its other checks as well: a `requires` asks for a pass, a `take` does not. Use it for an ID the app makes up: the owner creates an object, and the peer asks for it by the taken ID. A value is taken only when it is a whole number or a short text of letters, digits, `.`, `_`, `~` and `-` that does not start with a dot, so it can fill one path segment and nothing else. The case fails its `taken` check otherwise, and every case that names the value is `not-run` with the gap `value-not-taken`. Taken values reach only later requests and the private HAR.

```json
{"id": "owner-creates-document", "path": "/api/documents", "method": "POST", "session": "owner", "requires": ["owner-login"],
 "json": {"title": "synthetic-owner-title"}, "expect_status": [201], "take": {"doc": ["data", "id"]}},
{"id": "peer-cannot-read-created-document", "path": "/api/documents/{doc}", "session": "peer", "requires": ["peer-login"],
 "expect_status": [403, 404], "forbid_text": ["synthetic-owner-title"]}
```

A `take` can also name where else a value stands. Instead of the list, give an object with one source, `json` (a path as above), `header` (a response header's name), `cookie` (the name of a cookie the answer sets) or `body` (a regular expression with exactly one group, searched in the answer's text), and for `json` and `header` at most one cut, `query` (the parameter of that name) or `segment` (that path segment, counted from 1), when the value is a link:

```json
{"id": "owner-shares-document", "path": "/api/documents/synthetic-owner-document/share-links", "method": "POST", "session": "owner", "json": {"permission": "view"},
 "expect_status": [201], "take": {"link": {"json": ["url"], "segment": 2}, "sig": {"json": ["url"], "query": "sig"}}},
{"id": "authorize-redirects-with-code", "path": "/oauth/authorize?client_id=synthetic-client&response_type=code", "session": "peer",
 "expect_status": [302], "take": {"code": {"header": "Location", "query": "code"}}},
{"id": "consent-page", "path": "/oauth/consent", "session": "peer", "expect_status": [200],
 "take": {"csrf": {"body": "name=\"csrf_token\" value=\"([^\"]+)\""}}}
```

The same rule decides what is taken: one path segment's worth of safe characters. A whole URL is never taken; cut the part out of it.

Each row of `report.json` carries `body_sha256`, the hash of the answer's body, which is what `same_as` compares.

## State-changing cases

A case that changes state is accepted only when the runner is started with `--allow-writes`; without it a plan that holds one is refused before the first request.

One kind of `POST` counts as a read and needs no flag: a case whose whole `json` body is a single JSON-RPC 2.0 request with the method `initialize`, `ping`, `tools/list`, `resources/list`, `resources/templates/list`, `resources/read`, `prompts/list` or `prompts/get`, and no `json_env`. That is how an MCP endpoint is asked what it offers. `tools/call` and every other method change state as far as the runner knows, and need the flag. The rule goes by the method's name, so inspect the handler first when the endpoint is not an MCP server, as for a `GET`.

- `method`: `POST`, `PUT`, `PATCH` or `DELETE`. The default is `GET`.
- `json`: a nonempty object sent as the `application/json` request body.
- `json_env`: top-level body fields whose values come from `DAST_` environment variables, for a test account's password. The same rules as `headers_env` apply.
- `form` and `form_env`: the same two, sent as `application/x-www-form-urlencoded`: a sign-in form, an OAuth token or consent endpoint, an SSO callback. A value is a text or a whole number, and a value that is `{name}` and nothing else is filled from a `take`.
- `multipart`: fields sent as `multipart/form-data`, for an upload. A text that is `{name}` and nothing else is filled from a `take`. A field is a text, or a file: `{"filename": "note.html", "content_type": "text/html", "text": "<b>synthetic</b>"}`. Small text files only; no binary content.

A case sends one kind of body. A `Content-Type` given in `headers_env` replaces the one the body would get, which is how to ask whether the app takes a JSON body sent as `text/plain`.

```json
{"id": "peer-login", "path": "/login", "method": "POST", "session": "peer", "session_token": ["data", "auth_token"],
 "json": {"email": "peer@test.invalid"}, "json_env": {"password": "DAST_PEER_PASSWORD"},
 "expect_status": [200]},
{"id": "peer-cannot-delete-owner-document", "path": "/api/documents/synthetic-owner-document",
 "method": "DELETE", "session": "peer", "requires": ["owner-reads-document", "peer-login"],
 "expect_status": [403, 404]},
{"id": "owner-still-reads-document", "path": "/api/documents/synthetic-owner-document",
 "session": "owner", "requires": ["owner-login"], "expect_status": [200],
 "expect_text": ["synthetic-owner-document"]}
```

The example leaves out the owner's login and the owner's control read that its `requires` name. The login here answers with a token in its JSON; an app that sets a cookie needs no `session_token`, and its login may answer 303. A write's status proves little in either direction: a route can refuse and still have changed the object, or answer 204 to the peer and have changed only the peer's own record. Follow each peer write with a read by the owner that shows the object unchanged, and judge by that read. A write changes the instance, so a second run meets a different state; reset the fixtures first. A request body is at most 64 KiB.

A token lives as long as the app says. Put an identity's cases directly after its login when tokens are short-lived: each request is followed by a pause of half a second, so a plan of 50 cases takes at least 25 seconds.

A value that must be computed at send time (a one-time code, a signature over a taken value, a signed token) cannot be written in a plan. Make it outside the runner: with the app's own code in the disposable copy between two runs, passed in through a `DAST_` variable, or in remote mode by having the user sign the test account in. Reading the disposable copy's own database, outbox or log between runs, to carry a reset token into the next plan or to see what a request made the app write, is the same thing and is allowed there; say in the delivery that the value came that way. A flow that starts in one run and ends in the next (an SSO callback whose signed token holds a nonce the first run was given) keeps its browser session by sending the pending session's cookie as a `Cookie` header through `headers_env` in the second run. An expired session or link is made the same way: change its row in the disposable database between two runs. A one-time code (TOTP) lives 30 to 90 seconds: compute it right before the run and put its case first.

Check what the app's CSRF rule wants before reading a 403 on a cookie session as an access decision: a `DELETE` without a body, a form or an upload can be refused for that reason alone. Take the token from where the app gives it and send it back in `headers`, `form` or `multipart`, so the case asks what a browser would ask. The plan's own sign-ins count against the app's sign-in limit; restart the instance with each fixture reset when the limit is kept in memory.

A redirect is never followed. When the case lists the 3xx status as expected (a login that answers 303), the case passes and the report marks the redirect; an unexpected redirect is a failed assertion (a callback that signs in where it must refuse answers this way), and the report marks it as well.

Limits are 50 requests, 60 seconds for capture, at most 5 seconds per request, one MiB per response, and at least 0.5 seconds between completed requests. ZAP has an additional 120-second process limit. These are bounded request observations, not a crawler. There is no automatic retry, redirect following, DNS (except to resolve the one host of a remote run), environment proxy use or browser execution, and no cookie is kept outside a named `session`. A new run is a new budget; do not repeatedly rerun an inconclusive plan to evade it.

Run with the pinned archive, or explicitly use `--http-only` if ZAP is unavailable. The latter still evaluates cases but produces an incomplete result. Neither mode starts or stops the app, and its data changes only through the write cases the plan lists.

## Other case shapes

Access is the first question, not the only one. Write these when the app has the route; each uses fields from above and one request, or two.

- **A parameter that reaches a query.** A sort, order, filter or search parameter: one case with a value the app documents, one with a value that is no column or operator (`?sort=synthetic_no_such_column`). A sound route answers the second with a 4xx or the same list; a 500, or an answer that changes with a quote in the value, is a candidate to read in the handler. This is two bounded requests, not a scan.
- **Stored markup.** One identity writes `<b>dast-markup-canary</b>` into a title, comment or profile field; a second case reads the HTML page that shows it, as another identity, with `forbid_text: ["<b>dast-markup-canary</b>"]`. The JSON of an API may hold the text as written; the page must not. An uploaded `note.html` or SVG served back with `Content-Type: text/html` from the app's own origin is the same question, asked with `forbid_headers`.
- **Redirect targets.** A `next`, `return_to` or `redirect_uri` parameter set to `https://other.example/`, with `forbid_headers: {"Location": "other.example"}`.
- **Cross-origin answers.** `headers: {"Origin": "https://other.example"}` on a signed-in read, with `forbid_headers: {"Access-Control-Allow-Origin": "other.example"}`; again with an origin that only starts or ends like the allowed one. A signed-in page with `forbid_headers: {"Cache-Control": "public"}`.
- **CSRF.** A cookie-session write without the token, and one with a JSON body sent as `text/plain`, each followed by the owner's re-read.
- **Password reset and sign-in.** Ask for a reset twice and read the outbox: is the first token dead after the second, after use, and after its lifetime; does the link's host follow the `Host` header; does the answer differ for an unknown address (`same_as`). Does the session cookie change at sign-in (`take` a `cookie`, then `forbid_headers`), and is it dead after sign-out (send it again in `headers`)? Does the sign-in limit hold when `X-Forwarded-For` changes?
- **Server-side fetch.** A field that takes a URL (a webhook, an avatar, a metadata address), set to `http://127.0.0.1:1/` and to a loopback port of the app itself; with the network denied, read the handler and the log for whether the fetch was tried.
- **Uploads.** A file over the size limit, one with a content type the app does not list, one for an object the caller may not write.

## Running part of a plan

`--only <case id>`, given once per case, runs those cases and what they rest on: their `requires`, the case they are compared with, the cases their values come from, every earlier case that changes state, and every earlier case of a `session` that a kept case uses. So a re-read brings the write it judges, a rate-limit case brings the attempts before it, and a session brings its sign-in, with none of them in `requires`. Earlier reads without a session of their own are cut. Only the variables of the cases that run need to be set.

## Access policy cases

When the source repository's `security/profile.md` has an `## Access policy` section (security-gap-analysis proposes it, the owner confirms it), the plan tests that table, and the runner gets `--policy <source-repository>/security/profile.md`. One row per route, one column per role with `anonymous` among them, and in each cell `allow`, `deny` or `allow if <condition>`:

```markdown
## Access policy

Status: PROPOSED

| ID | Route | Resource | Action | anonymous | member | admin | Enforced at |
| --- | --- | --- | --- | --- | --- | --- | --- |
| P1 | GET /api/docs/{id} | document | read | deny | allow if own tenant | allow if own tenant | src/docs.py:41 |
| P2 | PATCH /api/docs/{id} | document | update | deny | allow if owner | allow if own tenant | no check found |
```

Make every identity the table distinguishes, not just two users: anonymous, one per role, and for each role with an `allow if` cell a second one for whom the condition fails (the same role in another tenant, or another user in the same tenant). The fixtures give each row's resource an object in the first tenant, holding a canary.

Tag each case that tests a cell with `policy`: `{"row": "P1", "role": "member", "holds": false}`. `holds` is there exactly when the cell is `allow if …`, and says whether the condition holds for this identity and this object. From the cell the runner knows whether to expect allow or deny. It refuses a plan in which an allowed case expects only refusals, or a read that the policy judges asserts nothing about the body.

- **Read, list, search.** Allowed: assert the object's canary (`expect_canary` or `expect_text`). Denied: forbid it (`forbid_canary` or `forbid_text`), whatever the status.
- **Write.** The identity's `POST`, `PUT`, `PATCH` or `DELETE`, then a read of the object with the same tag, usually by the owner. Allowed: the read shows the new value. Denied: the read still shows the canary and not the new value. When no route reads the object back, read its row in the disposable copy's database after the run and say so in the assessment; the report shows that pair as `missing-reread`.

```json
{"id": "member-a-reads-doc", "path": "/api/docs/doc-a1", "session": "member-a", "requires": ["member-a-login"],
 "policy": {"row": "P1", "role": "member", "holds": true},
 "expect_status": [200], "expect_canary": ["63de5a651634183720ba18ca95060e114e6cb19c3ff3f93404ac1cd7dd8b3d65"]},
{"id": "member-b-cannot-read-doc", "path": "/api/docs/doc-a1", "session": "member-b", "requires": ["member-b-login", "member-a-reads-doc"],
 "policy": {"row": "P1", "role": "member", "holds": false},
 "expect_status": [403, 404], "forbid_canary": ["63de5a651634183720ba18ca95060e114e6cb19c3ff3f93404ac1cd7dd8b3d65"]},
{"id": "anonymous-cannot-read-doc", "path": "/api/docs/doc-a1", "requires": ["member-a-reads-doc"],
 "policy": {"row": "P1", "role": "anonymous"},
 "expect_status": [401, 403, 404], "forbid_canary": ["63de5a651634183720ba18ca95060e114e6cb19c3ff3f93404ac1cd7dd8b3d65"]},
{"id": "member-b-cannot-rename-doc", "path": "/api/docs/doc-a1", "method": "PATCH", "session": "member-b", "requires": ["member-b-login"],
 "policy": {"row": "P2", "role": "member", "holds": false},
 "json": {"title": "dast-renamed-by-member-b"}, "expect_status": [403, 404]},
{"id": "doc-unchanged-after-member-b", "path": "/api/docs/doc-a1", "session": "member-a", "requires": ["member-a-login"],
 "policy": {"row": "P2", "role": "member", "holds": false},
 "expect_status": [200], "expect_canary": ["63de5a651634183720ba18ca95060e114e6cb19c3ff3f93404ac1cd7dd8b3d65"], "forbid_text": ["dast-renamed-by-member-b"]}
```

The report's `policy` lists every pair (row, role and `holds`) with what the policy expects, its cases, and `pass`, `fail`, `not-run`, `missing` or `missing-reread`; `review.md` shows it as a table. A pair without a case makes the run `incomplete`. When the pairs do not fit in 50 cases, split the rows over several plans and run each once. A PROPOSED policy is tested all the same; the report says its results are judged against a policy the owner has not confirmed.

## Output

`report.json` and `review.md` contain case labels, methods, status codes, assertion booleans, hashes and numeric ZAP rule metadata. `review.md` names the checks a case failed (`status`, `json`, `absent`, `taken`), for `json` the top-level fields of `expect_json` that did not hold, and for `text` and `absent` the places in the list of the texts that failed, so a failed case says which expectation did not hold. An `incomplete` report lists why in `incomplete_because`: ZAP, each case with a gap, each policy pair without a case. No response bodies, header values, raw URLs, alert descriptions or evidence strings are copied into these projections. IDs must themselves be non-sensitive labels. All ZAP alerts remain unreviewed until the agent assesses them.

ZAP instance URLs are mapped to `observed_cases` labels by method and URL, never printed. If multiple identities sent the same method to the same URL, `ambiguous_instances` records that the report cannot attribute the alert to one identity. `unmapped_instances` preserves missing associations. Use individual follow-up cases to resolve these; do not infer an offending identity from a shared URL. The original plan connects labels to routes.

The `private/` subdirectory contains the exact plan, HAR, ZAP plan, raw scanner report, log and ZAP session data. These are sensitive even when test accounts were used. Directories are private and files are restricted when run through the CLI. Do not publish them or add them to Git. They are retained for local investigation; deletion of the run directory is the retention boundary.

Map any assertion failure to source, the expected policy and reproducible behavior before calling it a vulnerability. Response limits, connection failures, unmet prerequisites and absent ZAP analysis remain explicit coverage gaps. A successful health request does not establish coverage of the rest of the app.
