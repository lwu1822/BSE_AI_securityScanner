# red-vs-blue-starter

A hands-on starter project for learning how automated **code-scanning security
agents** work. You will run a small, deliberately-broken web app on your own
computer, then build an AI agent that reads the app's source code, finds a
SQL injection bug, and proves the bug is real — all on localhost.

This is the same idea as [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)
or the [PortSwigger Web Security Labs](https://portswigger.net/web-security):
a safe, intentionally vulnerable target you attack in a controlled sandbox.

> ⚠️ **For local learning only.** The practice app has security holes *on
> purpose*. It binds to `127.0.0.1` (your machine only) and must **never** be
> put on a public server or the internet.

---

## What's in here

```
red-vs-blue-starter/
  README.md
  requirements.txt
  .env.example
  .github/workflows/
    security-scan.yml # scans pull requests and comments with findings
  target_app/
    app.py            # intentionally-vulnerable sample app for the scanner
  agent/
    ci_scan.py        # complete, read-only CI scanner (no TODOs to fill in)
    llm.py            # talks to the AI model            (done for you)
    tools.py          # list_files / read_file / send_request (done for you)
    attack_agent.py   # the agent loop (the "red" attacker) -- YOU complete this
```

- **`target_app/app.py`** — a tiny Flask + SQLite app with a login route and a
  product search route. Both build their database queries by gluing your input
  straight into SQL, which is exactly how SQL injection happens. This is an
  intentionally-vulnerable sample app that the scanner is demonstrated against,
  not production code to deploy.
- **`agent/`** — the AI attacker. `llm.py` and `tools.py` are finished.
  `attack_agent.py` is a working loop with the core logic left as `TODO`s for
  you to fill in.

---

## Automated pull request security scan

`.github/workflows/security-scan.yml` runs on every `pull_request` event. It
checks out the code, sets up Python 3.12, installs `requirements.txt`, and runs
`python agent/ci_scan.py > findings.md`. The scanner reads Python files
recursively under `target_app/` and asks the model to trace user input into
SQL queries. It does not start or attack the sample app.

**Required setup:** add your API key as a repository Actions secret named
`LLM_API_KEY` under **Settings → Secrets and variables → Actions**. The workflow
uses `https://generativelanguage.googleapis.com/v1beta/openai/` as `LLM_BASE_URL`
and `gemini-3.5-flash-lite` as `LLM_MODEL`. Source code under `target_app/` is
sent to this provider; do not put secrets in the sample source.

`actions/github-script@v7` posts the markdown report as a new PR comment:
a heading followed by `file:line — description` findings, or
`No vulnerabilities found.` The comment step runs even if the scan fails
(including missing keys, API errors, rate limits, or invalid model responses)
and posts a short "Scan couldn't complete" notice instead. Scan errors leave
the workflow failed rather than silently treating an incomplete scan as clean.
Findings themselves are advisory and do not fail the workflow.

`agent/ci_scan.py` contains its own complete detection prompt and does not use
the unfinished exercises in `attack_agent.py`. For local use, install the
requirements, export `LLM_API_KEY` (optionally `LLM_BASE_URL` and `LLM_MODEL`),
and run `python agent/ci_scan.py`. Unlike the exercise agents, this CI script
reads environment variables directly and does not load `.env`.

GitHub normally withholds repository secrets and provides a read-only token
for fork PRs and Dependabot PRs. Those runs cannot perform the authenticated
scan or post a comment without appropriate GitHub permissions. Do not switch
to `pull_request_target` to run untrusted PR code with secrets. Only run
secret-enabled scans on PR code you trust. AI findings still need human review.

---

## Setup (total beginner, Windows or Mac)

You will need **Python 3.9+** installed. Check with `python --version`
(try `python3 --version` on Mac if `python` isn't found).

### 1. Get the code and open a terminal in this folder

```bash
cd red-vs-blue-starter
```

### 2. Create a virtual environment (a private sandbox for this project's packages)

**Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate
```

**Mac / Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

When it works you'll see `(.venv)` at the start of your terminal line.

### 3. Install the required packages

```bash
pip install -r requirements.txt
```

### 4. Get your free Gemini key

This project defaults to **Google Gemini's free API tier** (the `openai`
library talks to it through Gemini's OpenAI-compatible endpoint, so no code
changes are needed).

1. Go to [aistudio.google.com/apikey](https://aistudio.google.com/apikey) and
   sign in with a Google account.
2. Click **Create API key**. No credit card is needed.
3. Copy the example settings file to a real one:

   **Windows (PowerShell):**
   ```powershell
   copy .env.example .env
   ```

   **Mac / Linux:**
   ```bash
   cp .env.example .env
   ```

4. Open `.env` and paste your key into `LLM_API_KEY`. The `LLM_BASE_URL` and
   `LLM_MODEL` are already set to Gemini's free defaults, so you don't need to
   change them.

> ⏱️ The free tier has **per-minute rate limits**. If you see a "rate limit"
> or `429` error, just wait a minute and run the agent again.

> 🤖 The default free model is `gemini-3.5-flash-lite`. If it's ever
> unavailable, a good backup is `gemini-3.8-flash`, or pick another Gemini
> Flash model listed as free at
> [ai.google.dev/pricing](https://ai.google.dev/pricing) and put its name in
> `LLM_MODEL`.

> 🔒 Your `.env` holds a secret key. Don't share it or commit it to git.

---

## Run it (two terminals)

You need the target app running in one terminal and the agent in another.
**Both terminals must have the virtual environment activated** (step 2 above).

### Terminal 1 — start the practice app

```bash
python target_app/app.py
```

It will start on `http://127.0.0.1:5000`. Leave this terminal running. You can
open that address in your browser to see a little help page.

### Terminal 2 — run the agent

Run from the repo root. With no argument it scans the `target_app` folder:

```bash
python agent/attack_agent.py
```

You can also point it at a different directory by passing it as an argument
(the path is relative to the repo root; anything outside the repo is refused):

```bash
python agent/attack_agent.py target_app
python agent/attack_agent.py agent
```

The agent prints which directory it's scanning, then every step so you can
watch it think: which tool it chose, what the tool returned, and its report.

> Until you complete the `TODO`s in `attack_agent.py`, the agent won't have
> real instructions yet — that's the point! Read the next section.

---

## Your mission (the three checkpoints)

Open **`agent/attack_agent.py`**. The loop already works; you fill in the three
`TODO`s. Aim for these checkpoints in order:

### ✅ Minimum — setup working
Both terminals run without errors. The app responds at `http://127.0.0.1:5000`,
and the agent starts, calls the model, and prints steps. (It won't find the bug
yet — that's fine.)

### 🎯 Target — the agent names the vulnerable line
Complete the **system prompt (TODO #1)** and the **exact file + line reporting
(TODO #2)** so the agent uses `list_files` and `read_file`, then finishes with
a report naming the precise file and line number of a SQL injection, e.g.
`target_app/app.py` around the `/login` query.

### 🏆 Stretch — the agent confirms the exploit locally
Complete **TODO #3** so that, before finishing, the agent uses `send_request`
to actually attack the running app — for example logging in with a payload like
`' OR '1'='1` — and checks the response to prove the injection really works.

---

## Build the defense agent (red team → blue team)

Once the attack agent can find the bug, build the **defense agent** to fix it.
Open **`agent/defense_agent.py`** and fill in its two `TODO`s (the system prompt,
and the confirm-the-fix step). Its tools are just `read_file` and `write_file`.

The goal: it reads the vulnerable file, rewrites the unsafe SQL using
**parameterized queries** (the `?` placeholder style already in `seed_database`),
and writes the corrected code to a **new** file `target_app/app_fixed.py`. It
must **not** overwrite `app.py`.

Run it from the repo root (same CLI as the attack agent — the directory is a
hard boundary; it can only read/write inside it):

```bash
python agent/defense_agent.py
```

**Close the loop** — prove the fix actually works:

1. Stop the vulnerable app (Ctrl-C in Terminal 1).
2. Run the fixed app instead:
   ```bash
   python target_app/app_fixed.py
   ```
3. In Terminal 2, run the attack agent again:
   ```bash
   python agent/attack_agent.py
   ```
   The `' OR '1'='1` login bypass should now **fail** (HTTP 401) — the
   parameterized query treats the payload as literal text, not SQL.

---

## How to try the exploit yourself (to understand what the agent is doing)

Peek at the bug by hand so you know what "success" looks like. With the app
running:

**Bypass the login** (note the password turns the check into always-true):
```bash
curl -X POST http://127.0.0.1:5000/login \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"admin\", \"password\": \"' OR '1'='1\"}"
```

**Reveal a hidden product** in search:
```bash
curl "http://127.0.0.1:5000/search?q=%27%20OR%201%3D1%20--%20"
```
(That URL-encoded query is `' OR 1=1 -- ` — the `OR 1=1` makes the row filter
always true and the trailing `-- ` comments out the rest of the query,
defeating the `hidden = 0` filter so the SECRET product shows up.)

If those return data they shouldn't, the injection works — and that's exactly
what your agent should discover and confirm on its own.

---

## A note on ethics

Only ever run this against the app in this repo, on your own machine. Finding
and exploiting vulnerabilities in systems you don't own or have permission to
test is illegal. The whole point of a sandbox like this is to learn safely.
