# upwork-mcp

MCP (Model Context Protocol) server for Upwork — lets AI assistants like Claude search jobs, manage proposals, and update your freelancer profile directly from a conversation.

## Features

31 tools across six categories:

**Profile & Account**
- `get_user_context` — logged-in user ID and account info
- `get_profile` / `get_profile_additional` — full profile data
- `update_profile_title` — change your headline
- `update_profile_hourly_rate` — change your hourly rate
- `update_profile_description` — change your overview/bio
- `get_account_health` — job success score and top-rated status
- `get_work_history` — past contracts for any user
- `get_portfolio_projects` — portfolio items for any user

**Connects & Billing**
- `get_connects_balance` — current connects + ad credits balance
- `get_connects_data` — balance + cost to apply for a specific job
- `get_connects_for_job` — connects price for a job/person combo

**Job Search & Analysis**
- `search_jobs` — keyword search with filters
- `get_job_details` — full job description, budget, client info
- `get_job_proposals_info` — proposal count and bid range
- `get_competing_bids` — competing bid stats for a job
- `get_suggested_bid` — Upwork's suggested bid for a job
- `get_job_match_score` — match percentage between job and vendor
- `get_job_fee` — Upwork service fee for a job
- `pre_apply_check` — full pre-apply analysis (bids, score, cost, fee)

**Proposals**
- `submit_proposal` — submit a proposal with cover letter and bid
- `get_proposals` — list your submitted proposals
- `get_boost_init` — boost/sponsored data for a job

**Notifications & Saved Jobs**
- `get_notifications_unread_count` — unread notification count
- `get_interview_invitations` — pending interview invites
- `get_person_saved_jobs` — jobs saved/followed by the user
- `get_saved_jobs_count` — count of saved jobs
- `get_messages` — inbox messages (all or unread only)

**Rates & Contractors**
- `get_contractor_rate` — hourly rate for another freelancer

## Setup

### 1. Install

```bash
git clone https://github.com/clement-igonet/upwork-mcp.git
cd upwork-mcp
uv sync
```

### 2. Configure credentials

Create a `.env` file in the **parent directory** of the project (one level up):

```bash
# /path/to/parent/.env
UPWORK_LOGIN=your@email.com
UPWORK_PASSWD=yourpassword
MCP_TRANSPORT=streamable-http
MCP_PORT=8080
```

The server manages its own session entirely — no manual cookie copying required.

### 3. Start the server

**With uv (recommended):**
```bash
MCP_TRANSPORT=streamable-http MCP_PORT=8080 uv run python -m upwork_mcp
```

**With Docker (once network support is available in your container runtime):**
```bash
docker build -t upwork-mcp:latest .
docker run -d \
  --env-file /path/to/parent/.env \
  -p 8080:8080 \
  upwork-mcp:latest
```

### 4. Connect Claude Code

Add to `~/.claude.json` (or your Claude config):

```json
{
  "mcpServers": {
    "upwork": {
      "type": "http",
      "url": "http://localhost:8080/mcp"
    }
  }
}
```

Restart Claude Code — the `upwork` tools will appear.

## How login works

On first call the server performs a full browser-emulated login:

1. GET login page → Cloudflare cookies
2. POST username + iovation/forterToken device fingerprint
3. POST password → receives `authToken` + `securityCheckCertificate`
4. WebSocket to `tl.upwork.com` — Transmit Security behavioral check
5. Poll until `status == 1` (device recognized)
6. Follow the success redirect → sets sb-scoped OAuth2 bearer cookies

The session is cached in `~/.upwork-mcp-session.json` and reused on subsequent calls. When it expires the full login runs again automatically.

**Device fingerprints** (`UPWORK_IOVATION`, `UPWORK_FORTER_TOKEN`) can be overridden via environment variables if the hardcoded ones are rotated by Upwork.

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `UPWORK_LOGIN` | yes | Upwork account email |
| `UPWORK_PASSWD` | yes | Upwork account password |
| `MCP_TRANSPORT` | no | `stdio` (default), `sse`, or `streamable-http` |
| `MCP_PORT` | no | Port for HTTP transports (default `8080`) |
| `UPWORK_SESSION_FILE` | no | Override session cache path |
| `UPWORK_IOVATION` | no | Override iovation device fingerprint |
| `UPWORK_FORTER_TOKEN` | no | Override Forter device token |

## License

Apache 2.0
