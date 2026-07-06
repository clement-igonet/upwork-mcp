"""
Upwork HTTP client.

Uses curl-cffi (Chrome TLS fingerprint) for all requests to bypass
Cloudflare bot protection on both the login page and API endpoints.

Authentication:
  1. UPWORK_COOKIES env var — raw Cookie header string (fastest)
  2. Cached ~/.upwork-mcp-session.json from a previous login
  3. UPWORK_LOGIN + UPWORK_PASSWD — full programmatic login flow

Bearer token strategy:
  Upwork grants two OAuth2 tokens (sb-suffixed cookies) during login.
  The second one has broader scopes (profile edits, connects, saved jobs).
  We use it as the Bearer token for all GraphQL requests.

  The oauth2_global_js_token is kept for REST endpoints (notifications).

Job search:
  The GQL job-search endpoints require scopes that a programmatic login
  does not provide.  As a fallback we parse the SSR HTML of the
  find-work page, which contains the user's personalised job feed
  with full titles and skill tags.  Client-side keyword filtering is
  applied on top.
"""
import asyncio
import json
import os
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

import websockets
from curl_cffi.requests import AsyncSession

GRAPHQL_URL = "https://www.upwork.com/api/graphql/v1"
REST_BASE = "https://www.upwork.com/api/v3"
SEARCH_BASE = "https://www.upwork.com/api/profiles/v2"
LOGIN_BASE = "https://www.upwork.com"
PORTFOLIO_UPLOAD_URL = (
    "https://www.upwork.com"
    "/api/v3/profile-projects/auth/profile/projects/files/thumbnail"
)

SESSION_FILE = Path(
    os.environ.get("UPWORK_SESSION_FILE", "~/.upwork-mcp-session.json")
).expanduser()

_CHROME_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
)
_API_HEADERS = {
    "accept": "application/json, text/plain, */*",
    "accept-language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
    "content-type": "application/json",
    "origin": "https://www.upwork.com",
    "referer": "https://www.upwork.com/",
    "user-agent": _CHROME_UA,
    "x-upwork-accept-language": "en-US",
}

# Upwork OAuth2 subordinate token endpoint (generates app-scoped bearer token from JS)
_OAUTH_SUBORDINATE = (
    "https://auth.upwork.com/api/v3/oauth2/token/subordinate/v3/"
    "ad40656599b41c597ebc81ca2e09a677"
)

# Device fingerprint tokens captured from a real Chrome browser session.
# iovation/Transmit Security blackbox — valid for extended periods on the same UA.
_IOVATION = '0400cppdXaR9opmVebKatfMjIK3PMgINKOfuLRJgWmMlghk9lR52ajpBgigZSuVgixhRv6yASvwdtELAyzwEmd4b4WTmOqLA3SnRQ2HW1vUfzl0D1Zdfe+AZ8TGgvgODUbtM1GtGYlsaO+Q3ZqiRkRBEQOOtVCzk8Gb5QfUM5mIHUwarg3Q497TjkvGl2xpLaVsbcD6T1dGUjL/a5eZzBeuVRbJB5gIzaLNO+fgAinmODDita5dOp9XVvtnX2RjZmxyebXrq1zqbQx65mZwvTfjFe6H2QNNZaQWxhgdcW8fd9Oc4z2g8OLuV+ArtlZ3ZPYc64vQjtvpyqyWRF0uY9VKFfW+2P3OpeWlXJMSUFYJ0MhWT2+W/XYUpDWqB1yvtJIm49i6YhHG67NjSt0oGtrebhuWMpUYFIHEWFvCVW4RNRsImKhhONRMH0M4DSesKkBkfBeiOThsX3U+fFbdEWBKF7kmxUPWH3Fm5rE8YIxAxgWTgKWTxcPoMukvpRlwQxt/MbZWp/5NFsh1VNt3hdRvYy+jLrUoE9at1+LDxk9BMuLR9j2MTdoFdOj5Y7m0DsmfpXcRjRsoVFFFjQrg+B67vw4yUNrHSgKXh++DiLGozWULQtVCYANQUGQ4vEesFTVfa+qqMRKptoEO9f2PXvHogeO3Gk9aWzC1qh8sUhpTflxtI185O+yC2f3lLEO0Tay66NZEyiLNePemJKSIdwO9O5ZtntuUkG6NTWEyGyPkeu3UGLDM4fZkS+HhVKFtj4RUEzX0hM3tAJxtauODchk2WrIB1NFRhR9cZ6c6+kxFUVlqPh0lrqdJN+Kh1fJQrFSBW1n74tpcOq4gNfyJw5Y9lzLhejolH6jy42HYF5oyZHJdTD4DAXqEMYyngqEPYBM4f+snP9+SWhwwQjHzFmjZC2x3+Dd6SKNckEBjYgek9rRz93jVPqiMeZeeRU0mQTUFrFFAN6Q1x80UdCdGdyqwwbTKdeSg4P+ujHRH29E2Pl68vN0XpeFtRxxRQDekNcfNFHQnRncqsMG0ynXkoOD/rox0R9vRNj5evLzdF6XhbUccUUA3pDXHzRR0J0Z3KrDBtoN6ijYgbJ3ZjjZSkBTBViIrlX+O5aTGb61Qny5FOhe+nYZCQQ+dVsLrkDpifR/qHdfJL0Vta6Q6/TDp0UzLYSzsntGrOrjOhiSkiHcDvTuVFWopiv1Rjk6BlbWMnixy0YRCREsUiSzFboTlPtKNtO32evD6q1xN2idQ9ylbHrXQNfEPyOUXe7+TNsBcSqJycMX2H742zq/GGWJpkiTeT8do7eNQCnRAuLFZ/XI2DukyAxsl5TifdBzyNGIZ39FSE+WTA9V9kv9TD7aSBsaDNxkskBWlUJe88MP3mjzkA8sw795eeAp8HIxd9Gy7EvCEuC/RnI8ZyxqZixSJzCgmmWKdY6bCyrDdW4uOv+PWCa2hpHx4BxRkDn+9vGtmc6IOB1Q85gSii9jubJ3hilB+UhphWpsp9wUR42ayNCmZIZDf9tU9mxVG4aFIlCTP+qJPgnkEdvLIexLyVjSD6LwjUchxkVLWPG8KnQq59Bpja2sPRm8izGtdlLPR3lzeTfyF2NUiV8PnDmhxxxP1NdmR0qX3GPkgUj03WJD8ZcxgUndwp5slZtYmR5NeBOdVa5XhP728a2Zzog4HVDzmBKKL2O0dYEXWlV1U+GU53aRtttvMVHkhdMlB+bfk0CuluVCSivChJNMago4VFhiNqWMwY7z9zYbbPGsQrK6ClPMisA/mRojothoVUn/mDIemP6fg4Iwzw0daa9/KUSw0lPjyRREYVI8FfE49/YvCOGioS0qrEmlYTD2WCAiBi3pfhn3mylDiZvHQDpvsXplA6956QnbFt29Nm9E0wGYcZsjouZ+ob0y1uxvejbTzmHvOZVxQkLBXn+KRCrWGLL2b9abokJHdJjIRqH2CvHm/CURv2QYXxewl5Y+/YJ/j3u1lzZNww4aSBrCgk4z+wb7cOvPweHXPjHgurOBLDAh4+v+l+mTmAi24V9UBrw5hViYWkvpztwCGB9HjULB6ob7tFfqZY66upCkkkTJEgF4gmUvK4BI/igMJ7kTJ6wa2zZ+v2aKGbjwv63kYkOzlxcIWIteDnOFXn4H87oC3ywUjyNf+qt5cWJuelMqWS1sXuEwZf9M4BiUbrahXQx6qB7YsKBgwIpd3CHm1R85iSl09jn92e7b1vGPfuTpxNsURzZJ28CqtWrU9h6VBy7cKxyuILXWyUwlf3hYUZZVUvZfdF/Xr059lIWlvbdbXidreXNrKPd6Lv2JRzNS/I7mGiCv8z3bX/sqG5ztQ7Tu2nv9eOvsyvTBXSQsDlEzm3KeebCIDzMxDNhGmYWT9sjIvh4z5rvXhCNcmMjhXmiAlfoxTbRMlZ6Az4Pk5U2Dn0xcbWi4pLopRzxc3ZN65qV41SiJT/NmEL4WPFId+Xd5B8JbvKAzWnfaXP3SvA1+ZhIj63P7NDo1hcPQTbSg6ROQ/PhBIR/2xZ/5jK3nyWurWOJHywdEvdqAkClmfkobrMaXbvOWGvvCh+KcRHZUh28FY8HkQO2k/Utn0mxFvPFeFNRMuKtt6mZ2QslQIXtC8kJLoifFrCv6/uAJdP1Gagr4ZMWr9OPb7G7KrCxXzAAeUll29S+mMiOJrfBJ2g8KAIj029wzKZEGu2XEOjNMGGO8dtJcwfYuMwhanEr1sXBBbb7L4UbygONfaO94bENg3lIf+5TDC5qfMnddlWqgx8zUFbDQdRm5JKLf052J1TxtDIC8wk0HqDs2w85evj5gzBZ81S40nNRfhhI1sFT6/+3Gr26E9lpfSd0RFAgAKn0BavMOsippCUvnllFmPUSWU7Nnj2sbZRCQ78sYZd0309m+8xVt5i9oqLpuL6jkCjoVZVc7cJNaxr1aR/mmMjPd8qCqstZDY3l2T7u7y8PA+j3LES6J0ZOt7FThTQ4zDegt/Y5pc+o0sGFF0aO/ylBQRPvnQH0a4foD4fj0tWgH/SNS40wvJVelaNCn6mJV4LoToc46k8Zyj2Zbzc9vnr7pRp8Q/fOir/MVieB7L9WkUL9TcLtobxbNs0TTqyCGwl1dBjKIao4dU1KJzwCyKGpIUXTH5kVLSKNPAIFiebRqY0jF95mWaFxaLi74qOk2JH9Fv0wkGQ4S9JKuAEMRomYLJs6aRgOEwNhUwW3yPc9RVvNwdt/8Pf3pv8USSJvxEKpWRan3KDFZG0eK73CREHfvxw1uW9EH23klFwbvo4U4ifMN0Az4ovPdxfqw9TrqEY0KUzN5zoOvj41+E5SA6QQ5BzOSEeQENcLQPzR393muZtm12EbFhTPQmtaeSHtb0p9mHIAA6a5GVLTRZsYYtWJfY6B2EMJTSjLVa7aIpXht8Bh2zNt9l5x45zoQHVrcA7IQb6KfBj35Cz7caxWnFFO4AjUdZicLNNnhgFGtV6Ka72sanJ/9RVQJuRJqUwx6TiVSNyo4SXB+lUnPvgO+hjdoo0UO7YwkJKLXY0EJZtiIYy2xWZuzSRQxFquUts1V8N5APhyIipM4mI9qXmymNocLmEpw72c+4bvt2InXhW8aji3Nuzeh+4DqYIhc13/lKBXi7OLA8anxZDlT2oYUPRPvWTvKhhQ9E+9ZO8UMhUTX3obpHcEeZuoGPDzLw+0XLAPyB1h1qULNntyanhfP9fGuloveTrEiCEO6/8UUv+3cZdeN2YGk92BsPAdBa6VqOTkbACi+1KuAMtmzblstc8FLByuxyW+hBzDVZDL8F3WupHrH4yUIFGcqBOaQpmmz3D0O0BhGPVDeuPBBxJEa5ygwP3gQ==;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'
_FORTER_TOKEN = '37971dc2d75949bba400d1f7a7b070da_1783278814466__UDF43-m4_23ck_L/TJA1ZtPs0=-622-v2_tt'


def _parse_cookie_str(raw: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for part in raw.split("; "):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies


def _parse_job_tiles(html: str) -> list[dict[str, Any]]:
    """Extract job listings from Upwork's find-work SSR HTML.

    The page embeds the personalised job feed server-side.  Job tiles follow
    the pattern /jobs/[slug]_~[cipher]/ and job titles appear in anchor text.
    Skill tags are extracted from data-test="skill" badge spans.
    """
    jobs: dict[str, dict[str, Any]] = {}

    # href="/jobs/Slug-text_~cipher/?..." > Title Text </a>
    link_re = re.compile(
        r'href="(/jobs/([^_]+)_(~[0-9a-f]{18,22})/[^"]*)"[^>]*>([^<]{5,200})</a>',
        re.IGNORECASE,
    )
    for m in link_re.finditer(html):
        url, slug, cipher, title = m.group(1), m.group(2), m.group(3), m.group(4).strip()
        if cipher not in jobs and title:
            jobs[cipher] = {
                "ciphertext": cipher,
                "url": f"https://www.upwork.com{url.split('?')[0]}",
                "title": title,
                "skills": [],
            }

    # Skill badges — <span data-test="skill...">SkillName</span>
    skill_re = re.compile(r'data-test="[^"]*skill[^"]*"[^>]*>([^<]{2,60})</span>', re.IGNORECASE)
    # Associate skills by proximity to ciphertexts (simple approach: global collect)
    # If only 1-2 jobs, attach all skills to the nearest job
    all_skills = [m.group(1).strip() for m in skill_re.finditer(html)]

    if len(jobs) == 1:
        list(jobs.values())[0]["skills"] = all_skills

    # Extract posted-time hints from common SSR snippets
    posted_re = re.compile(r'(\d+)\s+(hour|day|week|month)s?\s+ago', re.IGNORECASE)
    times = posted_re.findall(html)
    job_list = list(jobs.values())
    for i, (n, unit) in enumerate(times[: len(job_list)]):
        job_list[i]["posted"] = f"{n} {unit}s ago"

    return job_list


def _pick_bearer(cookies: dict[str, str]) -> str:
    """Return the broadest-scope Bearer token from the cookie jar.

    During Upwork login two OAuth2 tokens are set as *sb-suffixed cookies.
    The second one (in insertion order) has scopes for profile edits, connects,
    saved-jobs counts, etc.  Fall back to oauth2_global_js_token if absent.
    """
    sb_vals = [v for k, v in cookies.items() if k.endswith("sb")]
    if sb_vals:
        return sb_vals[-1]
    return cookies.get("oauth2_global_js_token", "")


class UpworkClient:
    def __init__(self) -> None:
        self._session = AsyncSession(impersonate="chrome")
        self._bearer: str = ""        # broad-scope sb token (profile, connects, …)
        self._global_bearer: str = "" # oauth2_global_js_token (REST notifications)
        self._xsrf: str = ""
        self._authenticated = False

    async def ensure_auth(self) -> None:
        if self._authenticated:
            return

        raw_cookies = os.environ.get("UPWORK_COOKIES", "").strip()
        if raw_cookies:
            cookies = _parse_cookie_str(raw_cookies)
            self._session.cookies.update(cookies)
            self._bearer = _pick_bearer(cookies)
            self._global_bearer = cookies.get("oauth2_global_js_token", self._bearer)
            self._xsrf = cookies.get("XSRF-TOKEN", "")
            self._authenticated = True
            return

        login = os.environ.get("UPWORK_LOGIN", "").strip()
        passwd = os.environ.get("UPWORK_PASSWD", "").strip()
        if not login or not passwd:
            raise RuntimeError(
                "Set UPWORK_LOGIN + UPWORK_PASSWD (or UPWORK_COOKIES) in .env"
            )

        # Try cached session
        if SESSION_FILE.exists():
            try:
                raw = json.loads(SESSION_FILE.read_text())
                saved_bearer = raw.get("__bearer__")
                cookie_list = raw.get("__cookies__", [])
                if cookie_list:
                    for c in cookie_list:
                        self._session.cookies.set(
                            c["name"], c["value"], domain=c.get("domain", "")
                        )
                    flat: dict[str, str] = {c["name"]: c["value"] for c in cookie_list}
                else:
                    # Legacy flat-dict format
                    flat = {k: v for k, v in raw.items() if not k.startswith("__")}
                    self._session.cookies.update(flat)
                self._bearer = saved_bearer or _pick_bearer(flat)
                self._global_bearer = flat.get("oauth2_global_js_token", self._bearer)
                self._xsrf = flat.get("XSRF-TOKEN", "")
                await self._raw_graphql("user-context", "query { user { id } }")
                self._authenticated = True
                return
            except Exception:
                self._session.cookies.clear()
                self._bearer = ""
                self._global_bearer = ""
                self._xsrf = ""

        await self._login(login, passwd)

    async def _login(self, login: str, passwd: str) -> None:
        """Page-based login with Transmit Security behavioral check.

        Flow:
          1. GET /ab/account-security/login  — Cloudflare cookies
          2. POST username step              — device fingerprint sent
          3. POST password step              — authToken + securityCheckCertificate
          4. WebSocket to tl.upwork.com      — behavioral check (device recognition)
          5. Poll POST with cert+token        — until status == 1 (success)
          6. GET redirectUrl                 — sets sb-scoped bearer cookies (broad scope)
        """
        nav_h = {
            "accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "accept-language": "fr-FR,fr;q=0.9,en-US;q=0.8",
            "user-agent": _CHROME_UA,
        }
        api_h = {
            "accept": "application/json, text/plain, */*",
            "content-type": "application/json",
            "origin": LOGIN_BASE,
            "referer": f"{LOGIN_BASE}/ab/account-security/login",
            "user-agent": _CHROME_UA,
            "x-requested-with": "XMLHttpRequest",
        }

        # Step 1: Cloudflare cookies
        r1 = await self._session.get(f"{LOGIN_BASE}/ab/account-security/login", headers=nav_h)
        if r1.status_code == 403:
            raise RuntimeError("Cloudflare blocked login page (403).")
        r1.raise_for_status()

        # Step 2: Username
        iovation = os.environ.get("UPWORK_IOVATION", _IOVATION)
        forter = os.environ.get("UPWORK_FORTER_TOKEN", _FORTER_TOKEN)
        await self._session.post(
            f"{LOGIN_BASE}/ab/account-security/login",
            json={"login": {"mode": "username", "username": login,
                            "iovation": iovation, "forterToken": forter,
                            "deviceType": "desktop", "elapsedTime": 3000}},
            headers=api_h,
        )

        # Step 3: Password — get authToken + securityCheckCertificate
        r3 = await self._session.post(
            f"{LOGIN_BASE}/ab/account-security/login",
            json={"login": {"mode": "password", "username": login, "password": passwd,
                            "iovation": iovation, "forterToken": forter,
                            "deviceType": "desktop", "elapsedTime": 5000, "captcha": ""}},
            headers=api_h,
        )
        body = r3.json() if r3.text else {}
        auth_token: str = body.get("authToken", "")
        cert: str = body.get("securityCheckCertificate", "")
        redirect_url: str = body.get("redirectUrl", "/nx/find-work/")

        if not auth_token:
            raise RuntimeError(
                f"Login failed — no authToken in response: {r3.status_code} {r3.text[:200]}"
            )

        # Steps 4 + 5: WebSocket behavioral check + poll until status == 1
        ws_url = (
            f"wss://tl.upwork.com/wp?app=AccountSecurity&libVersion=4.8.0"
            f"&oauth2_token={auth_token}&tml=true&base64=false"
        )
        try:
            async with websockets.connect(
                ws_url,
                additional_headers={"User-Agent": _CHROME_UA, "Origin": LOGIN_BASE},
                open_timeout=10,
            ) as ws:
                try:
                    await asyncio.wait_for(ws.recv(), timeout=5)
                except asyncio.TimeoutError:
                    pass

                for _ in range(8):
                    await asyncio.sleep(2)
                    r = await self._session.post(
                        f"{LOGIN_BASE}/ab/account-security/login",
                        json={"login": {"mode": "password", "username": login,
                                        "password": passwd, "iovation": iovation,
                                        "forterToken": forter, "deviceType": "desktop",
                                        "elapsedTime": 8000, "captcha": "",
                                        "authToken": auth_token,
                                        "securityCheckCertificate": cert}},
                        headers=api_h,
                    )
                    body = r.json() if r.text else {}
                    if body.get("securityCheckCertificate"):
                        cert = body["securityCheckCertificate"]
                    if body.get("authToken"):
                        auth_token = body["authToken"]
                    if body.get("redirectUrl"):
                        redirect_url = body["redirectUrl"]
                    if body.get("status") not in (0, 2):
                        break
        except Exception:
            pass  # WS failure is non-fatal; session cookies may still be valid

        # Step 6: Follow redirect — sets sb-scoped bearer cookies with broader OAuth2 scope
        redir_full = (
            redirect_url if redirect_url.startswith("http")
            else f"https://www.upwork.com{redirect_url}"
        )
        try:
            await self._session.get(redir_full, headers=nav_h)
        except Exception:
            pass

        cookie_list = [
            {"name": c.name, "value": c.value, "domain": c.domain or "", "path": c.path or "/"}
            for c in self._session.cookies.jar
        ]
        flat = {c["name"]: c["value"] for c in cookie_list}
        self._bearer = _pick_bearer(flat)
        self._global_bearer = flat.get("oauth2_global_js_token", self._bearer)
        self._xsrf = flat.get("XSRF-TOKEN", "")

        SESSION_FILE.write_text(json.dumps({"__bearer__": self._bearer, "__cookies__": cookie_list}))
        self._authenticated = True

    async def aclose(self) -> None:
        await self._session.close()

    # ------------------------------------------------------------------
    # Core request helpers
    # ------------------------------------------------------------------

    def _auth_headers(self) -> dict[str, str]:
        h = dict(_API_HEADERS)
        if self._bearer:
            h["authorization"] = f"Bearer {self._bearer}"
        if self._xsrf:
            h["x-odesk-csrf-token"] = self._xsrf
        return h

    async def _raw_graphql(
        self,
        alias: str,
        query: str,
        variables: dict[str, Any] | None = None,
    ) -> Any:
        payload: dict[str, Any] = {"query": query}
        if variables:
            payload["variables"] = variables
        resp = await self._session.post(
            f"{GRAPHQL_URL}?alias={alias}",
            json=payload,
            headers=self._auth_headers(),
        )
        resp.raise_for_status()
        body = resp.json()
        if "errors" in body:
            raise RuntimeError(f"GraphQL errors [{alias}]: {body['errors']}")
        return body.get("data")

    async def graphql(
        self,
        alias: str,
        query: str,
        variables: dict[str, Any] | None = None,
    ) -> Any:
        await self.ensure_auth()
        return await self._raw_graphql(alias, query, variables)

    async def rest_get(self, path: str) -> Any:
        await self.ensure_auth()
        resp = await self._session.get(
            f"{REST_BASE}{path}", headers=self._auth_headers()
        )
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Named queries (from HAR recordings)
    # ------------------------------------------------------------------

    async def get_user_context(self) -> Any:
        return await self.graphql(
            "user-context",
            "query { user { id rid nid } requestMetadata { sudo } }",
        )

    async def get_profile(self) -> Any:
        """Return freelancer profile (aggregates + personalData).

        Uses fields confirmed accessible with the sb-bearer token.
        The profile.description field requires a browser-level scope;
        use update_profile_description to write and the geospatial resource
        to get the canonical bio template.
        """
        return await self.graphql(
            "profile.retrieve",
            """
            query {
              user {
                freelancerProfile {
                  aggregates {
                    jobSuccessScore topRatedStatus
                    totalFixedJobs totalHourlyJobs
                    totalEarnings { displayValue currency }
                  }
                  portrait { portrait }
                  userPreferences { visibilityLevel }
                  availability { id capacity name }
                  personalData {
                    contractToHire
                    firstName lastName title profileUrl
                  }
                }
              }
            }
            """,
        )

    async def get_profile_additional(self) -> Any:
        return await self.graphql(
            "profile.additionalInfo.retrieve",
            """
            query {
              freelancerPendingInvitations { totalCount }
              freelancerOffersCount
              freelancerVisibilityStatus { locked risky allocated notFound }
              freelancerApplicationsCount { accepted activated }
            }
            """,
        )

    async def update_profile_description(self, description: str) -> Any:
        return await self.graphql(
            "updateOverviewGql",
            """
            mutation updateTalentProfileDescription($input: TalentProfileDescriptionInput!) {
              updateTalentProfileDescription(input: $input) { status }
            }
            """,
            {"input": {"description": description}},
        )

    async def get_connects_balance(self) -> Any:
        return await self.graphql(
            "get-connects-payments-balances",
            """
            query getConnectsPaymentsBalances($input: ConnectsPaymentsBalancesInput!) {
              getConnectsPaymentsBalances: connectsPaymentsBalances(input: $input) {
                connectsBalance
                adCreditsBalance
                totalBalance
              }
            }
            """,
            {"input": {"productCode": "FL_BOOSTED_PROFILES"}},
        )

    async def get_connects_summary(self) -> Any:
        return await self.graphql(
            "boost-init-connects",
            "query { connectsSummary { connectsBalance } }",
        )

    async def get_saved_jobs_count(self) -> Any:
        return await self.graphql(
            "savedJobsCount.retrieve",
            "query savedJobsCount { personSavedJobCount { count } }",
        )

    async def search_jobs(
        self,
        query: str = "",
        sort: str = "recency",
        page: int = 0,
        per_page: int = 10,
        job_type: str | None = None,
        budget_min: int | None = None,
        budget_max: int | None = None,
        experience_level: list[int] | None = None,
    ) -> Any:
        """Search jobs.

        Upwork's job-search GraphQL requires scopes that programmatic login
        doesn't grant.  We parse the SSR HTML of the find-work page instead,
        which contains the personalised job feed, then filter client-side.
        When UPWORK_COOKIES contains a full browser session the personalised
        feed will reflect the user's saved search preferences.
        """
        await self.ensure_auth()
        html = await self._fetch_find_work_html()
        jobs = _parse_job_tiles(html)

        # Client-side keyword filter
        kw = query.lower()
        if kw:
            jobs = [
                j for j in jobs
                if kw in j.get("title", "").lower()
                or any(kw in s.lower() for s in j.get("skills", []))
                or kw in j.get("description", "").lower()
            ]

        # Sort and paginate
        start = page * per_page
        return {
            "jobs": jobs[start : start + per_page],
            "total": len(jobs),
            "page": page,
            "per_page": per_page,
            "source": "find-work-feed",
        }

    async def _fetch_find_work_html(self) -> str:
        resp = await self._session.get(
            f"{LOGIN_BASE}/nx/find-work/",
            headers={**_API_HEADERS, "accept": "text/html,application/xhtml+xml,*/*;q=0.8"},
        )
        resp.raise_for_status()
        return resp.text

    async def get_job_details(self, ciphertext: str) -> Any:
        return await self.graphql(
            "gql-query-fetchjobdetailsandcontext",
            """
            query fetchJobDetailsAndContext($ciphertext: String!) {
              fetchJobDetailsAndContext(ciphertext: $ciphertext) {
                companyId topClient enterpriseClient
                idVerificationRequired phoneVerificationRequired
                qualifications {
                  locationCheckRequired localMarket minHoursWeek
                  minJobSuccessScore prefEnglishSkill risingTalent
                }
                job {
                  ciphertext title description publishedOn
                  skills { uid prettyName }
                  occupations { uid prettyName }
                  client {
                    totalSpent { displayValue }
                    totalFeedback totalReviews
                    location { country }
                  }
                  contractorTier duration
                }
              }
            }
            """,
            {"ciphertext": ciphertext},
        )

    async def get_job_proposals_info(self, ciphertext: str) -> Any:
        return await self.graphql(
            "gql-query-proposalsopenings",
            """
            query ($ciphertext: String!) {
              proposalsOpenings(ciphertext: $ciphertext) {
                clientSuspended
                opening {
                  id hideBudget publishTime freelancerMilestonesAllowed
                  hourlyBudgetMax hourlyBudgetMin
                  job { info { type } budget { amount } }
                }
                questions { questions { question } }
              }
            }
            """,
            {"ciphertext": ciphertext},
        )

    async def get_suggested_bid(self, job_uid: str) -> Any:
        return await self.graphql(
            "getSuggestedBid",
            """
            query ($jobPostUid: ID!) {
              bidsJobPostUid(jobPostUid: $jobPostUid, includeSuggestedBid: true) {
                suggestedBid { medianBid p80Bid p90Bid }
              }
            }
            """,
            {"jobPostUid": job_uid},
        )

    async def pre_apply_check(self, ciphertext: str) -> Any:
        return await self.graphql(
            "gql-query-preapplycheck",
            """
            query preApplyCheck($ciphertext: String!) {
              preApplyCheck(ciphertext: $ciphertext) { passed error }
            }
            """,
            {"ciphertext": ciphertext},
        )

    async def get_interview_invitations(
        self, status: str = "Pending", limit: int = 10
    ) -> Any:
        # status values: "Pending", "Active", "Declined", "Withdrawn"
        return await self.graphql(
            "interviewInvitations",
            """
            query interviewInvitations(
              $status: InterviewInvitationStatus!
              $pagination: Pagination
            ) {
              interviewInvitations(status: $status, pagination: $pagination) {
                totalCount count
                pageInfo { endCursor }
                invitations {
                  topClient uid: id
                  jobPostingUid: openingId
                  title: openingTitle
                  viewed
                  clientCompanyPublic {
                    country { name }
                    paymentVerification { paymentVerified }
                    workHistoryStats {
                      feedbackScore totalJobsWithHires
                      totalCharges { currency displayValue }
                    }
                  }
                }
              }
            }
            """,
            {"status": status, "pagination": {"first": limit}},
        )

    async def get_notifications_unread_count(self) -> Any:
        # notifications REST requires oauth2_global_js_token, not the sb token
        await self.ensure_auth()
        h = dict(_API_HEADERS)
        if self._global_bearer:
            h["authorization"] = f"Bearer {self._global_bearer}"
        resp = await self._session.get(
            f"{REST_BASE}/notification-feed/notifications/unreadCount", headers=h
        )
        resp.raise_for_status()
        return resp.json()

    async def get_contractor_rate(self, person_uid: str) -> Any:
        return await self.graphql(
            "gql-query-contractorsrate",
            "query ($contractorUid: ID!) { contractorsRate(personUid: $contractorUid) }",
            {"contractorUid": person_uid},
        )

    async def get_person_saved_jobs(
        self, job_ids: list[str] | None = None, followed: bool = True
    ) -> Any:
        return await self.graphql(
            "gql-query-getpersonsavedjobs",
            """
            query GetPersonSavedJobs($jobIds: [ID], $followed: Boolean) {
              getPersonSavedJobs(jobIds: $jobIds, followed: $followed) {
                personSavedJobs { job { id } }
              }
            }
            """,
            {"jobIds": job_ids, "followed": followed},
        )

    async def get_boost_init(self, user_id: str) -> Any:
        return await self.graphql(
            "boost-init",
            """
            query boostInit($userId: ID!) {
              getCategories: ontologyCategories { id preferredLabel services { id preferredLabel } }
              getFreelancerProfile: user {
                freelancerProfile {
                  profileCompletenessSummary {
                    skillsCount employmentRecordCount overviewRecordCount portraitRecordCount
                  }
                  personalData { portrait { portrait100 portrait500 } firstName lastName title }
                  userPreferences { visibilityLevel }
                }
              }
              getConnectsBalance: connectsSummary { connectsBalance }
            }
            """,
            {"userId": user_id},
        )

    async def update_profile_title(self, title: str) -> Any:
        return await self.graphql(
            "updateTitle",
            """
            mutation updateTalentProfileTitle($input: TalentProfileTitleInput!) {
              updateTalentProfileTitle(input: $input) { status }
            }
            """,
            {"input": {"title": title}},
        )

    async def update_profile_hourly_rate(self, amount: float) -> Any:
        return await self.graphql(
            "updateProfileRateGql",
            """
            mutation updateTalentProfileHourlyRate($input: TalentProfileHourlyRateInput!) {
              updateTalentProfileHourlyRate(input: $input) { status }
            }
            """,
            {"input": {"hourlyRate": {"amount": amount, "currency": "USD"}}},
        )

    async def get_work_history(self, person_id: str, limit: int = 10) -> Any:
        return await self.graphql(
            "gql-query-talentworkhistory",
            """
            {
              talentWorkHistory(
                filter: {
                  personId: %s
                  status: [CLOSED]
                  excludeNoFeedback: false
                  sort: { type: NEWEST, order: ASC }
                  pagination: { first: %d, after_id: 0 }
                }
              ) {
                workHistoryList {
                  id title description
                  skills { prettyName }
                  feedback {
                    comment
                    rating { score label }
                  }
                  client { country { name } }
                  contractFrom contractTo
                  totalHoursWorked
                  amount { amount currency }
                }
                totalCount
              }
            }
            """ % (person_id, limit),
        )

    async def get_portfolio_projects(self, person_id: str) -> Any:
        return await self.graphql(
            "gql-query-talentportfolioprojects",
            """
            {
              talentPortfolioProjects(
                filter: {
                  personId: %s
                  pageSize: 10
                  page: 0
                  sortDirection: DESC
                  sortFields: ["rank"]
                }
              ) {
                projects {
                  id title description
                  skills { prettyName }
                  completionDate
                }
                totalProjects
              }
            }
            """ % person_id,
        )

    async def get_job_match_score(self, job_id: str, vendor_id: str) -> Any:
        return await self.graphql(
            "gql-query-vendormatches",
            """
            query vendorMatches($input: VendorMatchesInput!) {
              vendorMatches(input: $input) {
                totalPrefs
                totalMatches
                matchingDetails {
                  fieldName match preferred preferredLabel fieldLabel
                  subFields { fieldName match actual preferred }
                }
              }
            }
            """,
            {"input": {"vendorId": vendor_id, "jobId": job_id, "agency": False}},
        )

    async def get_connects_for_job(self, job_id: str, person_id: str) -> Any:
        try:
            return await self.graphql(
                "gql-query-connectsforjobapply-jobfeatureincurrentsubscription",
                """
                query($jobId: ID!, $freelancerPersonId: ID!, $agencyId: ID, $isAgency: Boolean!, $feature: SubscriptionFeatureEnum) {
                  connectsForJobApply(jobId: $jobId, freelancerId: $freelancerPersonId, agencyId: $agencyId) {
                    connects connectsV2Applicable canBuyConnects canApply
                    jobsPrice
                    priceDetails { pricing { price auctionPrice } }
                  }
                  hasFeatureInSubscription: organization {
                    featureInCurrentSubscription(feature: $feature) {
                      value: featureInCurrentSubscription
                    }
                  }
                }
                """,
                {
                    "jobId": job_id,
                    "freelancerPersonId": person_id,
                    "agencyId": None,
                    "isAgency": False,
                    "feature": "MAXIMUM_AGENCY_SIZE",
                },
            )
        except RuntimeError as exc:
            if "oauth2 permissions" in str(exc):
                return {"connectsForJobApply": None, "note": "requires browser session scope"}
            raise

    async def get_job_fee(
        self, opening_id: str, freelancer_id: str | None = None
    ) -> Any:
        return await self.graphql(
            "gql-query-talentfeebyopeningid",
            """
            query talentFeeByOpeningId($openingId: ID!, $freelancerId: ID, $agencyOrgUid: ID) {
              talentFeeByOpeningId(openingId: $openingId, freelancerId: $freelancerId, agencyOrgUid: $agencyOrgUid) {
                reasonCode feePercent
              }
            }
            """,
            {
                "openingId": opening_id,
                "freelancerId": freelancer_id,
                "agencyOrgUid": None,
            },
        )

    async def get_competing_bids(self, job_uid: str) -> Any:
        return await self.graphql(
            "gql-query-bidsjobpostuid",
            """
            query ($jobPostUid: ID!) {
              bidsJobPostUid(jobPostUid: $jobPostUid, filter: IN_THE_MONEY) {
                bids { id amount createdTime }
              }
            }
            """,
            {"jobPostUid": job_uid},
        )

    async def get_account_health(self) -> Any:
        try:
            return await self.graphql(
                "account-health-status",
                "query GetAccountHealthStatus { accountHealthStatus }",
            )
        except RuntimeError as exc:
            if "oauth2 permissions" in str(exc):
                return {"accountHealthStatus": "unknown", "note": "requires browser session scope"}
            raise

    async def get_connects_data(self, job_id: str) -> Any:
        """Connects balance + cost to apply for a specific job (confirmed working from HAR)."""
        return await self.graphql(
            "gql-query-get-connects-data",
            """
            query connectsDataForFreelancer($jobId: ID!) {
              pricingJobPost: jobConnectsPriceFreelancer(jobId: $jobId) {
                price context auctionPrice
              }
              connectsSummary: jobFreelancerConnectsSummary {
                connectsBalance
              }
            }
            """,
            {"jobId": job_id},
        )

    async def get_proposals(self, job_id: str | None = None) -> Any:
        """List submitted proposals. Optionally filter to a specific job."""
        if job_id:
            return await self.graphql(
                "gql-query-get-applications-freelancer",
                """
                query ($jobId: ID!) {
                  jobApplications: jobApplicationsFreelancer(jobId: $jobId) {
                    applications { id firstName lastName }
                    canSubmitMoreProposals
                  }
                }
                """,
                {"jobId": job_id},
            )
        # Without a jobId, fall back to SSR page scraping
        await self.ensure_auth()
        resp = await self._session.get(
            f"{LOGIN_BASE}/nx/proposals/",
            headers={**_API_HEADERS, "accept": "text/html,application/xhtml+xml,*/*;q=0.8"},
        )
        resp.raise_for_status()
        html = resp.text
        # Extract proposal IDs from href="/nx/proposals/<id>" links
        ids = re.findall(r'/nx/proposals/(\d{16,20})\b', html)
        return {"proposal_ids": list(dict.fromkeys(ids)), "source": "proposals-page"}

    async def submit_proposal(
        self,
        job_id: str,
        cover_letter: str,
        charged_amount: float,
        nid: str,
        person_id: str,
        questions: list | None = None,
        milestones: list | None = None,
        attachments: list | None = None,
    ) -> Any:
        return await self.graphql(
            "gql-mutation-createproposal",
            """
            mutation createProposal($input: CreateProposalInput!) {
              createProposal(input: $input) {
                success
                newProposalId
              }
            }
            """,
            {
                "input": {
                    "jobReference": job_id,
                    "chargedAmount": charged_amount,
                    "coverLetter": cover_letter,
                    "attachments": attachments or [],
                    "boostBidAmount": None,
                    "sri": {"percent": 5, "frequency": 3},
                    "gitHubRepoLink": None,
                    "umaThreadId": None,
                    "umaTouched": False,
                    "questions": questions or [],
                    "occupationId": None,
                    "milestones": milestones or [],
                    "selectedContractor": {
                        "oDeskUserID": nid,
                        "id": person_id,
                    },
                }
            },
        )

    async def get_messages(
        self, unread_only: bool = False, limit: int = 20
    ) -> Any:
        await self.ensure_auth()
        resp = await self._session.get(
            f"{LOGIN_BASE}/nx/messages/",
            headers={**_API_HEADERS, "accept": "text/html,application/xhtml+xml,*/*;q=0.8"},
        )
        resp.raise_for_status()
        html = resp.text
        # Extract room IDs from href="/nx/messages/<id>" links
        room_ids = re.findall(r'/nx/messages/(\d{10,20})\b', html)
        return {"room_ids": list(dict.fromkeys(room_ids))[:limit], "source": "messages-page"}

    # ------------------------------------------------------------------
    # Portfolio
    # ------------------------------------------------------------------

    def _cookie_only_headers(self) -> dict[str, str]:
        """Cookie-only headers for mutations that reject Bearer auth (skills, portfolio)."""
        h = dict(_API_HEADERS)
        h.pop("authorization", None)
        if self._xsrf:
            h["x-odesk-csrf-token"] = self._xsrf
        return h

    async def find_skills(self, query: str, limit: int = 20) -> Any:
        """Search Upwork skill ontology by preferred label. Returns id + preferredLabel."""
        return await self.graphql(
            "findSkills",
            """
            query searchSkillsByPrefLabel(
              $query: String!, $type: OntologyEntityType!,
              $status: OntologyEntityStatus!, $ordering: String!, $limit: Int!
            ) {
              ontologyElementsSearchByPrefLabel(filter: {
                preferredLabel_any: $query, type: $type,
                entityStatus_eq: $status, sortOrder: $ordering, limit: $limit
              }) { id preferredLabel }
            }
            """,
            {"query": query, "type": "SKILL", "status": "ACTIVE",
             "ordering": "match-start", "limit": limit},
        )

    async def upload_portfolio_image(
        self, image_bytes: bytes, filename: str, content_type: str = "image/png"
    ) -> dict[str, str]:
        """Upload image to Upwork portfolio CDN.

        Returns dict with fileUid, imageLargeUid, imageMiddleUid,
        imageSmallUid, imageFixedWidthUid — pass to create_portfolio_project.
        """
        await self.ensure_auth()
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else "png"
        params = {
            "file-name": filename,
            "file-extension": ext,
            "content-length": str(len(image_bytes)),
            "content-type": content_type,
            "resize-thumbnails": "true",
        }
        resp = await self._session.post(
            PORTFOLIO_UPLOAD_URL,
            params=params,
            content=image_bytes,
            headers={
                "accept": "*/*",
                "content-type": "application/octet-stream",
                "origin": "https://www.upwork.com",
                "referer": "https://www.upwork.com/",
                "user-agent": _CHROME_UA,
                "x-upwork-accept-language": "en-US",
                **({"x-odesk-csrf-token": self._xsrf} if self._xsrf else {}),
            },
        )
        resp.raise_for_status()
        return resp.json()

    async def create_portfolio_project(
        self,
        title: str,
        description: str,
        role: str = "",
        project_url: str | None = None,
        skill_ids: list[str] | None = None,
        image_uids: dict[str, str] | None = None,
    ) -> Any:
        """Create a portfolio project using the createTalentPortfolio mutation.

        image_uids: dict returned by upload_portfolio_image
          (fileUid, imageLargeUid, imageMiddleUid, imageSmallUid, imageFixedWidthUid)
        skill_ids: list of ontology skill IDs from find_skills
        """
        await self.ensure_auth()

        attachments: list[dict[str, Any]] = []
        if image_uids:
            attachments.append({
                "id": None,
                "type": "image",
                "title": "",
                "attachmentName": "portfolio-image.png",
                "attachmentSize": 0,
                "rank": 1,
                "originalFileId": image_uids.get("fileUid"),
                "imageSmallId": image_uids.get("imageSmallUid"),
                "imageMiddleId": image_uids.get("imageMiddleUid"),
                "imageLargeId": image_uids.get("imageLargeUid"),
                "imageFixedWidthId": image_uids.get("imageFixedWidthUid"),
            })

        project: dict[str, Any] = {
            "title": title,
            "description": description,
            "thumbnail": None,
            "thumbnailId": image_uids.get("imageLargeUid") if image_uids else None,
            "thumbnailOriginal": None,
            "thumbnailOriginalId": image_uids.get("fileUid") if image_uids else None,
            "published": True,
            "role": role or title,
            "attachments": attachments,
            "tags": skill_ids or [],
        }
        if project_url:
            project["projectUrl"] = project_url

        fragment = """
        fragment PortfolioProjectFragment on TalentPortfolioEdge {
          node {
            uid: id title description thumbnail thumbnailUid: thumbnailId
            published projectUrl completionDate: completionDateTime
            isPublic: public rank
            attachments {
              uid: id link title rank attachmentName: fileName
              attachmentSize: fileSize type imageSmall imageLarge
            }
            tags {
              freeText
              ontologySkill: skill { uid: id prefLabel: preferredLabel }
            }
          }
        }
        """
        mutation = fragment + """
        mutation ($project: TalentPortfolioCreateInput!) {
          createTalentPortfolio(portfolio: $project) {
            ...PortfolioProjectFragment
          }
        }
        """
        resp = await self._session.post(
            f"{GRAPHQL_URL}?alias=createPortfolioProject",
            json={"query": mutation, "variables": {"project": project}},
            headers=self._cookie_only_headers(),
        )
        resp.raise_for_status()
        body = resp.json()
        if "errors" in body:
            raise RuntimeError(f"GraphQL errors [createPortfolioProject]: {body['errors']}")
        return body.get("data")

    # ------------------------------------------------------------------
    # Skills
    # ------------------------------------------------------------------

    async def get_profile_skills(self, profile_url: str = "~01f6303b10e07608a5") -> Any:
        """Return skills currently set on the profile."""
        return await self.graphql(
            "getProfileSkills",
            """
            query getProfileSkills($profileUrl: String) {
              talentVPDAuthProfile(filter: { profileUrl: $profileUrl }) {
                profile {
                  skills {
                    node {
                      uid: id
                      prettyName
                      active
                      rank
                    }
                  }
                }
              }
            }
            """,
            {"profileUrl": profile_url},
        )

    async def update_profile_skills(self, skill_ids: list[str]) -> Any:
        """Replace the profile skill list (full replace, not append).

        skill_ids: list of ontology skill IDs from find_skills.
        Max 15 skills per Upwork's limit.
        """
        await self.ensure_auth()
        skills = [{"skillID": sid} for sid in skill_ids[:15]]
        resp = await self._session.post(
            f"{GRAPHQL_URL}?alias=updateSkillsGql",
            json={
                "query": """
                mutation updateTalentProfileSkills($input: TalentProfileSkillsInput!) {
                  updateTalentProfileSkills(input: $input) { status }
                }
                """,
                "variables": {"input": {"skills": skills}},
            },
            headers=self._cookie_only_headers(),
        )
        resp.raise_for_status()
        body = resp.json()
        if "errors" in body:
            raise RuntimeError(f"GraphQL errors [updateSkillsGql]: {body['errors']}")
        return body.get("data")
