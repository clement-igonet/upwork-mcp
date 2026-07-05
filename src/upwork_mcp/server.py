"""Upwork MCP server — exposes Upwork freelancer tools via the MCP protocol."""
from contextlib import asynccontextmanager
from typing import AsyncIterator

from mcp.server.fastmcp import FastMCP

from .client import UpworkClient

# ---------------------------------------------------------------------------
# Lifespan: one shared client per server process
# ---------------------------------------------------------------------------

_client: UpworkClient | None = None


@asynccontextmanager
async def lifespan(server: FastMCP) -> AsyncIterator[None]:
    global _client
    _client = UpworkClient()
    try:
        yield
    finally:
        await _client.aclose()
        _client = None


mcp = FastMCP("upwork", lifespan=lifespan)


def _c() -> UpworkClient:
    if _client is None:
        raise RuntimeError("Client not initialised — server not started yet")
    return _client


# ===========================================================================
# IDENTITY
# ===========================================================================


@mcp.tool()
async def get_user_context() -> dict:
    """Return the authenticated Upwork user's ID, RID, and NID."""
    return await _c().get_user_context()


# ===========================================================================
# PROFILE — read
# ===========================================================================


@mcp.tool()
async def get_profile() -> dict:
    """
    Return the freelancer profile: title, bio, hourly rate, skills,
    categories, availability, JSS, total earnings, and job counts.
    """
    return await _c().get_profile()


@mcp.tool()
async def get_profile_additional() -> dict:
    """
    Return supplementary profile info: pending invitation count, open offer
    count, visibility status (locked/risky), and application acceptance stats.
    """
    return await _c().get_profile_additional()


# ===========================================================================
# PROFILE — write
# ===========================================================================


@mcp.tool()
async def update_profile_description(description: str) -> dict:
    """
    Replace the freelancer overview / bio text.

    Uses the `updateTalentProfileDescription` GraphQL mutation recorded in
    the HAR session. The mutation is idempotent — safe to call repeatedly.

    Args:
        description: New overview text. Must be 100–5000 characters.

    Returns:
        {'updateTalentProfileDescription': {'status': True}} on success.

    Example description for geospatial focus:
        'Senior DevOps & Geospatial Architect with 24+ years of experience.
         Creator of Open-Indoor (https://github.com/open-indoor), an
         open-source indoor mapping platform. Expertise: PostGIS, GDAL,
         Shapely, GeoPandas, Kubernetes, GeoServer, vector tiles, Mapbox.'
    """
    if len(description) < 100:
        raise ValueError("Description must be at least 100 characters.")
    if len(description) > 5000:
        raise ValueError("Description must be at most 5000 characters.")
    return await _c().update_profile_description(description)


# ===========================================================================
# BALANCE / STATS
# ===========================================================================


@mcp.tool()
async def get_connects_balance() -> dict:
    """Return current connects balance and ad-credits balance."""
    return await _c().get_connects_balance()


@mcp.tool()
async def get_saved_jobs_count() -> dict:
    """Return the number of jobs the freelancer has saved/followed."""
    return await _c().get_saved_jobs_count()


# ===========================================================================
# JOB SEARCH
# ===========================================================================


@mcp.tool()
async def search_jobs(
    query: str = "",
    page: int = 0,
    per_page: int = 10,
) -> dict:
    """
    Return jobs from the personalised Upwork find-work feed, filtered by keyword.

    Upwork's GQL job-search endpoints require extended OAuth2 scopes that a
    programmatic login does not grant.  As a reliable fallback this tool parses
    the SSR HTML of the authenticated find-work page, which contains the
    jobs Upwork recommends for this account, then applies client-side keyword
    filtering.

    To get broader results set your Upwork saved-search preferences in the
    browser (category = Geospatial / GIS) — those preferences are reflected in
    the personalised feed and thus in the results here.

    Args:
        query:    Keywords to filter on, e.g. 'geospatial GIS PostGIS'.
                  Leave empty to return the full feed (up to per_page items).
        page:     Zero-based page index.
        per_page: Items per page (default 10).

    Returns:
        {'jobs': [...], 'total': N, 'source': 'find-work-feed'}
    """
    return await _c().search_jobs(query=query, page=page, per_page=per_page)


# ===========================================================================
# JOB DETAILS
# ===========================================================================


@mcp.tool()
async def get_job_details(ciphertext: str) -> dict:
    """
    Return full job posting details: title, description, client info,
    skills, qualifications, and engagement duration options.

    Args:
        ciphertext: Job ciphertext from the URL, e.g. '~022068812691817848865'.
    """
    return await _c().get_job_details(ciphertext)


@mcp.tool()
async def get_job_proposals_info(ciphertext: str) -> dict:
    """
    Return proposal context for a job: budget, hourly range, milestone
    allowance, publish time, and client screening questions.

    Args:
        ciphertext: Job ciphertext, e.g. '~022068812691817848865'.
    """
    return await _c().get_job_proposals_info(ciphertext)


@mcp.tool()
async def get_suggested_bid(job_uid: str) -> dict:
    """
    Return market bid statistics for a job: median bid, p80 bid, p90 bid.

    Args:
        job_uid: Numeric job UID without the '~02' prefix,
                 e.g. '2068812691817848865'.
    """
    return await _c().get_suggested_bid(job_uid)


@mcp.tool()
async def pre_apply_check(ciphertext: str) -> dict:
    """
    Check whether the freelancer is eligible to apply to a job.

    Args:
        ciphertext: Job ciphertext, e.g. '~022068812691817848865'.

    Returns:
        {'preApplyCheck': {'passed': bool, 'error': str | None}}
    """
    return await _c().pre_apply_check(ciphertext)


@mcp.tool()
async def get_person_saved_jobs(
    job_ids: list[str] | None = None,
    followed: bool = True,
) -> dict:
    """
    Return saved/followed jobs for the authenticated freelancer.

    Args:
        job_ids: Optional list of job IDs to filter.
        followed: If True, return only followed jobs (default True).
    """
    return await _c().get_person_saved_jobs(job_ids=job_ids, followed=followed)


# ===========================================================================
# INVITATIONS & NOTIFICATIONS
# ===========================================================================


@mcp.tool()
async def get_interview_invitations(
    status: str = "Pending",
    limit: int = 10,
) -> dict:
    """
    List interview invitations sent to the freelancer.

    Args:
        status: 'Pending' (default) | 'Active' | 'Declined' | 'Withdrawn'.
        limit:  Maximum results to return (default 10).
    """
    return await _c().get_interview_invitations(status=status, limit=limit)


@mcp.tool()
async def get_notifications_unread_count() -> dict:
    """Return the count of unread notifications in the freelancer feed."""
    return await _c().get_notifications_unread_count()


@mcp.tool()
async def get_contractor_rate(person_uid: str) -> dict:
    """
    Return the current hourly rate for a contractor.

    Args:
        person_uid: The Upwork person UID (from get_user_context).
    """
    return await _c().get_contractor_rate(person_uid)


@mcp.tool()
async def get_boost_init(user_id: str) -> dict:
    """
    Return profile categories, completeness summary, connects balance,
    and basic personal data (useful for boosting the profile).

    Args:
        user_id: Upwork user UID from get_user_context.
    """
    return await _c().get_boost_init(user_id)


# ===========================================================================
# RESOURCE — geospatial profile template
# ===========================================================================

_GEOSPATIAL_BIO = """\
I am a senior DevOps and Geospatial Solutions Architect with over 24 years of \
experience in software development, cloud infrastructure, and spatial data \
engineering. My work combines deep cloud-native DevOps expertise — Kubernetes, \
Terraform, CI/CD, Docker — with hands-on geospatial development spanning \
indoor positioning systems, GIS data pipelines, and interactive map rendering \
at scale.

As the creator and lead architect of Open-Indoor, an open-source indoor \
mapping platform hosted on GitHub, I designed and deployed systems that ingest \
OpenStreetMap floor-plan data, process it through geospatial pipelines \
(PostGIS, GDAL, GeoPandas, Shapely), and serve interactive indoor maps via \
vector tiles and REST APIs to end users worldwide.

My geospatial services include:
- Indoor and outdoor mapping systems (OpenStreetMap, GeoJSON, Mapbox, Leaflet)
- Geospatial data pipelines: ETL, PostGIS, GDAL, QGIS automation, STAC
- Cloud-native GeoServer, GeoNode and GeoWebCache on Kubernetes
- Spatial data APIs: FastAPI + PostGIS, OGC WMS/WFS/WMTS, GraphQL
- DevOps for geospatial stacks: Helm, ArgoCD, GitHub Actions, Terraform
- Satellite and drone imagery processing: rasterio, GDAL, COG, STAC

I bridge infrastructure excellence with domain-specific geospatial needs, \
ensuring your spatial data platform is reliable, scalable, and \
production-ready. Let's discuss how I can contribute to your GIS project.\
"""

_GEOSPATIAL_TITLE = (
    "GIS & Geospatial Infrastructure | Cloud DevOps, Indoor Mapping, Python"
)


# ===========================================================================
# PROFILE — write (title, rate)
# ===========================================================================


@mcp.tool()
async def update_profile_title(title: str) -> dict:
    """Update the freelancer's profile title (headline).

    Args:
        title: New title string, max 100 characters recommended.
    """
    if len(title) > 100:
        raise ValueError("Title must be at most 100 characters.")
    return await _c().update_profile_title(title)


@mcp.tool()
async def update_profile_hourly_rate(rate_usd: float) -> dict:
    """Update the freelancer's hourly rate in USD.

    Args:
        rate_usd: Hourly rate in USD (must be between 1 and 999).
    """
    if rate_usd < 1 or rate_usd > 999:
        raise ValueError("rate_usd must be between 1 and 999.")
    return await _c().update_profile_hourly_rate(rate_usd)


# ===========================================================================
# WORK HISTORY & PORTFOLIO
# ===========================================================================


@mcp.tool()
async def get_work_history(person_id: str, limit: int = 10) -> dict:
    """Return closed contracts with client feedback for a freelancer.

    Args:
        person_id: Upwork person/freelancer numeric ID.
        limit:     Maximum number of contracts to return (default 10).
    """
    return await _c().get_work_history(person_id=person_id, limit=limit)


@mcp.tool()
async def get_portfolio_projects(person_id: str) -> dict:
    """Return portfolio projects for a freelancer.

    Args:
        person_id: Upwork person/freelancer numeric ID.
    """
    return await _c().get_portfolio_projects(person_id=person_id)


# ===========================================================================
# JOB APPLICATION HELPERS
# ===========================================================================


@mcp.tool()
async def get_job_match_score(job_id: str, vendor_id: str) -> dict:
    """Return match percentage and per-field reasons for a job/freelancer pair.

    Use this before applying to understand how well you fit a job posting.

    Args:
        job_id:    Numeric job ID (strip the '~02' prefix from the ciphertext).
        vendor_id: Freelancer/vendor person ID.
    """
    return await _c().get_job_match_score(job_id=job_id, vendor_id=vendor_id)


@mcp.tool()
async def get_connects_for_job(job_id: str, person_id: str) -> dict:
    """Return the connects cost and canApply flag for a specific job.

    Args:
        job_id:    Numeric job ID (strip the '~02' prefix from the ciphertext).
        person_id: Freelancer person ID.
    """
    return await _c().get_connects_for_job(job_id=job_id, person_id=person_id)


@mcp.tool()
async def get_job_fee(opening_id: str, freelancer_id: str | None = None) -> dict:
    """Return Upwork's service fee percentage for a job opening.

    Args:
        opening_id:    Numeric opening/job ID (strip the '~02' prefix from the ciphertext).
        freelancer_id: Optional freelancer ID to personalise the fee calculation.
    """
    return await _c().get_job_fee(opening_id=opening_id, freelancer_id=freelancer_id)


@mcp.tool()
async def get_competing_bids(job_uid: str) -> dict:
    """Return the in-the-money competing bids for a job to gauge competition.

    Args:
        job_uid: Numeric job UID (strip the '~02' prefix from the ciphertext).
    """
    return await _c().get_competing_bids(job_uid=job_uid)


# ===========================================================================
# ACCOUNT HEALTH, PROPOSALS & MESSAGES
# ===========================================================================


@mcp.tool()
async def get_account_health() -> dict:
    """Return account health status (GOOD, WARNING, or SUSPENDED)."""
    return await _c().get_account_health()


@mcp.tool()
async def get_connects_data(job_id: str) -> dict:
    """Return connects balance and the cost to apply to a specific job.

    Args:
        job_id: Numeric job ID (strip the '~02' prefix from the ciphertext).
    """
    return await _c().get_connects_data(job_id=job_id)


@mcp.tool()
async def get_proposals(job_id: str | None = None) -> dict:
    """List submitted proposals.

    With job_id: returns application status for that specific job (GQL, reliable).
    Without job_id: scrapes the proposals page for proposal IDs.

    Args:
        job_id: Optional numeric job ID to check application status for a specific job.
    """
    return await _c().get_proposals(job_id=job_id)


@mcp.tool()
async def submit_proposal(
    job_id: str,
    cover_letter: str,
    charged_amount: float,
    nid: str,
    person_id: str,
    questions: list[str] | None = None,
    milestones: list[dict] | None = None,
) -> dict:
    """Submit a proposal to an Upwork job. IRREVERSIBLE — spends Connects.

    Call get_connects_data(job_id) first to confirm balance and cost.
    Call pre_apply_check(ciphertext) first to verify eligibility.

    Args:
        job_id:         Numeric job ID (strip '~02' prefix from ciphertext).
        cover_letter:   Full cover letter text.
        charged_amount: Your bid — hourly rate in USD for hourly jobs, or total for fixed-price.
        nid:            Your Upwork NID from get_user_context() (e.g. '64588a64601ff452').
        person_id:      Your Upwork user ID from get_user_context() (e.g. '2073794592179891427').
        questions:      Answers to screening questions, in order (omit if none).
        milestones:     Milestone list for fixed-price jobs (omit for hourly).
    """
    if not cover_letter or len(cover_letter) < 50:
        raise ValueError("cover_letter must be at least 50 characters.")
    if charged_amount <= 0:
        raise ValueError("charged_amount must be positive.")
    return await _c().submit_proposal(
        job_id=job_id,
        cover_letter=cover_letter,
        charged_amount=charged_amount,
        nid=nid,
        person_id=person_id,
        questions=questions,
        milestones=milestones,
    )


@mcp.tool()
async def get_messages(unread_only: bool = False, limit: int = 20) -> dict:
    """Return inbox conversation room IDs from the Upwork messages page.

    Args:
        unread_only: Ignored (filtering not available via page scraping).
        limit:       Maximum number of room IDs to return (default 20).
    """
    return await _c().get_messages(unread_only=unread_only, limit=limit)


# ===========================================================================
# PORTFOLIO
# ===========================================================================


@mcp.tool()
async def find_skills(query: str, limit: int = 20) -> dict:
    """Search Upwork skill ontology by name. Returns id + preferredLabel pairs.

    Use the returned IDs as skill_ids when calling create_portfolio_project.

    Args:
        query: Skill name(s) to search, e.g. "PostGIS" or "GDAL OpenStreetMap".
        limit: Maximum results to return (default 20).
    """
    return await _c().find_skills(query=query, limit=limit)


@mcp.tool()
async def upload_portfolio_image(image_path: str) -> dict:
    """Upload a local image file to Upwork's portfolio CDN.

    Returns UUIDs (fileUid, imageLargeUid, imageSmallUid, …) to pass
    to create_portfolio_project.

    Args:
        image_path: Absolute path to a PNG or JPEG image on disk.
    """
    from pathlib import Path
    p = Path(image_path).expanduser()
    if not p.exists():
        raise FileNotFoundError(f"Image not found: {image_path}")
    image_bytes = p.read_bytes()
    ext = p.suffix.lstrip(".").lower() or "png"
    content_type = "image/jpeg" if ext in ("jpg", "jpeg") else "image/png"
    return await _c().upload_portfolio_image(
        image_bytes=image_bytes,
        filename=p.name,
        content_type=content_type,
    )


@mcp.tool()
async def create_portfolio_project(
    title: str,
    description: str,
    role: str = "",
    project_url: str = "",
    skill_ids: list[str] | None = None,
    image_path: str = "",
) -> dict:
    """Create a portfolio project on the Upwork profile.

    Optionally uploads an image first if image_path is provided.
    Use find_skills to look up skill_ids before calling this tool.

    Args:
        title:       Project title (shown on profile card).
        description: Project description (up to ~2000 chars recommended).
        role:        Your role in the project (defaults to title if empty).
        project_url: Link to live demo or repo (optional).
        skill_ids:   List of ontology skill IDs from find_skills (optional).
        image_path:  Local path to a PNG/JPEG thumbnail image (optional).
    """
    image_uids: dict | None = None
    if image_path:
        from pathlib import Path
        p = Path(image_path).expanduser()
        if not p.exists():
            raise FileNotFoundError(f"Image not found: {image_path}")
        image_bytes = p.read_bytes()
        ext = p.suffix.lstrip(".").lower() or "png"
        content_type = "image/jpeg" if ext in ("jpg", "jpeg") else "image/png"
        image_uids = await _c().upload_portfolio_image(
            image_bytes=image_bytes,
            filename=p.name,
            content_type=content_type,
        )
    return await _c().create_portfolio_project(
        title=title,
        description=description,
        role=role,
        project_url=project_url or None,
        skill_ids=skill_ids,
        image_uids=image_uids,
    )


# ===========================================================================
# RESOURCE — geospatial profile template
# ===========================================================================


@mcp.resource("upwork://profile/geospatial-bio")
def geospatial_profile_bio() -> str:
    """
    Ready-to-use geospatial-focused profile bio for Clement I.,
    highlighting Open-Indoor project, PostGIS, GDAL, and Kubernetes.
    Character count is within the 100–5000 limit.
    """
    return _GEOSPATIAL_BIO


@mcp.resource("upwork://profile/geospatial-title")
def geospatial_profile_title() -> str:
    """Suggested profile title for geospatial positioning."""
    return _GEOSPATIAL_TITLE
