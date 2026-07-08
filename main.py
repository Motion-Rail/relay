"""
Fibre Tone Tester — relay service.

Field app  ──►  this relay (holds token)  ──►  EXFO FMS cloud (raman.ems.exfo-fms.com)

Wired end to end from captured requests:
  LOGIN    POST {AUTH_BASE}/auth/realms/Fiber/protocol/openid-connect/token
           client_id=fg-topologyui, grant_type=password, form-urlencoded.
  RESOLVE  POST {GRAPHQL_URL}  operation searchOpticalRouteByRtu (matchType CONTAINS),
           paginated, maps fibre name -> {id, rtuId}. Primed per route stem.
  TONE     {TONE_METHOD} {TOPO_HOST}{TONE_PATH with {route_id}}
           body {"name":"", "payload":"<stringified inner>"}
           inner {"MeasurementType":"PonXplorer;TimedSource;Modulation=<freq>;Duration=<dur>",
                  "WavelengthsUsed":[<wavelength m>]}

Set LIVE_TONE=1 to actually call EXFO; otherwise tones are simulated.
"""

import os
import re
import json
import time
import uuid
import httpx
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ── EXFO auth ────────────────────────────────────────────────────────────────
AUTH_BASE     = os.getenv("EXFO_AUTH_BASE",  "https://raman.ems.exfo-fms.com")
TOKEN_PATH    = os.getenv("EXFO_TOKEN_PATH", "/auth/realms/Fiber/protocol/openid-connect/token")
CLIENT_ID     = os.getenv("EXFO_CLIENT_ID",  "fg-topologyui")
CLIENT_SECRET = os.getenv("EXFO_CLIENT_SECRET", "")
SCOPE         = os.getenv("EXFO_SCOPE", "")

# ── Topology host + GraphQL resolver + tone call ─────────────────────────────
TOPO_HOST   = os.getenv("TOPO_HOST", "https://raman.ems.exfo-fms.com")   # confirmed same host
GRAPHQL_URL = os.getenv("GRAPHQL_URL", TOPO_HOST.rstrip("/") + "/topology/graphql/graphql")
TONE_PATH   = os.getenv("TONE_PATH", "/api/topology/control/opticalroutes/{route_id}/testsetup/build")
TONE_METHOD = os.getenv("TONE_METHOD", "POST").upper()
TONE_ID_FIELD = os.getenv("TONE_ID_FIELD", "id")   # which node field feeds {route_id}: id | rtuId
LIVE_TONE   = os.getenv("LIVE_TONE", "0") == "1"

MEAS_PAYLOAD_TEMPLATE = os.getenv(
    "MEAS_PAYLOAD_TEMPLATE",
    '{"MeasurementType":"PonXplorer;TimedSource;Modulation={freq};Duration={duration}",'
    '"WavelengthsUsed":[{wl_m}]}'
)
SETUP_NAME  = os.getenv("SETUP_NAME", "")
PAGE_SIZE   = int(os.getenv("PAGE_SIZE", "50"))

# ── relay access ─────────────────────────────────────────────────────────────
APP_KEY    = os.getenv("APP_KEY", "")
APP_ORIGIN = os.getenv("APP_ORIGIN", "*")
TOKEN_TTL_FALLBACK = int(os.getenv("TOKEN_TTL_FALLBACK", "900"))

app = FastAPI(title="Fibre Tone Tester relay")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[APP_ORIGIN] if APP_ORIGIN != "*" else ["*"],
    allow_methods=["*"], allow_headers=["*"],
)

SESSIONS: dict[str, dict] = {}          # session_id -> {access, refresh, exp, user}
ROUTE_ID_CACHE: dict[str, dict] = {}    # FIBRE NAME (upper) -> {"id":..., "rtuId":...}

# GraphQL query (compact; requests only the fields we map)
SEARCH_QUERY = (
    "query searchOpticalRouteByRtu($search: String, $condition: OpticalRouteSearchOutputCondition, "
    "$orderBy: OpticalRouteSearchOutputsOrderBy!, $first: Int!, $offset: Int!) { "
    "routeSearchResult: searchOpticalRouteByRtu(matchType: CONTAINS, search: $search, condition: $condition, "
    "orderBy: $orderBy, first: $first, offset: $offset) { totalCount nodes { id name rtuId portId "
    "testSetup { id name __typename } __typename } __typename } }"
)


def _fill(t, **kw):
    for k, v in kw.items():
        t = t.replace("{" + k + "}", str(v))
    return t

def _wl_metres(nm):
    return ("%.12f" % (nm * 1e-9)).rstrip("0").rstrip(".")

def _stem(fibre):
    return re.sub(r"-F\d+$", "", fibre, flags=re.I)

def _check_key(x_app_key):
    if APP_KEY and x_app_key != APP_KEY:
        raise HTTPException(401, "Bad or missing app key")


# ── auth ──────────────────────────────────────────────────────────────────────
async def _grant(data):
    data = {"client_id": CLIENT_ID, **data}
    if CLIENT_SECRET: data["client_secret"] = CLIENT_SECRET
    if SCOPE:         data["scope"] = SCOPE
    async with httpx.AsyncClient(timeout=20) as c:
        r = await c.post(AUTH_BASE.rstrip("/") + TOKEN_PATH, data=data,
                         headers={"Content-Type": "application/x-www-form-urlencoded"})
    return r

async def _password_grant(username, password):
    r = await _grant({"grant_type": "password", "username": username, "password": password})
    if r.status_code != 200:
        raise HTTPException(401, f"EXFO login failed ({r.status_code}): {r.text[:200]}")
    return r.json()

async def _refresh_grant(refresh_token):
    r = await _grant({"grant_type": "refresh_token", "refresh_token": refresh_token})
    if r.status_code != 200:
        raise HTTPException(401, "Session expired — sign in again")
    return r.json()

def _store(sid, tok, user):
    ttl = int(tok.get("expires_in", TOKEN_TTL_FALLBACK))
    SESSIONS[sid] = {"access": tok["access_token"], "refresh": tok.get("refresh_token", ""),
                     "exp": time.time() + ttl - 30, "user": user}

async def _valid_token(sid):
    s = SESSIONS.get(sid)
    if not s:
        raise HTTPException(401, "No session — sign in again")
    if time.time() >= s["exp"]:
        if not s["refresh"]:
            raise HTTPException(401, "Session expired — sign in again")
        _store(sid, await _refresh_grant(s["refresh"]), s["user"])
    return SESSIONS[sid]["access"]


# ── resolver (GraphQL searchOpticalRouteByRtu) ────────────────────────────────
async def _graphql_search(token, search, first, offset):
    payload = {"operationName": "searchOpticalRouteByRtu",
               "variables": {"search": search, "condition": {}, "orderBy": "NAME_ASC",
                             "first": first, "offset": offset},
               "query": SEARCH_QUERY}
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.post(GRAPHQL_URL, headers=headers, content=json.dumps(payload))
    if not (200 <= r.status_code < 300):
        raise HTTPException(502, f"Route search failed ({r.status_code}): {r.text[:200]}")
    data = r.json()
    if data.get("errors"):
        raise HTTPException(502, f"GraphQL error: {json.dumps(data['errors'])[:200]}")
    res = (data.get("data") or {}).get("routeSearchResult") or {}
    return res.get("totalCount", 0), res.get("nodes", []) or []

async def _prime(token, search, max_pages=20):
    offset, total, primed = 0, None, 0
    while True:
        tc, nodes = await _graphql_search(token, search, PAGE_SIZE, offset)
        if total is None:
            total = tc
        for n in nodes:
            name = str(n.get("name", "")).upper()
            if name:
                ROUTE_ID_CACHE[name] = {"id": str(n.get("id", "")), "rtuId": str(n.get("rtuId", ""))}
                primed += 1
        offset += PAGE_SIZE
        if not nodes or offset >= (total or 0) or offset >= PAGE_SIZE * max_pages:
            break
    return primed, total

async def _resolve_route_id(token, fibre):
    key = fibre.upper()
    if key not in ROUTE_ID_CACHE:
        await _prime(token, _stem(fibre))          # prime the whole cable from the stem
    if key not in ROUTE_ID_CACHE:
        _, nodes = await _graphql_search(token, fibre, PAGE_SIZE, 0)  # fall back to exact search
        for n in nodes:
            if str(n.get("name", "")).upper() == key:
                ROUTE_ID_CACHE[key] = {"id": str(n.get("id", "")), "rtuId": str(n.get("rtuId", ""))}
    if key not in ROUTE_ID_CACHE:
        raise HTTPException(404, f"No OpticalRouteID found for {fibre}")
    entry = ROUTE_ID_CACHE[key]
    rid = entry.get(TONE_ID_FIELD) or entry.get("id")
    if not rid:
        raise HTTPException(404, f"Resolved {fibre} but '{TONE_ID_FIELD}' was empty")
    return rid


# ── models ─────────────────────────────────────────────────────────────────────
class LoginIn(BaseModel):
    username: str
    password: str

class PrimeIn(BaseModel):
    search: str

class ToneIn(BaseModel):
    fibre: str
    stem: str | None = None
    wavelengthNm: int = 1550
    durationS: int = 10
    freqHz: int = 1000
    routeId: str | None = None


# ── endpoints ───────────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"ok": True, "auth_host": AUTH_BASE, "topo_host": TOPO_HOST,
            "graphql": GRAPHQL_URL, "tone": "live" if LIVE_TONE else "simulated",
            "tone_id_field": TONE_ID_FIELD, "cached": len(ROUTE_ID_CACHE), "client": CLIENT_ID}

@app.post("/api/login")
async def login(body: LoginIn, x_app_key: str | None = Header(default=None)):
    _check_key(x_app_key)
    tok = await _password_grant(body.username, body.password)
    sid = uuid.uuid4().hex
    _store(sid, tok, body.username)
    return {"session_id": sid, "user": body.username}

@app.post("/api/prime")
async def prime(body: PrimeIn, x_app_key: str | None = Header(default=None),
                x_session: str | None = Header(default=None)):
    _check_key(x_app_key)
    token = await _valid_token(x_session)
    primed, total = await _prime(token, body.search)
    return {"ok": True, "primed": primed, "totalCount": total}

@app.post("/api/tone")
async def tone(body: ToneIn, x_app_key: str | None = Header(default=None),
               x_session: str | None = Header(default=None)):
    _check_key(x_app_key)

    if not LIVE_TONE:
        return {"ok": True, "simulated": True,
                "detail": f"(simulated) tone {body.fibre} @ {body.wavelengthNm}nm "
                          f"{body.durationS}s {body.freqHz}Hz"}

    token = await _valid_token(x_session)
    route_id = body.routeId or await _resolve_route_id(token, body.fibre)

    inner = _fill(MEAS_PAYLOAD_TEMPLATE,
                  freq=body.freqHz, duration=body.durationS, wl_m=_wl_metres(body.wavelengthNm))
    outer = json.dumps({"name": SETUP_NAME, "payload": inner})
    url = _fill(TONE_PATH, route_id=route_id)
    if not url.startswith("http"):
        url = TOPO_HOST.rstrip("/") + url

    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.request(TONE_METHOD, url, headers=headers, content=outer)
    if not (200 <= r.status_code < 300):
        raise HTTPException(502, f"EXFO tone call failed ({r.status_code}): {r.text[:200]}")
    return {"ok": True, "status": r.status_code, "route_id": route_id, "detail": r.text[:300]}
