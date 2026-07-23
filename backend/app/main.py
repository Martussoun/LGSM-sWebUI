import asyncio, json, time, random
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from slowapi import Limiter
from slowapi.util import get_remote_address
from fastapi import FastAPI, HTTPException, Request, Body
from fastapi.responses import StreamingResponse, JSONResponse, PlainTextResponse
from backend.app.registry import ServerRegistry, ServerStatus
from fastapi.staticfiles import StaticFiles
from backend.app.auth import verify_password, create_session, SESSION_COOKIE, SESSION_MAX_AGE_SECONDS, require_auth
from pydantic import BaseModel
from typing import List
from backend.db.init_db import engine, Admin, revoke_all_sessions, create_db_and_tables
from sqlmodel import Session, select
from fastapi.middleware.cors import CORSMiddleware

limiter = Limiter(key_func=get_remote_address, default_limits=["2 per minute"])
reservation_lock = asyncio.Lock()
registry = ServerRegistry()
db=Session(engine)
MIN_LOGIN_TIME = 0.8
JITTER = 0.03


@asynccontextmanager
async def lifespan(app: FastAPI):
    revoke_all_sessions()
    registry.scan()
    await registry.reconcile_unknown()
    yield

app = FastAPI(title="LinuxGSM Server Control API", version="0.6.0",lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "Cookie"],
)
create_db_and_tables()

class LoginData(BaseModel):
    username: str
    password: str

@app.post("/auth/login")
@limiter.limit("12 per minute")
def login(data: LoginData, request: Request):
    start = time.perf_counter()
    try:
        with Session(engine) as db:
            admin = db.exec(
                select(Admin).where(Admin.username == data.username)
            ).first()

            # USER MUST EXIST
            if not admin:
                verify_password(None, data.password)
                raise HTTPException(status_code=401, detail="Invalid credentials")

            # CHECK IF REVOKED
            if admin.revoked_access:
                verify_password(None, data.password)
                raise HTTPException(status_code=403, detail="Access revoked")

            # LOCK CHECK
            if admin.is_locked:
                if admin.locked_until and datetime.now(timezone.utc).replace(tzinfo=None) < admin.locked_until:
                    raise HTTPException(status_code=403, detail="Account locked")
                else:
                    # unlock if time passed
                    admin.is_locked = False
                    admin.failed_attempts = 0
                    admin.locked_until = None
                    db.add(admin)
                    db.commit()

            # VERIFY PASSWORD
            if not verify_password(admin.pw_hash, data.password):
                admin.failed_attempts += 1

                # lock policy
                if admin.failed_attempts >= 5:
                    admin.is_locked = True
                    admin.locked_until = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=10)

                db.add(admin)
                db.commit()

                raise HTTPException(status_code=401, detail="Invalid credentials")

            # RESET FAILURES ON SUCCESS
            admin.failed_attempts = 0
            admin.is_locked = False
            admin.locked_until = None
            db.add(admin)
            db.commit()

            # CREATE SESSION (SAME DB SESSION)
            token = create_session(admin.id)

        response = JSONResponse({"ok": True})

        response.set_cookie(
            key=SESSION_COOKIE,
            value=token,
            httponly=True,
            secure=False,  # True in prod
            samesite="lax", # strict for prod
            max_age=SESSION_MAX_AGE_SECONDS,
        )

        return response
    finally:
        elapsed = time.perf_counter() - start
        remaining = MIN_LOGIN_TIME - elapsed

        if remaining > 0:
            time.sleep(remaining + random.uniform(0, JITTER))


@app.post("/auth/logout")
@limiter.limit("30 per minute")
def logout(request: Request):
    """
    Logout:
    - Revokes session in DB
    - Clears cookie
    """

    from backend.app.auth import revoke_session  # avoid circular import

    session_token = request.cookies.get(SESSION_COOKIE)

    if session_token:
        revoke_session(session_token)

    response = JSONResponse({"ok": True})
    response.delete_cookie(SESSION_COOKIE)

    return response

@app.get("/auth/session")
@limiter.limit("61 per minute")
def session_status(request: Request):
    require_auth(request)
    return {"loggedIn": True}

@app.get("/servers")
@limiter.limit("15 per minute")
def list_servers(request: Request):
    require_auth(request)
    return registry.list()

@app.post("/servers/scan")
@limiter.limit("1 per minute")
def rescan_servers(request: Request):
    require_auth(request)
    return registry.scan()

@app.post("/servers/refresh_status")
@limiter.limit("4 per minute")
async def rescan_servers(request: Request):
    require_auth(request)
    await registry.reconcile_unknown()
    return registry.list()

@app.get("/servers/{server_id}/details")
@limiter.limit("10 per minute")
def server_details(server_id: str, request: Request):
    require_auth(request)
    try:
        srv = registry.get(server_id).instance()
        return {"server_id": server_id, "details": srv.details()}
    except KeyError:
        raise HTTPException(404, "Server not found")
    except Exception as e:
        raise HTTPException(500, str(e))

@app.get("/servers/{server_id}/status")
@limiter.limit("30 per minute")
async def server_start(server_id: str, request: Request, body: dict = Body(default={})):
    require_auth(request)

    try:
        server = registry.get(server_id)
        return {"server_id": server_id, "status": server.status.value}
    except KeyError:
        raise HTTPException(404, "Server not found")
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/servers/{server_id}/start")
@limiter.limit("30 per minute")
async def server_start(server_id: str, request: Request, body: dict = Body(default={})):
    require_auth(request)

    debug_dir = Path("debug_requests")
    debug_dir.mkdir(exist_ok=True)

    timestamp = datetime.now(timezone.utc).isoformat().replace(":", "-")

    with open(debug_dir / f"{server_id}_{timestamp}.json", "w", encoding="utf-8") as f:
        json.dump(
            {
                "server_id": server_id,
                "body": body,
            },
            f,
            indent=2,
            default=str
        )

    try:
        server = registry.get(server_id)
        if server.status in {ServerStatus.STARTING, ServerStatus.LIVE}:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "already_running",
                    "server_id": server_id,
                    "status": server.status.value
                }
            )
        srv = server.instance()
        extras = body.get("extras")

        # PRE-START HOOK
        if extras:
            shortname = extras.get("shortname")
            payload = extras.get("payload", {})

            if shortname and server.shortname != shortname:
                raise HTTPException(
                    400,
                    f"Server shortname mismatch: expected {server.shortname}, got {shortname}"
                )
            handler = server.handler
            if not handler:
                raise HTTPException(500, "Server handler not found")

            if hasattr(handler, "prepare"):
                prepare_fn = handler.prepare

                if asyncio.iscoroutinefunction(prepare_fn):
                    await prepare_fn(srv, payload)
                else:
                    await asyncio.to_thread(prepare_fn, srv, payload)
                await asyncio.sleep(0.2)

        # START SERVER
        server.status = ServerStatus.STARTING
        result = await asyncio.to_thread(srv.start)
        server.status = ServerStatus.LIVE
        return {"server_id": server_id, "result": result, "status": server.status.value}

    except HTTPException:
        raise
    except KeyError:
        raise HTTPException(404, "Server not found")
    except Exception as e:
        registry.get(server_id).status = ServerStatus.UNKNOWN
        raise HTTPException(500, str(e))

@app.post("/servers/{server_id}/stop")
@limiter.limit("30 per minute")
def server_stop(server_id: str, request: Request):
    require_auth(request)
    try:
        srv = registry.get(server_id).instance()
        registry.get(server_id).status = ServerStatus.STOPPING
        result = srv.stop()
        registry.get(server_id).status = ServerStatus.FREE
        return {"server_id": server_id, "result": result}
    except KeyError:
        raise HTTPException(404, "Server not found")
    except Exception as e:
        registry.get(server_id).status = ServerStatus.UNKNOWN
        raise HTTPException(500, str(e))

@app.post("/servers/{server_id}/restart")
@limiter.limit("30 per minute")
def server_restart(server_id: str, request: Request):
    require_auth(request)
    try:
        srv = registry.get(server_id).instance()
        return {"server_id": server_id, "result": srv.restart()}
    except KeyError:
        raise HTTPException(404, "Server not found")
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/servers/{server_id}/update")
@limiter.limit("30 per minute")
def server_update(server_id: str, request: Request):
    require_auth(request)
    try:
        srv = registry.get(server_id).instance()
        return {"server_id": server_id, "result": srv.update()}
    except KeyError:
        raise HTTPException(404, "Server not found")
    except Exception as e:
        raise HTTPException(500, str(e))

@app.get("/servers/{server_id}/check-update")
@limiter.limit("30 per minute")
def server_check_update(server_id: str, request: Request):
    require_auth(request)
    try:
        srv = registry.get(server_id).instance()
        return {"server_id": server_id, "result": srv.check_update()}
    except KeyError:
        raise HTTPException(404, "Server not found")
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/servers/{server_id}/force-update")
@limiter.limit("30 per minute")
def server_force_update(server_id: str, request: Request):
    require_auth(request)
    try:
        srv = registry.get(server_id).instance()
        return {"server_id": server_id, "result": srv.force_update()}
    except KeyError:
        raise HTTPException(404, "Server not found")
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/servers/{server_id}/validate")
@limiter.limit("30 per minute")
def server_validate(server_id: str, request: Request):
    require_auth(request)
    try:
        srv = registry.get(server_id).instance()
        return {"server_id": server_id, "result": srv.validate()}
    except KeyError:
        raise HTTPException(404, "Server not found")
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/servers/reserve/{game_shortname}")
@limiter.limit("30 per minute")
async def reserve_server(game_shortname: str, request: Request):
    require_auth(request)
    async with reservation_lock:
        # Filter candidates by shortname
        candidates = [
            s for s in registry._servers.values()
            if s.shortname == game_shortname and s.status in (ServerStatus.FREE, ServerStatus.UNKNOWN)
        ]

        # Reconcile only UNKNOWN servers
        unknowns = [s for s in candidates if s.status == ServerStatus.UNKNOWN]
        if unknowns:
            await registry.reconcile_unknown()  # pass only relevant servers

        # Re-filter after reconciliation
        free_candidates = [s for s in candidates if s.status == ServerStatus.FREE]
        if not free_candidates:
            raise HTTPException(404, f"No available server found for {game_shortname}")

        server = free_candidates[0]
        server.status = ServerStatus.RESERVED

        return {"server_id": server.id, "shortname": server.shortname}

@app.post("/servers/{server_id}/release")
@limiter.limit("30 per minute")
async def release_server(server_id: str, request: Request):
    require_auth(request)
    try:
        srv = registry.get(server_id)
    except KeyError:
        raise HTTPException(404, f"Server not found: {server_id}")

    # Only attempt release if server is RESERVED or LIVE
    if srv.status in [ServerStatus.RESERVED, ServerStatus.LIVE, ServerStatus.STARTING]:
        try:
            # If the server is LIVE, stop it first
            if srv.status == ServerStatus.LIVE:
                await asyncio.to_thread(srv.instance().stop)

            # Mark server as free
            srv.status = ServerStatus.FREE
            return {"server_id": server_id, "status": "released"}

        except Exception as e:
            srv.status = ServerStatus.ERROR
            raise HTTPException(500, f"Failed to release server {server_id}: {e}")

    # Already free or unknown → just return current status
    return {"server_id": server_id, "status": srv.status.value}


@app.get("/servers/{server_id}/start/stream")
@limiter.limit("30 per minute")
def start_server_stream(server_id: str, request: Request):
    require_auth(request)
    srv = registry.get(server_id).instance()
    registry.get(server_id).status = ServerStatus.LIVE
    return StreamingResponse(
        srv.start_stream(),
        media_type="text/event-stream"
    )

@app.get("/servers/{server_id}/stop/stream")
@limiter.limit("30 per minute")
def stop_server_stream(server_id: str, request: Request):
    require_auth(request)
    srv = registry.get(server_id).instance()
    registry.get(server_id).status = ServerStatus.FREE
    return StreamingResponse(
        srv.stop_stream(),
        media_type="text/event-stream"
    )

@app.get("/servers/{server_id}/restart/stream")
@limiter.limit("30 per minute")
def restart_server_stream(server_id: str, request: Request):
    require_auth(request)
    srv = registry.get(server_id).instance()
    return StreamingResponse(
        srv.restart_stream(),
        media_type="text/event-stream"
    )

@app.get("/servers/{server_id}/details/stream")
@limiter.limit("10 per minute")
def details_stream(server_id: str, request: Request):
    require_auth(request)
    srv = registry.get(server_id).instance()
    return StreamingResponse(
        srv.details_stream(),
        media_type="text/event-stream"
    )

@app.get("/servers/{server_id}/check-update/stream")
@limiter.limit("30 per minute")
def check_update_stream(server_id: str, request: Request):
    require_auth(request)
    srv = registry.get(server_id).instance()
    return StreamingResponse(
        srv.check_update_stream(),
        media_type="text/event-stream"
    )

@app.get("/servers/{server_id}/update/stream")
@limiter.limit("30 per minute")
def update_server_stream(server_id: str, request: Request):
    require_auth(request)
    srv = registry.get(server_id).instance()
    return StreamingResponse(
        srv.update_stream(),
        media_type="text/event-stream"
    )

@app.get("/servers/{server_id}/force-update/stream")
@limiter.limit("30 per minute")
def force_update_server_stream(server_id: str, request: Request):
    require_auth(request)
    srv = registry.get(server_id).instance()
    return StreamingResponse(
        srv.force_update_stream(),
        media_type="text/event-stream"
    )

@app.get("/servers/{server_id}/validate/stream")
@limiter.limit("30 per minute")
def validate_server_stream(server_id: str, request: Request):
    require_auth(request)
    srv = registry.get(server_id).instance()
    return StreamingResponse(
        srv.validate_stream(),
        media_type="text/event-stream"
    )


@app.get("/servers/{id}/lgsm/configs")
@limiter.limit("30 per minute")
def list_lgsm_configs(id: str, request: Request) -> List[str]:
    require_auth(request)
    srv = registry.get(id)
    if not srv:
        raise HTTPException(status_code=404, detail="Server not found")

    # Return filenames only
    return [p.name for p in srv.handler.list_lgsm_configs()]


# Read a specific LGSM config
@app.get("/servers/{id}/lgsm/configs/{name}", response_class=PlainTextResponse)
@limiter.limit("30 per minute")
def read_lgsm_config(id: str, name: str, request: Request):
    require_auth(request)
    srv = registry.get(id)
    if not srv:
        raise HTTPException(status_code=404, detail="Server not found")

    try:
        text = srv.handler.read_lgsm_config(name)
        return PlainTextResponse(content=text)  # preserves formatting
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Config file not found")
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e))


# Write a specific LGSM config
@app.post("/servers/{id}/lgsm/configs/{name}")
@limiter.limit("30 per minute")
def write_lgsm_config(id: str, name: str, request: Request, content: str = Body(..., media_type="text/plain")):
    require_auth(request)
    srv = registry.get(id)
    if not srv:
        raise HTTPException(status_code=404, detail="Server not found")

    try:
        # Attempt to write the config
        srv.handler.write_lgsm_config(name, content)
        return {"detail": "Config saved successfully"}
    except FileNotFoundError:
        # File doesn’t exist → return 404 instead of crashing
        raise HTTPException(status_code=404, detail=f"Config file '{name}' not found")
    except ValueError as e:
        # Security / path validation issues
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        # Catch-all for unexpected errors
        raise HTTPException(status_code=500, detail=str(e))



@app.get("/servers/{id}/game/configs")
@limiter.limit("30 per minute")
def list_game_configs(id: str, request: Request):
    require_auth(request)
    """
    List all available game server .cfg files for a server as JSON.
    """
    # Lookup the server
    srv = registry.get(id)
    if not srv:
        raise HTTPException(status_code=404, detail="Server not found")

    files = srv.handler.list_game_configs()
    if not files:
        return []

    # Convert to relative paths for clarity
    result = []
    for f in files:
        for cfg_root in srv.handler.game_config_dirs():
            try:
                result.append(str(f.relative_to(cfg_root)))
                break
            except ValueError:
                continue

    return result


# Read a specific game config
@app.get("/servers/{id}/game/configs/{name}", response_class=PlainTextResponse)
@limiter.limit("30 per minute")
def read_game_config(id: str, name: str, request: Request):
    require_auth(request)
    srv = registry.get(id)
    if not srv:
        raise HTTPException(status_code=404, detail="Server not found")

    try:
        text = srv.handler.read_game_config(name)
        return PlainTextResponse(content=text)  # preserves formatting
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Config file not found")
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e))


# Write a specific game config
@app.post("/servers/{id}/game/configs/{name}")
@limiter.limit("30 per minute")
def write_game_config(id: str, name: str, request: Request, content: str = Body(..., media_type="text/plain")):
    require_auth(request)
    srv = registry.get(id)
    if not srv:
        raise HTTPException(status_code=404, detail="Server not found")

    try:
        # Attempt to write the config
        srv.handler.write_game_config(name, content)
        return {"detail": "Config saved successfully"}
    except FileNotFoundError:
        # File doesn’t exist → return 404 instead of crashing
        raise HTTPException(status_code=404, detail=f"Config file '{name}' not found")
    except ValueError as e:
        # Security / path validation issues
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        # Catch-all for unexpected errors
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/configs")
@limiter.limit("30 per minute")
async def list_all_configs(request: Request):
    require_auth(request)
    """
    Return a flat, deduplicated list of all config paths from all servers.
    Each item includes the server_id, key, label, and absolute path.
    """
    return registry.all_config_paths()


@app.get("/configs/{key}/files")
@limiter.limit("30 per minute")
def list_files_for_config(key: str, request: Request):
    """
    Returns all servers using the specified config path and the editable files
    under that path. The key comes from `registry.all_config_paths()`.
    """
    require_auth(request)

    # Find the config entry by key
    config_entry = None
    for entry in registry.all_config_paths():
        if entry["key"] == key:
            config_entry = entry
            break

    if not config_entry:
        raise HTTPException(status_code=404, detail=f"Config key not found: {key}")

    result = {}
    config_path = config_entry["path"]

    # Loop over all servers that use this config path
    for server_id in config_entry["servers"]:
        try:
            srv = registry.get(server_id)
        except KeyError:
            continue  # skip if server is gone

        files = []
        if key == "lgsm":
            # Only include LGSM configs in this directory
            for p in srv.handler.list_lgsm_configs():
                if str(p.parent) == config_path:
                    files.append(p.name)
        else:
            # Game config directory
            for p in srv.handler.list_game_configs():
                if str(p.parent) == config_path:
                    files.append(p.name)

        result[server_id] = files

    return {
        "key": config_entry["key"],
        "label": config_entry["label"],
        "path": config_path,
        "servers": result,
    }

@app.get("/heartbeat")
@limiter.limit("60 per minute")
async def heartbeat(request: Request):
    async def gen():
        while True:
            yield "data: ping\n\n"
            await asyncio.sleep(5)

    return StreamingResponse(gen(), media_type="text/event-stream")


app.mount("/", StaticFiles(directory="frontend/dist", html=True), name="frontend")



