"""WebSocket: stream live hunt output from the per-session queue to the browser."""
import asyncio

from fastapi import APIRouter, WebSocket
from fastapi.websockets import WebSocketDisconnect

from . import bridge

router = APIRouter()


@router.websocket("/ws/hunt/{session_id}")
async def hunt_ws(websocket: WebSocket, session_id: str):
    await websocket.accept()
    q = bridge.get_queue(session_id)
    if q is None:  # no hunt registered (yet); hold a queue so reconnects work
        q = asyncio.Queue()
        bridge.register(session_id, q, asyncio.get_running_loop())

    # A receive task lets us notice the client disconnecting while we wait on the queue.
    disconnect = asyncio.create_task(websocket.receive())
    try:
        while True:
            getter = asyncio.create_task(q.get())
            done, _ = await asyncio.wait({getter, disconnect},
                                         return_when=asyncio.FIRST_COMPLETED)
            if disconnect in done:
                getter.cancel()
                break
            msg = getter.result()
            await websocket.send_json(msg)
            if msg.get("type") in ("done", "error"):
                break
    except WebSocketDisconnect:
        pass
    finally:
        disconnect.cancel()
        # Keep the queue registered: disconnecting must not kill the running hunt.
