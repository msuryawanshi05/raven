"""Thread-safe bridge from a sync hunt thread to a per-session asyncio Queue.

agent/loop.py imports put_message conditionally. When no queue is registered for
a session_id (CLI-only mode), put_message is a no-op.
"""
SESSION_QUEUES = {}  # session_id -> asyncio.Queue
SESSION_LOOPS = {}   # session_id -> the event loop that owns the queue


def register(session_id, queue, loop):
    SESSION_QUEUES[session_id] = queue
    SESSION_LOOPS[session_id] = loop


def unregister(session_id):
    SESSION_QUEUES.pop(session_id, None)
    SESSION_LOOPS.pop(session_id, None)


def get_queue(session_id):
    return SESSION_QUEUES.get(session_id)


def put_message(session_id, msg):
    """Called from the hunt thread. Schedules the put on the queue's event loop."""
    q = SESSION_QUEUES.get(session_id)
    loop = SESSION_LOOPS.get(session_id)
    if not session_id or q is None or loop is None:
        return
    try:
        loop.call_soon_threadsafe(q.put_nowait, msg)
    except Exception:  # loop closed / queue full: dropping a UI message is harmless
        pass
