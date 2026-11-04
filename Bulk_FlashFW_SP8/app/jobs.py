"""JobManager - runs a subprocess in the background and streams its output.

This is the web equivalent of flash_gui.py's QProcess usage: instead of
Qt signals (readyReadStandardOutput / finished) driving widgets directly,
each job's output lines are appended to an in-memory buffer that the SSE
endpoint in main.py polls/streams to connected browsers. Jobs are scoped
to an "owner" (the logged-in user's id) so one user can't see or stop
another's job - the whole reason per-user auth was chosen over a shared
login.
"""

import asyncio
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

# Same regex flash_gui.py uses to parse flash_fleet.py's per-system summary
# lines ("  [OK] <name>  (12s)  log: <path>") into live status updates.
STATUS_LINE_RE = re.compile(r"^\s*\[(OK|FAILED[^\]]*)\]\s+(\S+)\s+\(([\d.]+)s\)\s+log:\s+(.+)$")


@dataclass
class Job:
    id: str
    owner: str
    cmd: list
    kind: str
    created_at: float = field(default_factory=time.time)
    lines: list = field(default_factory=list)
    statuses: dict = field(default_factory=dict)  # system_name -> {"status": ..., "elapsed": ..., "log": ...}
    done: bool = False
    exit_code: Optional[int] = None
    process: Optional[asyncio.subprocess.Process] = None
    _subscribers: list = field(default_factory=list)

    def append_line(self, line: str):
        self.lines.append(line)
        m = STATUS_LINE_RE.match(line)
        if m:
            status, name, elapsed, log_path = m.groups()
            self.statuses[name] = {
                "status": "ok" if status == "OK" else "failed",
                "detail": status,
                "elapsed": elapsed,
                "log": log_path,
            }
        for q in list(self._subscribers):
            q.put_nowait(line)

    def finish(self, exit_code: int):
        self.exit_code = exit_code
        self.done = True
        for q in list(self._subscribers):
            q.put_nowait(None)  # sentinel: stream end

    def subscribe(self) -> "asyncio.Queue":
        q: asyncio.Queue = asyncio.Queue()
        for line in self.lines:
            q.put_nowait(line)
        if self.done:
            q.put_nowait(None)
        else:
            self._subscribers.append(q)
        return q


class JobManager:
    def __init__(self):
        self._jobs: dict[str, Job] = {}

    def start(self, cmd: list, owner: str, kind: str) -> Job:
        job_id = str(uuid.uuid4())
        job = Job(id=job_id, owner=owner, cmd=cmd, kind=kind)
        self._jobs[job_id] = job
        asyncio.create_task(self._run(job))
        return job

    def get(self, job_id: str, owner: str) -> Optional[Job]:
        job = self._jobs.get(job_id)
        if job is None or job.owner != owner:
            return None
        return job

    def list_for_owner(self, owner: str) -> list:
        return [j for j in self._jobs.values() if j.owner == owner]

    def stop(self, job_id: str, owner: str) -> bool:
        job = self.get(job_id, owner)
        if job is None or job.process is None or job.done:
            return False
        job.process.terminate()
        return True

    async def _run(self, job: Job):
        try:
            proc = await asyncio.create_subprocess_exec(
                *job.cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                stdin=asyncio.subprocess.DEVNULL,
            )
            job.process = proc
            assert proc.stdout is not None
            while True:
                raw = await proc.stdout.readline()
                if not raw:
                    break
                job.append_line(raw.decode(errors="replace").rstrip("\r\n"))
            exit_code = await proc.wait()
            job.finish(exit_code)
        except Exception as e:
            job.append_line(f"ERROR: job failed to start/run - {e}")
            job.finish(1)
