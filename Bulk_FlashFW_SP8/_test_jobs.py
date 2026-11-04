"""Unit tests for app.jobs.JobManager - no browser/network needed."""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
os.environ.setdefault("DEV_BYPASS_AUTH", "1")
os.environ.setdefault("BIND_HOST", "127.0.0.1")

from app.jobs import JobManager  # noqa: E402


async def test_basic_job_runs_and_captures_output():
    mgr = JobManager()
    job = mgr.start([sys.executable, "-c", "print('hello'); print('world')"], owner="user-a", kind="test")
    while not job.done:
        await asyncio.sleep(0.05)
    assert job.exit_code == 0, job.exit_code
    assert job.lines == ["hello", "world"], job.lines
    print("PASS: a trivial job's stdout is captured line by line and exit code recorded")


async def test_owner_isolation():
    mgr = JobManager()
    job = mgr.start([sys.executable, "-c", "print('x')"], owner="user-a", kind="test")
    while not job.done:
        await asyncio.sleep(0.05)
    assert mgr.get(job.id, owner="user-a") is not None
    assert mgr.get(job.id, owner="user-b") is None, "a different owner must not be able to fetch this job"
    print("PASS: a job is only visible to the owner who started it")


async def test_status_line_parsing():
    mgr = JobManager()
    script = (
        "import sys; "
        "print('  [OK] sys1  (3s)  log: C:\\\\logs\\\\sys1.log'); "
        "print('  [FAILED (exit 1)] sys2  (5s)  log: C:\\\\logs\\\\sys2.log')"
    )
    job = mgr.start([sys.executable, "-c", script], owner="user-a", kind="test")
    while not job.done:
        await asyncio.sleep(0.05)
    assert job.statuses["sys1"]["status"] == "ok", job.statuses
    assert job.statuses["sys2"]["status"] == "failed", job.statuses
    print("PASS: flash_fleet.py's [OK]/[FAILED] summary lines are parsed into per-system statuses")


async def test_subscribe_replays_buffered_lines_after_completion():
    mgr = JobManager()
    job = mgr.start([sys.executable, "-c", "print('done already')"], owner="user-a", kind="test")
    while not job.done:
        await asyncio.sleep(0.05)
    q = job.subscribe()
    first = await q.get()
    assert first == "done already", first
    sentinel = await q.get()
    assert sentinel is None, "a late subscriber to a finished job must get the buffered lines then the end sentinel"
    print("PASS: subscribing after a job already finished replays its buffered output, then signals the end")


async def main():
    await test_basic_job_runs_and_captures_output()
    await test_owner_isolation()
    await test_status_line_parsing()
    await test_subscribe_replays_buffered_lines_after_completion()
    print("\nALL PASS")


if __name__ == "__main__":
    asyncio.run(main())
