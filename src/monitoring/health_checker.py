"""
Agent health checker for GOATGuard server.

Periodically scans all registered agents and marks those
whose last heartbeat exceeds a configurable threshold as
disconnected. This ensures the dashboard reflects the real
availability state of each endpoint.

Without this module, an agent that crashes or loses network
connectivity would remain marked as "active" indefinitely
in the database, misleading the administrator.

Runs in a background thread with a configurable check interval.
"""

import logging
import threading
import time
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class HealthChecker:
    """Monitors agent connectivity and updates status.

    Runs a background thread that periodically queries all
    registered agents. If an agent's last_heartbeat is older
    than the timeout threshold, its status is set to "inactive"
    and the associated device status is set to "disconnected".

    Args:
        repository: Database repository for querying and updating agents.
        check_interval: How often to run the check (seconds).
        timeout_seconds: How long without heartbeat before marking inactive.
    """

    def __init__(self, repository, check_interval: int = 30,
                 timeout_seconds: int = 90) -> None:
        self.repo = repository
        self.check_interval = check_interval
        self.timeout_seconds = timeout_seconds
        self._running = False
    
    def start(self) -> None:
        """Start the health checker in a background thread."""
        self._running = True
        thread = threading.Thread(target=self._check_loop, daemon=True)
        thread.start()
        logger.info(
            f"Health checker started: interval={self.check_interval}s, "
            f"timeout={self.timeout_seconds}s"
        )

    def _check_loop(self) -> None:
        """Periodically check all agents for timeout."""
        while self._running:
            try:
                self._check_agents()
            except Exception as e:
                logger.error(f"Health check error: {e}")

            time.sleep(self.check_interval)

    def _check_agents(self) -> None:
        """Query all agents and mark timed-out ones as inactive."""
        cutoff = datetime.utcnow() - timedelta(seconds=self.timeout_seconds)
        inactive_count = self.repo.mark_inactive_agents(cutoff)

        if inactive_count > 0:
            logger.warning(f"Marked {inactive_count} agents as inactive")

    def stop(self) -> None:
        """Stop the health checker."""
        self._running = False
        logger.info("Health checker stopped")
        