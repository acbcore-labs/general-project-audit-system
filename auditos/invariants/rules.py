"""
Business and architectural invariants for AuditOS.
Dual-correction status masking, health score calibration, and hierarchy cycle prevention.
"""
from __future__ import annotations

import sqlite3
from typing import Optional, Set


class HierarchyCycleDetector:
    """Enforces DAG integrity in system and subsystem hierarchies."""

    @staticmethod
    def validate_no_cycles(conn: sqlite3.Connection, system_id: str, proposed_parent_id: Optional[str]) -> None:
        """Walk full ancestor chain to reject both direct and transitive hierarchy cycles (RF-10)."""
        curr_anc = proposed_parent_id
        visited_anc: Set[str] = {system_id}
        while curr_anc:
            if curr_anc in visited_anc:
                raise ValueError(
                    "Hierarchy cycle detected: a system cannot be a direct or transitive parent of itself."
                )
            visited_anc.add(curr_anc)
            prow = conn.execute("SELECT parent_id FROM systems WHERE id = ?", (curr_anc,)).fetchone()
            curr_anc = prow["parent_id"] if prow else None


class StatusGovernor:
    """Enforces status dual-correction so active critical/high defects cannot be masked."""

    @staticmethod
    def compute_post_audit_system_status(
        conn: sqlite3.Connection,
        system_id: str,
        current_status: str,
        requested_status: Optional[str],
    ) -> str:
        """Prevent systems with open critical/high findings from being marked reviewed, healthy, or unreviewed (F-02, RF-01)."""
        open_crit_high = conn.execute(
            """
            SELECT COUNT(*) AS cnt FROM findings
            WHERE system_id = ?
              AND severity IN ('critical', 'high')
              AND status NOT IN ('resolved', 'wont_fix')
            """,
            (system_id,),
        ).fetchone()["cnt"]

        if open_crit_high > 0 and requested_status in (None, "reviewed", "healthy", "unreviewed"):
            return "needs_attention"
        if requested_status:
            return requested_status
        active_tasks = conn.execute(
            """
            SELECT COUNT(*) AS cnt FROM tasks
            WHERE system_id = ? AND status IN ('open', 'claimed')
            """,
            (system_id,),
        ).fetchone()["cnt"]
        if active_tasks > 0 and current_status == "in_progress":
            return "in_progress"
        return "reviewed" if current_status == "in_progress" else current_status


class HealthCalibrator:
    """Clamps asserted health scores against open finding severities."""

    @staticmethod
    def calibrate_system_health(
        conn: sqlite3.Connection,
        system_id: str,
        asserted_health: Optional[int],
    ) -> Optional[int]:
        """Calibrate and clamp health score to prevent open Critical/High findings from asserting misleadingly high scores."""
        if asserted_health is None:
            return None
        rows = conn.execute(
            """
            SELECT severity, COUNT(*) AS cnt
            FROM findings
            WHERE system_id = ? AND status NOT IN ('resolved', 'wont_fix')
            GROUP BY severity
            """,
            (system_id,),
        ).fetchall()
        sev_counts = {r["severity"]: r["cnt"] for r in rows}
        score = asserted_health
        if sev_counts.get("critical", 0) > 0:
            score = min(score, 65)
        elif sev_counts.get("high", 0) > 0:
            score = min(score, 75)
        elif sev_counts.get("medium", 0) > 0:
            score = min(score, 85)
        return score
