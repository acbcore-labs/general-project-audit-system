"""
Core AuditDB orchestration engine assembling all repository, coordination, and reporting mixins.
"""
from __future__ import annotations

from typing import Optional

from auditos.core.database import DatabaseEngine
from auditos.repositories.project_repo import ProjectRepositoryMixin
from auditos.repositories.agent_repo import AgentRepositoryMixin
from auditos.repositories.system_repo import SystemRepositoryMixin
from auditos.repositories.task_repo import TaskRepositoryMixin
from auditos.repositories.finding_repo import FindingRepositoryMixin
from auditos.repositories.checkpoint_repo import CheckpointRepositoryMixin
from auditos.repositories.log_repo import LogRepositoryMixin
from auditos.coordination.lease_manager import LeaseCoordinatorMixin
from auditos.coordination.blackboard import BlackboardCoordinatorMixin
from auditos.coordination.sweep_engine import SweepOrchestratorMixin
from auditos.reporting.export import MarkdownReportMixin
from auditos.reporting.snapshot import SnapshotMixin


class AuditDB(
    DatabaseEngine,
    ProjectRepositoryMixin,
    AgentRepositoryMixin,
    SystemRepositoryMixin,
    TaskRepositoryMixin,
    FindingRepositoryMixin,
    CheckpointRepositoryMixin,
    LogRepositoryMixin,
    LeaseCoordinatorMixin,
    BlackboardCoordinatorMixin,
    SweepOrchestratorMixin,
    MarkdownReportMixin,
    SnapshotMixin,
):
    """
    Unified AuditDB kernel providing:
    - ACID transactions over SQLite WAL mode
    - Repository layer (projects, systems, agents, tasks, findings, checkpoints, logs)
    - Concurrency coordination (leases, atomic task claiming, auto-recovery, checkpoints)
    - Mission blackboard & scrum-master sweep engine
    - Invariant enforcement (hierarchy acyclicity, status governor, health calibration)
    - Snapshot & Markdown reporting
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
        auto_sync_snapshot: bool = False,
        ui_dir: Optional[str] = None,
    ) -> None:
        super().__init__(
            db_path=db_path,
            auto_sync_snapshot=auto_sync_snapshot,
            ui_dir=ui_dir,
        )
