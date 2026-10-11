from enum import StrEnum


class UserRole(StrEnum):
    TRAINEE = "trainee"
    INSTRUCTOR = "instructor"
    ADMIN = "admin"


class ScenarioDifficulty(StrEnum):
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"


class ScenarioStatus(StrEnum):
    DRAFT = "draft"
    PUBLISHED = "published"
    ARCHIVED = "archived"


class ShiftStatus(StrEnum):
    ACTIVE = "active"
    PAUSED = "paused"
    SUBMITTED = "submitted"
    COMPLETED = "completed"
    ABANDONED = "abandoned"


class IncidentStatus(StrEnum):
    NEW = "new"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"


class AssignmentStatus(StrEnum):
    ASSIGNED = "assigned"
    STARTED = "started"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class ReportStatus(StrEnum):
    DRAFT = "draft"
    SUBMITTED = "submitted"
    GRADED = "graded"

