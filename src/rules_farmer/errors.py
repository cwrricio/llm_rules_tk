class RulesFarmerError(Exception):
    """Base class for structured experiment errors."""


class SIDCounterCorruptedError(RulesFarmerError):
    """Raised when the SID counter cannot be trusted at startup."""


class SSHUnreachableError(RulesFarmerError):
    """Raised when a remote entity cannot be reached over SSH."""


class IDSReloadError(RulesFarmerError):
    """Raised when the IDS container fails to reload rules."""


class AttackPlanValidationError(RulesFarmerError):
    """Raised when the attacker agent cannot produce a valid attack plan."""


class UnmappedIntentError(RulesFarmerError):
    """Raised when an intent cannot be mapped to an attack skill."""
