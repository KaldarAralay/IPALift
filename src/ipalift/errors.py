"""User-facing error types."""


class IPALiftError(Exception):
    """Base class for expected analysis failures."""


class InvalidIPAError(IPALiftError):
    """The input is not a safe, supported IPA archive."""


class MachOError(IPALiftError):
    """A Mach-O executable cannot be parsed safely."""


class ObjectiveCError(IPALiftError):
    """Objective-C metadata is malformed or unsupported."""

