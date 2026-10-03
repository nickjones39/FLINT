"""Exceptions raised by FLINT."""
from __future__ import annotations


class ProvFormatError(ValueError):
    """A PROV-JSON document FLINT cannot load.

    Raised for structural problems in any mode (a relation missing a required
    field, a section that is not an object) and, under ``strict=True``, for
    anything that would otherwise let a flow go unseen: a relation naming an
    undeclared node or a node of the wrong PROV type, an identifier declared
    twice, an activity without a valid role, or a conflicting ``adprov`` prefix.
    """
