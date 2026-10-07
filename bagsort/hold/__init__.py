"""Forensic (legal) hold subsystem.

A hold pins a batch of committed records so that neither compaction nor any
destructive rewrite may touch them for the duration of a matter. The manifest
of exactly which journal sequences were retained is registered at place time,
sealed by a digest, stored with the journal, and only an authorised releaser
may end it, citing the basis for the release.
"""
