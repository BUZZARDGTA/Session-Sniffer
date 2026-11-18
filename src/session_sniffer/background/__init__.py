"""Background processing tasks and cores for player data enrichment.

Import symbols directly from their submodules (`cores`, `events`, `tasks`,
`voice_notifications`) so importing `session_sniffer.background.events` stays
dependency-light and avoids pulling heavier subsystems into leaf modules.
"""
