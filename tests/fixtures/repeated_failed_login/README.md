# Repeated failed-login replay scenario

Ten invented Security 4625 records, spaced ten seconds apart, share one account,
source, domain, host, and logon type. Default settings emit Medium at record 5
and escalate the same alert to High at record 10. No personal or production
security data is included; addresses use the documentation-only TEST-NET range.

Each file contains one Windows Event XML document. This is a synthetic scenario,
not evidence that real Windows monitoring works. Replay sorts by event timestamp
and anchors simulated startup to the newest valid record, so the scenario does
not expire with wall-clock time. All records use lookback ingestion.

Run: `python -m threatlens replay tests/fixtures/repeated_failed_login`
