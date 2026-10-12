# Secure Agent

The daemon records what an agent session did on this machine and what was decided about it.

## Language

**Session evidence**:
Retained findings and outcome history for one session. Live coverage and resource controls are not session evidence.
_Avoid_: snapshot, activity report

**Finding**:
A detected condition and the evidence that supports it.
_Avoid_: flag, alert

**Outcome history**:
Retained reviews, incidents, and resource interventions for one session. It does not authorize a new action.
_Avoid_: decision log, audit
