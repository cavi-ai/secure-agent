"""All named browser cases and their fixture catalog."""
from fixture_catalog import FIXTURES
from cases_reports import CASES as reports
from cases_sessions import CASES as sessions
from cases_spend import CASES as spend
from cases_agent import CASES as agent
from cases_policy import CASES as policy
from cases_worktrees import CASES as worktrees
from cases_review_results import CASES as review_results
from cases_expected_removal import CASES as expected_removal
from cases_policy_health import CASES as policy_health
from cases_protection_context import CASES as protection_context
from cases_worktree_selection import CASES as worktree_selection
from cases_monitoring import CASES as monitoring

CASES = (*reports, *sessions, *spend, *agent, *policy, *worktrees, *review_results, *expected_removal, *policy_health,
         *protection_context, *worktree_selection, *monitoring)
