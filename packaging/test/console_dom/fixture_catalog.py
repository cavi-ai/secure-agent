"""Browser inputs declared independently of runner implementation."""
import payload_cases
from case_types import Fixture

def scenario_payload(scenarios, now_ms=None):
    """Named legacy probes use the same payload constructors as catalog cases."""
    names = set(scenarios)
    builders = []
    if names & {"attentionactionfocus", "attentionactionmanual"}:
        builders.append(payload_cases.attention_focus)
    if "attentionremodel" in names:
        builders.append(lambda now: payload_cases.grouped_attention(now, final="attentionfinal" in names))
    if "incidentremediation" in names:
        builders.append(payload_cases.incident_remediation)
    if "filteredscope" in names:
        builders.append(payload_cases.filtered_history)
    if "reviewresult" in names:
        builders.append(payload_cases.review_result)
    if "worktreehierarchy" in names:
        builders.append(payload_cases.worktree_reading_hierarchy)
    spec = {}
    for builder in builders:
        part = builder(spec.get("now", now_ms))
        spec["now"] = part["now"]
        spec.setdefault("patches", []).extend(part.get("patches", []))
        spec.setdefault("payloads", {}).update(part.get("payloads", {}))
    return spec

FIXTURES = {
    'dom_csp': Fixture(
        query='?cspdemo&raildemo',
        scenarios=('cspdemo', 'raildemo'),
        served=True,
    ),
    'dom_themefirst': Fixture(
        query='?themefirst',
        scenarios=('themefirst',),
        served=True,
    ),
    'dom': Fixture(
        query='',
        scenarios=(),
        served=False,
    ),
    'dom_payload': Fixture(
        query='?payloadoutcomes&tab=findings',
        scenarios=('payloadoutcomes', 'tab', 'tab=findings'),
        payload=lambda: payload_cases.payload_outcomes(),
        served=True,
    ),
    'dom_resource_results': Fixture(
        query='?resourceoutcomes&tab=resources',
        scenarios=('resourceoutcomes', 'tab', 'tab=resources'),
        payload=lambda: {'patches': [{'route': '/resources', 'path': ['interventions'], 'value': [{'id': 'fixture-partial', 'kind': 'pause', 'status': 'partial', 'verification': 'unknown', 'error': 'One captured process could not be resumed.', 'before': {'rss_bytes': 8000000000, 'cpu_percent': 140, 'host_capacity': 'constrained'}, 'after': [], 'limits': ['Pause may stop growth without freeing memory. Resume may be needed.']}, {'id': 'fixture-termination', 'kind': 'terminate', 'status': 'applied', 'verification': 'verified', 'verified_by': 'captured-family-absent', 'before': {'rss_bytes': 8000000000, 'host_capacity': 'constrained'}, 'after': [{'captured_family_present': False, 'host_capacity': 'ample', 'host_available_bytes': 12000000000}], 'limits': ['Verification covers only the captured process family. Observations do not establish causation or task completion.']}]}]},
        served=True,
    ),
    'dom_session': Fixture(
        query='?sessiondemo',
        scenarios=('sessiondemo',),
        served=False,
    ),
    'dom_guard': Fixture(
        query='?guarddemo',
        scenarios=('guarddemo',),
        served=False,
    ),
    'dom_resolve': Fixture(
        query='?resolvedemo',
        scenarios=('resolvedemo',),
        served=False,
    ),
    'dom_expect': Fixture(
        query='?expectdemo',
        scenarios=('expectdemo',),
        served=False,
    ),
    'dom_uninsp': Fixture(
        query='?uninspecteddemo',
        scenarios=('uninspecteddemo',),
        served=False,
    ),
    'dom_keepopen': Fixture(
        query='?keepopendemo',
        scenarios=('keepopendemo',),
        served=False,
    ),
    'dom_endpoint': Fixture(
        query='?endpointdemo',
        scenarios=('endpointdemo',),
        served=False,
    ),
    'dom_file': Fixture(
        query='?filedemo',
        scenarios=('filedemo',),
        served=False,
    ),
    'dom_filedeep': Fixture(
        query='#file=%2FUsers%2Fdev%2F.codex%2Fsessions%2F2026%2F09%2F23%2Frollout-2026-09-23T12-53-26-demo.jsonl',
        scenarios=(),
        served=False,
    ),
    'dom_toast': Fixture(
        query='?toastdemo',
        scenarios=('toastdemo',),
        served=False,
    ),
    'dom_notify': Fixture(
        query='?notifydemo',
        scenarios=('notifydemo',),
        served=False,
    ),
    'dom_notifyfocus': Fixture(
        query='?notifyfocusdemo',
        scenarios=('notifyfocusdemo',),
        served=False,
    ),
    'dom_allow': Fixture(
        query='?allowdemo',
        scenarios=('allowdemo',),
        served=False,
    ),
    'dom_dismiss': Fixture(
        query='?dismissdemo',
        scenarios=('dismissdemo',),
        served=False,
    ),
    'dom_retriage': Fixture(
        query='?retriagedemo',
        scenarios=('retriagedemo',),
        payload=lambda: payload_cases.retriaged_finding(),
        served=False,
    ),
    'dom_tab': Fixture(
        query='?tabdemo',
        scenarios=('tabdemo',),
        served=False,
    ),
    'dom_view': Fixture(
        query='?viewdemo',
        scenarios=('viewdemo',),
        served=False,
    ),
    'dom_advdown': Fixture(
        query='',
        scenarios=(),
        payload=lambda: payload_cases.offline_advisor(),
        served=False,
    ),
    'dom_authfail': Fixture(
        query='?authfail',
        scenarios=('authfail',),
        served=False,
    ),
    'dom_authmixed': Fixture(
        query='?authmixed',
        scenarios=('authmixed',),
        served=False,
    ),
    'dom_spendauth': Fixture(
        query='?spendauth',
        scenarios=('spendauth',),
        served=False,
    ),
    'dom_refreshrace': Fixture(
        query='?refreshrace',
        scenarios=('refreshrace',),
        served=False,
    ),
    'dom_health': Fixture(
        query='?healthdemo',
        scenarios=('healthdemo',),
        served=False,
    ),
    'dom_healthrecover': Fixture(
        query='?healthdemo&recover',
        scenarios=('healthdemo', 'recover'),
        served=False,
    ),
    'dom_slowshape': Fixture(
        query='?slowshape',
        scenarios=('slowshape',),
        served=False,
    ),
    'dom_slowshapefirst': Fixture(
        query='?slowshape&firstload',
        scenarios=('slowshape', 'firstload'),
        served=False,
    ),
    'dom_slowshaperecover': Fixture(
        query='?slowshape&recover',
        scenarios=('slowshape', 'recover'),
        served=False,
    ),
    'dom_historyflags': Fixture(
        query='?filteredscope&historyflags',
        scenarios=('filteredscope', 'historyflags'),
        payload=payload_cases.filtered_history,
        served=False,
    ),
    'dom_historyevents': Fixture(
        query='?filteredscope&historyevents',
        scenarios=('filteredscope', 'historyevents'),
        payload=payload_cases.filtered_history,
        served=False,
    ),
    'dom_historyflagschanged': Fixture(
        query='?filteredscope&historyflags&changed',
        scenarios=('filteredscope', 'historyflags', 'changed'),
        payload=payload_cases.filtered_history,
        served=False,
    ),
    'dom_historyeventschanged': Fixture(
        query='?filteredscope&historyevents&changed',
        scenarios=('filteredscope', 'historyevents', 'changed'),
        payload=payload_cases.filtered_history,
        served=False,
    ),
    'dom_historyrecover': Fixture(
        query='?filteredscope&historyflags&recover',
        scenarios=('filteredscope', 'historyflags', 'recover'),
        payload=payload_cases.filtered_history,
        served=False,
    ),
    'dom_malformed': Fixture(
        query='?malformeddemo',
        scenarios=('malformeddemo',),
        served=False,
    ),
    'dom_malformedrecover': Fixture(
        query='?malformeddemo&recover',
        scenarios=('malformeddemo', 'recover'),
        served=False,
    ),
    'dom_notoken': Fixture(
        query='?notoken',
        scenarios=('notoken',),
        served=False,
    ),
    'dom_hashagents': Fixture(
        query='#agents',
        scenarios=(),
        served=False,
    ),
    'dom_hashfindings': Fixture(
        query='#findings',
        scenarios=(),
        served=False,
    ),
    'dom_hashsessionswt': Fixture(
        query='#sessions/worktrees',
        scenarios=(),
        served=False,
    ),
    'dom_hashworktrees': Fixture(
        query='#worktrees',
        scenarios=(),
        served=False,
    ),
    'dom_trends': Fixture(
        query='?trendsprobe',
        scenarios=('trendsprobe',),
        served=False,
    ),
    'dom_hiddenrender': Fixture(
        query='?hiddenrenderprobe',
        scenarios=('hiddenrenderprobe',),
        served=False,
    ),
    'dom_policylists': Fixture(
        query='?policylists',
        scenarios=('policylists',),
        served=False,
    ),
    'dom_policyempty': Fixture(
        query='?policylists&emptypolicy',
        scenarios=('policylists', 'emptypolicy'),
        payload=lambda: {'payloads': {'/guard/rules': [], '/guard/path-allow': [], '/mute': [], '/expected': []}},
        served=False,
    ),
    'dom_forget': Fixture(
        query='?policylists&forgetexpected',
        scenarios=('policylists', 'forgetexpected'),
        served=False,
    ),
    'dom_scoped': Fixture(
        query='?scopedpermission',
        scenarios=('scopedpermission',),
        payload=lambda: payload_cases.scoped_review(),
        served=False,
    ),
    'dom_scoped_revoke': Fixture(
        query='?scopedpermission&revokescope',
        scenarios=('scopedpermission', 'revokescope'),
        payload=lambda: payload_cases.scoped_review(),
        served=False,
    ),
    'dom_netfail': Fixture(
        query='?netfail',
        scenarios=('netfail',),
        served=False,
    ),
    'dom_tokenseed': Fixture(
        query='?requiretoken&tokenseed',
        scenarios=('requiretoken', 'tokenseed'),
        served=False,
    ),
    'dom_nofleet': Fixture(
        query='?nofleetdemo',
        scenarios=('nofleetdemo',),
        payload=lambda: payload_cases.unconfigured_fleet(),
        served=False,
    ),
    'dom_noresources': Fixture(
        query='?noresourcesdemo',
        scenarios=('noresourcesdemo',),
        payload=lambda: payload_cases.postmortem_resources(),
        served=False,
    ),
    'dom_policy': Fixture(
        query='?policydemo',
        scenarios=('policydemo',),
        served=False,
    ),
    'dom_demote': Fixture(
        query='?demotedemo',
        scenarios=('demotedemo',),
        served=False,
    ),
    'dom_allowrm': Fixture(
        query='?allowlistdemo',
        scenarios=('allowlistdemo',),
        served=False,
    ),
    'dom_rail': Fixture(
        query='?raildemo',
        scenarios=('raildemo',),
        served=False,
    ),
    'dom_memory': Fixture(
        query='?raildemo&memorydemo',
        scenarios=('raildemo', 'memorydemo'),
        served=False,
    ),
    'dom_overview': Fixture(
        query='?overviewdemo',
        scenarios=('overviewdemo',),
        served=True,
    ),
    'dom_overview_stale': Fixture(
        query='?overviewdemo&overviewstale',
        scenarios=('overviewdemo', 'overviewstale'),
        served=True,
    ),
    'dom_overview_race': Fixture(
        query='?overviewdemo&overviewrace',
        scenarios=('overviewdemo', 'overviewrace'),
        served=True,
    ),
    'dom_overview_focus': Fixture(
        query='?overviewdemo&overviewfocus',
        scenarios=('overviewdemo', 'overviewfocus'),
        served=True,
    ),
    'dom_overview_decision': Fixture(
        query='?overviewdemo&overviewdecision',
        scenarios=('overviewdemo', 'overviewdecision'),
        served=True,
    ),
    'dom_overview_return': Fixture(
        query='?overviewdemo&overviewreturn',
        scenarios=('overviewdemo', 'overviewreturn'),
        served=True,
    ),
    'dom_memory_race': Fixture(
        query='?memoryrace',
        scenarios=('memoryrace',),
        served=False,
    ),
    'dom_trace_reactivation': Fixture(
        query='?tracereactivation',
        scenarios=('tracereactivation',),
        served=False,
    ),
    'dom_pill': Fixture(
        query='?pilldemo',
        scenarios=('pilldemo',),
        served=False,
    ),
    'dom_quiet': Fixture(
        query='?quietdemo',
        scenarios=('quietdemo',),
        payload=lambda: payload_cases.quiet_sessions(),
        served=False,
    ),
    'dom_nomatch': Fixture(
        query='?nomatchdemo',
        scenarios=('nomatchdemo',),
        served=False,
    ),
    'dom_coverage': Fixture(
        query='?coveragedemo',
        scenarios=('coveragedemo',),
        payload=lambda: {'patches': [{'route': '/posture', 'path': ['state'], 'value': 'attention'}, {'route': '/posture', 'path': ['needs_you'], 'value': 0}, {'route': '/posture', 'path': ['items'], 'value': []}, {'route': '/posture', 'path': ['groups'], 'value': []}, {'route': '/posture', 'path': ['summary'], 'value': 'No decisions pending. Monitoring coverage needs attention.'}]},
        served=False,
    ),
    'dom_session_coverage': Fixture(
        query='?sessionvisibility',
        scenarios=('sessionvisibility',),
        payload=lambda: payload_cases.session_coverage(),
        served=False,
    ),
    'dom_phone': Fixture(
        query='?phonedemo',
        scenarios=('phonedemo',),
        served=False,
    ),
    'dom_memory_phone': Fixture(
        query='?phonedemo&memorydemo',
        scenarios=('phonedemo', 'memorydemo'),
        served=False,
    ),
    'dom_nocosts': Fixture(
        query='?savedspendrepo',
        scenarios=('savedspendrepo',),
        payload=lambda: payload_cases.empty_spend(),
        served=False,
    ),
    'dom_memfam': Fixture(
        query='?memfamilydemo',
        scenarios=('memfamilydemo',),
        payload=lambda: payload_cases.shared_root_sessions(),
        served=False,
    ),
    'dom_memprobe': Fixture(
        query='?memprobe',
        scenarios=('memprobe',),
        served=False,
    ),
    'dom_spend': Fixture(
        query='?savedspendrepo&spenddemo',
        scenarios=('savedspendrepo', 'spenddemo'),
        served=False,
    ),
    'dom_spendrepo': Fixture(
        query='?savedspendrepo',
        scenarios=('savedspendrepo',),
        served=False,
    ),
    'dom_attentionremodel': Fixture(
        query='?attentionremodel',
        scenarios=('attentionremodel',),
        payload=payload_cases.grouped_attention,
        served=True,
    ),
    'dom_remodelusage': Fixture(
        query='?remodelusage',
        scenarios=('remodelusage',),
        served=True,
    ),
    'dom_plans': Fixture(
        query='?savedspendrepo',
        scenarios=('savedspendrepo',),
        payload=lambda: payload_cases.spend_plans(),
        served=False,
    ),
    'dom_spendday': Fixture(
        query='?spenddaydemo',
        scenarios=('spenddaydemo',),
        served=False,
    ),
    'dom_spendphone': Fixture(
        query='?phonedemo&spenddaydemo',
        scenarios=('phonedemo', 'spenddaydemo'),
        served=False,
    ),
    'dom_spendkeep': Fixture(
        query='?tab=overview&spenddaydemo&spendkeepdemo',
        scenarios=('tab', 'tab=overview', 'spenddaydemo', 'spendkeepdemo'),
        served=False,
    ),
    'dom_spendcache': Fixture(
        query='?savedspendrepo&spendcachedemo',
        scenarios=('savedspendrepo', 'spendcachedemo'),
        served=False,
    ),
    'dom_spendshape': Fixture(
        query='?savedspendrepo&spendshape',
        scenarios=('savedspendrepo', 'spendshape'),
        payload=lambda: payload_cases.delayed_spend(),
        served=False,
    ),
    'dom_spendshapefirst': Fixture(
        query='?savedspendrepo&spendshape&firstload',
        scenarios=('savedspendrepo', 'spendshape', 'firstload'),
        payload=lambda: payload_cases.delayed_spend(),
        served=False,
    ),
    'dom_spendshaperecover': Fixture(
        query='?savedspendrepo&spendshape&recover',
        scenarios=('savedspendrepo', 'spendshape', 'recover'),
        payload=lambda: payload_cases.delayed_spend(),
        served=False,
    ),
    'dom_spendslow': Fixture(
        query='?spendslowdemo',
        scenarios=('spendslowdemo',),
        served=False,
    ),
    'dom_events': Fixture(
        query='?tab=events',
        scenarios=('tab', 'tab=events'),
        served=False,
    ),
    'dom_burst': Fixture(
        query='?burstdemo',
        scenarios=('burstdemo',),
        served=False,
    ),
    'dom_railburst': Fixture(
        query='?railburst',
        scenarios=('railburst',),
        served=False,
    ),
    'dom_dup': Fixture(
        query='?dupdemo',
        scenarios=('dupdemo',),
        payload=lambda: payload_cases.grouped_sessions(),
        served=False,
    ),
    'dom_dupres': Fixture(
        query='?dupdemo&tab=resources',
        scenarios=('dupdemo', 'tab', 'tab=resources'),
        payload=lambda: payload_cases.grouped_sessions(),
        served=False,
    ),
    'dom_foldpatch': Fixture(
        query='?dupdemo&foldpatch',
        scenarios=('dupdemo', 'foldpatch'),
        payload=lambda: payload_cases.grouped_sessions(ended=True),
        served=False,
    ),
    'dom_familypatch': Fixture(
        query='?dupdemo&tab=resources&familypatch',
        scenarios=('dupdemo', 'tab', 'tab=resources', 'familypatch'),
        payload=lambda: payload_cases.grouped_sessions(sidecar=True),
        served=False,
    ),
    'dom_focus': Fixture(
        query='?focusburst',
        scenarios=('focusburst',),
        served=False,
    ),
    'dom_click': Fixture(
        query='?clickburst',
        scenarios=('clickburst',),
        served=False,
    ),
    'dom_rawmute': Fixture(
        query='?rawmute',
        scenarios=('rawmute',),
        served=False,
    ),
    'dom_act': Fixture(
        query='?actdemo',
        scenarios=('actdemo',),
        served=False,
    ),
    'dom_actfail': Fixture(
        query='?actdemo&postfail',
        scenarios=('actdemo', 'postfail'),
        served=False,
    ),
    'dom_export': Fixture(
        query='?raildemo&exportdemo',
        scenarios=('raildemo', 'exportdemo'),
        served=False,
    ),
    'dom_explain': Fixture(
        query='?explaindemo',
        scenarios=('explaindemo',),
        payload=lambda: payload_cases.explained_finding(),
        served=False,
    ),
    'dom_explainact': Fixture(
        query='?explaindemo&explainact',
        scenarios=('explaindemo', 'explainact'),
        payload=lambda: payload_cases.explained_finding(),
        served=False,
    ),
    'dom_allowpathact': Fixture(
        query='?explaindemo&allowpathact',
        scenarios=('explaindemo', 'allowpathact'),
        payload=lambda: payload_cases.explained_finding(),
        served=False,
    ),
    'dom_orgallow': Fixture(
        query='?orgallowdemo',
        scenarios=('orgallowdemo',),
        payload=lambda: payload_cases.organization_allow(),
        served=False,
    ),
    'dom_routine': Fixture(
        query='?routinedemo',
        scenarios=('routinedemo',),
        payload=lambda: payload_cases.routine_review(),
        served=False,
    ),
    'dom_explainfail': Fixture(
        query='?explaindemo&explainact&postfail',
        scenarios=('explaindemo', 'explainact', 'postfail'),
        payload=lambda: payload_cases.explained_finding(),
        served=False,
    ),
    'dom_detailsprobe': Fixture(
        query='?explaindemo&detailsprobe',
        scenarios=('explaindemo', 'detailsprobe'),
        payload=lambda: payload_cases.explained_finding(),
        served=False,
    ),
    'dom_fam': Fixture(
        query='?familiesdemo&tab=resources',
        scenarios=('familiesdemo', 'tab', 'tab=resources'),
        payload=lambda: payload_cases.resource_families(),
        served=False,
    ),
    'dom_famev': Fixture(
        query='?familiesdemo&familyevents&tab=resources',
        scenarios=('familiesdemo', 'familyevents', 'tab', 'tab=resources'),
        payload=lambda: payload_cases.resource_families(),
        served=False,
    ),
    'dom_evcap': Fixture(
        query='?tab=events',
        scenarios=('tab', 'tab=events'),
        payload=lambda: payload_cases.many_events(),
        served=False,
    ),
    'dom_evtrace': Fixture(
        query='?tab=events',
        scenarios=('tab', 'tab=events'),
        payload=lambda: payload_cases.trace_events(),
        served=False,
    ),
    'dom_duptrace': Fixture(
        query='?tab=events',
        scenarios=('tab', 'tab=events'),
        payload=lambda: payload_cases.duplicate_trace_events(),
        served=False,
    ),
    'dom_evorder': Fixture(
        query='?tab=events',
        scenarios=('tab', 'tab=events'),
        payload=lambda: payload_cases.unordered_events(),
        served=False,
    ),
    'dom_sesslink': Fixture(
        query='?sessionlinkdemo',
        scenarios=('sessionlinkdemo',),
        payload=lambda: payload_cases.session_link(),
        served=False,
    ),
    'dom_sticky': Fixture(
        query='?stickydemo',
        scenarios=('stickydemo',),
        served=False,
    ),
    'dom_drawerback': Fixture(
        query='?drawerbackdemo',
        scenarios=('drawerbackdemo',),
        served=False,
    ),
    'dom_wt': Fixture(
        query='?tab=worktrees',
        scenarios=('tab', 'tab=worktrees'),
        served=False,
    ),
    'dom_wtreview': Fixture(
        query='?tab=worktrees&reviewdemo',
        scenarios=('tab', 'tab=worktrees', 'reviewdemo'),
        served=False,
    ),
    'dom_wtreviewtrash': Fixture(
        query='?tab=worktrees&reviewdemo&reviewtrash',
        scenarios=('tab', 'tab=worktrees', 'reviewdemo', 'reviewtrash'),
        served=False,
    ),
    'dom_wtdiscuss': Fixture(
        query='?tab=worktrees&discussdemo',
        scenarios=('tab', 'tab=worktrees', 'discussdemo'),
        served=False,
    ),
    'dom_wtdockcycle': Fixture(
        query='?tab=worktrees&dockcycle',
        scenarios=('tab', 'tab=worktrees', 'dockcycle'),
        window_size=(1280, 900),
        served=False,
    ),
    'dom_wtdiscussoff': Fixture(
        query='?tab=worktrees&discussdemo&discussoff',
        scenarios=('tab', 'tab=worktrees', 'discussdemo', 'discussoff'),
        served=False,
    ),
    'dom_wtremove': Fixture(
        query='?tab=worktrees&worktreedemo',
        scenarios=('tab', 'tab=worktrees', 'worktreedemo'),
        served=False,
    ),
    'dom_wtorphan': Fixture(
        query='?tab=worktrees',
        scenarios=('tab', 'tab=worktrees'),
        payload=lambda: payload_cases.orphan_worktrees(),
        served=False,
    ),
    'dom_wtbatch': Fixture(
        query='?tab=worktrees&batchdemo',
        scenarios=('tab', 'tab=worktrees', 'batchdemo'),
        payload=lambda: payload_cases.batch_worktrees(),
        served=False,
    ),
    'dom_wtorphantrash': Fixture(
        query='?tab=worktrees&orphantrash',
        scenarios=('tab', 'tab=worktrees', 'orphantrash'),
        payload=lambda: payload_cases.orphan_worktrees(),
        served=False,
    ),
    'dom_wtremoving': Fixture(
        query='?tab=worktrees&worktreedemo&removerunning',
        scenarios=('tab', 'tab=worktrees', 'worktreedemo', 'removerunning'),
        served=False,
    ),
    'dom_wtremovefail': Fixture(
        query='?tab=worktrees&worktreedemo&removefaildemo',
        scenarios=('tab', 'tab=worktrees', 'worktreedemo', 'removefaildemo'),
        served=False,
    ),
    'dom_wtsizing': Fixture(
        query='?tab=worktrees&sizingdemo',
        scenarios=('tab', 'tab=worktrees', 'sizingdemo'),
        served=False,
    ),
    'dom_wtrefresh': Fixture(
        query='?tab=worktrees&refreshdemo',
        scenarios=('tab', 'tab=worktrees', 'refreshdemo'),
        served=False,
    ),
    'dom_clutter_view': Fixture(query='?tab=system/clutter', scenarios=('tab', 'tab=system/clutter')),
    'dom_clutter': Fixture(
        query='?tab=system/clutter&clutterdemo',
        scenarios=('tab', 'tab=system/clutter', 'clutterdemo'),
        served=False,
    ),
    'dom_wtremovable': Fixture(
        query='?tab=worktrees&removeremovabledemo',
        scenarios=('tab', 'tab=worktrees', 'removeremovabledemo'),
        payload=lambda: payload_cases.batch_worktrees(multiple_repos=True),
        served=False,
    ),
    'dom_wthistory': Fixture(
        query='?tab=worktrees&historydemo',
        scenarios=('tab', 'tab=worktrees', 'historydemo'),
        served=False,
    ),
    'dom_wtday': Fixture(
        query='?tab=worktrees&reclaimdaydemo',
        scenarios=('tab', 'tab=worktrees', 'reclaimdaydemo'),
        served=False,
    ),
    'dom_wtday_midnight': Fixture(
        query='?tab=worktrees&reclaimdaydemo&cleanupmidnight',
        scenarios=('tab', 'tab=worktrees', 'reclaimdaydemo', 'cleanupmidnight'),
        served=False,
    ),
    'dom_wtsearch': Fixture(
        query='?tab=worktrees&wtsearchdemo',
        scenarios=('tab', 'tab=worktrees', 'wtsearchdemo'),
        served=False,
    ),
    'dom_wtadopt': Fixture(
        query='?tab=worktrees',
        scenarios=('tab', 'tab=worktrees'),
        payload=lambda: payload_cases.running_worktree_removal(),
        served=False,
    ),
    'dom_wtcadence': Fixture(
        query='?tab=worktrees&removecadence',
        scenarios=('tab', 'tab=worktrees', 'removecadence'),
        served=False,
    ),
    'dom_clutteradvise': Fixture(
        query='?tab=system/clutter&clutteradvise',
        scenarios=('tab', 'tab=system/clutter', 'clutteradvise'),
        served=False,
    ),
    'dom_wtgroup': Fixture(
        query='?tab=worktrees&groupdemo',
        scenarios=('tab', 'tab=worktrees', 'groupdemo'),
        served=False,
    ),
    'dom_agent': Fixture(
        query='?tab=agent',
        scenarios=('tab', 'tab=agent'),
        served=True,
    ),
    'dom_agentworkspace': Fixture(
        query='?tab=agent&agentworkspace',
        scenarios=('tab', 'tab=agent', 'agentworkspace'),
        window_size=(1280, 900),
        payload=lambda: payload_cases.agent_queue(),
        served=True,
    ),
    'dom_agentworkspace_mobile': Fixture(
        query='?tab=agent&agentworkspace',
        scenarios=('tab', 'tab=agent', 'agentworkspace'),
        window_size=(390, 844),
        payload=lambda: payload_cases.agent_queue(),
        served=True,
    ),
    'dom_agentoff': Fixture(
        query='?tab=agent',
        scenarios=('tab', 'tab=agent'),
        payload=lambda: payload_cases.disabled_agent(),
        served=True,
    ),
    'dom_agentchat': Fixture(
        query='?tab=agent&agentchat',
        scenarios=('tab', 'tab=agent', 'agentchat'),
        served=True,
    ),
    'dom_agentlocal': Fixture(
        query='?tab=agent&agentlocal',
        scenarios=('tab', 'tab=agent', 'agentlocal'),
        served=True,
    ),
    'dom_agentlatency': Fixture(
        query='?tab=agent&agentlatency',
        scenarios=('tab', 'tab=agent', 'agentlatency'),
        served=True,
    ),
    'dom_agentthinking': Fixture(
        query='?tab=agent&agentthinking',
        scenarios=('tab', 'tab=agent', 'agentthinking'),
        served=True,
    ),
    'dom_agentreduced': Fixture(
        query='?tab=agent&agentthinking',
        scenarios=('tab', 'tab=agent', 'agentthinking'),
        reduced_motion=True,
        served=True,
    ),
    'dom_agentreject': Fixture(
        query='?tab=agent&agentreject',
        scenarios=('tab', 'tab=agent', 'agentreject'),
        served=True,
    ),
    'dom_agentdispatch': Fixture(
        query='?tab=agent&agentdispatch',
        scenarios=('tab', 'tab=agent', 'agentdispatch'),
        served=True,
    ),
    'dom_headroomwide': Fixture(
        query='?tab=sessions&headroomhint',
        scenarios=('tab', 'tab=sessions', 'headroomhint'),
        window_size=(1280, 800),
        served=True,
    ),
    'dom_headroomphone': Fixture(
        query='?phonedemo&headroomhint',
        scenarios=('phonedemo', 'headroomhint'),
        served=False,
    ),
    'dom_scope': Fixture(
        query='?scopedemo',
        scenarios=('scopedemo',),
        served=False,
    ),
    'dom_pattern': Fixture(
        query='?patterndemo',
        scenarios=('patterndemo',),
        payload=lambda: payload_cases.keychain_pattern(),
        served=False,
    ),
    'dom_gh': Fixture(
        query='?ghdemo',
        scenarios=('ghdemo',),
        payload=lambda: payload_cases.github_reader_pattern(),
        served=False,
    ),
    'dom_ghapprove': Fixture(
        query='?ghdemo&ghapprove',
        scenarios=('ghdemo', 'ghapprove'),
        payload=lambda: payload_cases.github_reader_pattern(),
        served=False,
    ),
    'dom_patternact': Fixture(
        query='?patterndemo&patternact',
        scenarios=('patterndemo', 'patternact'),
        payload=lambda: payload_cases.keychain_pattern(),
        served=False,
    ),
    'dom_patternphone': Fixture(
        query='?phonedemo&patterndemo',
        scenarios=('phonedemo', 'patterndemo'),
        payload=lambda: payload_cases.keychain_pattern(),
        served=False,
    ),
    'dom_patternstream': Fixture(
        query='?patterndemo&patternstream',
        scenarios=('patterndemo', 'patternstream'),
        payload=lambda: payload_cases.keychain_pattern(),
        served=False,
    ),
    'dom_attnkeep': Fixture(
        query='?patterndemo&attnkeep',
        scenarios=('patterndemo', 'attnkeep'),
        payload=lambda: payload_cases.keychain_pattern(),
        served=False,
    ),
    'dom_patternbig': Fixture(
        query='?patternbigdemo&logsclosed',
        scenarios=('patternbigdemo', 'logsclosed'),
        payload=lambda: payload_cases.large_keychain_pattern(),
        served=False,
    ),
    'dom_bulk': Fixture(
        query='?bulkdemo&logsclosed',
        scenarios=('bulkdemo', 'logsclosed'),
        served=False,
    ),
    'dom_empty': Fixture(
        query='?emptyposture',
        scenarios=('emptyposture',),
        payload=lambda: {'patches': [{'route': '/posture', 'path': ['state'], 'value': 'all-clear'}, {'route': '/posture', 'path': ['needs_you'], 'value': 0}, {'route': '/posture', 'path': ['coverage_count'], 'value': 0}, {'route': '/posture', 'path': ['coverage_items'], 'value': []}, {'route': '/posture', 'path': ['items'], 'value': []}, {'route': '/posture', 'path': ['groups'], 'value': []}, {'route': '/posture', 'path': ['summary'], 'value': 'Agents monitored, no action needed'}]},
        served=False,
    ),
    'dom_posturemore': Fixture(
        query='?posturemoredemo',
        scenarios=('posturemoredemo',),
        served=False,
    ),
    'dom_fold': Fixture(
        query='?folddemo',
        scenarios=('folddemo',),
        payload=lambda: payload_cases.firewall_fold(),
        served=False,
    ),
    'dom_procwidth': Fixture(
        query='?procwidthdemo',
        scenarios=('procwidthdemo',),
        window_size=(1440, 900),
        served=False,
    ),
}
