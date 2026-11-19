import re


_EXPRESSION_RE = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
_SECRET_EXPRESSION_RE = re.compile(
    r"\$\{\{\s*secrets\s*(?:\.|\[)", re.IGNORECASE
)
_FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$", re.IGNORECASE)
_VERSION_REF_RE = re.compile(
    r"^v?\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.-]+)?$", re.IGNORECASE
)
_EVAL_RE = re.compile(
    r"(?m)(?:^[ \t]*|[;&|(){}]\s*|\b(?:then|do|else|if|elif|while|until)\s+)"
    r"(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*"
    r"(?:sudo\s+|command\s+|exec\s+|builtin\s+|nohup\s+)?"
    r"eval(?:\s|$)"
)
_SHELL_EVAL_RE = re.compile(
    r"\b(?:bash|sh|zsh|dash|ksh)\s+-c\s+['\"]?"
    r"(?:.*?[;&|]\s*)?eval(?:\s|['\"])",
    re.IGNORECASE,
)
_PR_HEAD_RE = re.compile(
    r"github\s*(?:\.\s*event\s*\.\s*pull_request\s*\.\s*head"
    r"|\.\s*head_ref"
    r"|\[\s*['\"]event['\"]\s*\]\s*\[\s*['\"]pull_request['\"]\s*\]"
    r"\s*\[\s*['\"]head['\"]\s*\])",
    re.IGNORECASE,
)
_PULL_REF_RE = re.compile(r"refs/pull/[^/\s]+/(?:head|merge)", re.IGNORECASE)

_FINDING_ORDER = (
    "untrusted_pull_request_target_checkout",
    "expression_in_run",
    "write_all_permissions",
    "unpinned_action",
    "secret_on_fork",
    "self_hosted_public",
    "id_token_without_environment",
    "workflow_run_untrusted_artifact",
    "persist_credentials",
    "shell_eval",
    "unverified_artifact",
    "pull_request_target_secret",
)

_DIGEST_KEYS = {
    "digest",
    "artifact-digest",
    "checksum",
    "sha256",
    "hash",
}


def audit_workflow(workflow, event):
    """Audit a GitHub Actions workflow and return security findings."""
    triggers, jobs = _validate_workflow(workflow)
    event = event if isinstance(event, dict) else {}

    findings = set()
    step_entries = [
        (job, step)
        for job in jobs.values()
        for step in job.get("steps", [])
    ]
    steps = [step for _, step in step_entries]

    for job in jobs.values():
        if _is_self_hosted(job.get("runs-on")) and _is_public_repository(event):
            findings.add("self_hosted_public")

        if _is_unpinned_action(job.get("uses")):
            findings.add("unpinned_action")

        job_permissions = (
            job["permissions"] if "permissions" in job else workflow.get("permissions")
        )
        if _is_write_all(job_permissions):
            findings.add("write_all_permissions")

        if _grants_id_token_write(job_permissions) and not job.get("environment"):
            findings.add("id_token_without_environment")

    if _is_write_all(workflow.get("permissions")):
        findings.add("write_all_permissions")

    if "pull_request_target" in triggers:
        if any(_checks_out_pull_request_head(step) for step in steps):
            findings.add("untrusted_pull_request_target_checkout")

        if _jobs_expose_secrets(jobs):
            findings.add("pull_request_target_secret")

    if "pull_request" in triggers and _is_fork_pull_request(event):
        if _jobs_expose_secrets(jobs):
            findings.add("secret_on_fork")

    for job, step in step_entries:
        run = step.get("run")
        if isinstance(run, str):
            if any(
                _is_event_expression(match.group(1))
                for match in _EXPRESSION_RE.finditer(run)
            ):
                findings.add("expression_in_run")
            if _contains_eval(run):
                findings.add("shell_eval")

        if _is_unpinned_action(step.get("uses")):
            findings.add("unpinned_action")

        if _is_checkout_action(step.get("uses")):
            checkout_with = step.get("with") or {}
            if _is_truthy(checkout_with.get("persist-credentials")):
                findings.add("persist_credentials")

        if _is_artifact_download(step.get("uses")):
            if "workflow_run" in triggers and not _has_trusted_workflow_run_source(
                step, job
            ):
                findings.add("workflow_run_untrusted_artifact")
            elif not _has_artifact_digest(step):
                findings.add("unverified_artifact")

    return [finding for finding in _FINDING_ORDER if finding in findings]


def _validate_workflow(workflow):
    if not isinstance(workflow, dict):
        raise ValueError("workflow must be a mapping")

    raw_triggers = workflow.get("on", workflow.get(True))
    if isinstance(raw_triggers, dict):
        triggers = {str(name).lower() for name in raw_triggers}
    elif isinstance(raw_triggers, list) and all(
        isinstance(name, str) for name in raw_triggers
    ):
        triggers = {name.lower() for name in raw_triggers}
    else:
        raise ValueError("workflow 'on' must be a mapping or list of trigger names")

    if not triggers:
        raise ValueError("workflow must declare at least one trigger")

    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        raise ValueError("workflow 'jobs' must be a non-empty mapping")

    for job in jobs.values():
        if not isinstance(job, dict):
            raise ValueError("each job must be a mapping")

        if "uses" in job and not isinstance(job["uses"], str):
            raise ValueError("job 'uses' must be a string")

        steps = job.get("steps", [])
        if not isinstance(steps, list):
            raise ValueError("job 'steps' must be a list")

        for step in steps:
            if not isinstance(step, dict):
                raise ValueError("each step must be a mapping")
            for key in ("run", "uses"):
                if key in step and not isinstance(step[key], str):
                    raise ValueError("step '%s' must be a string" % key)
            for key in ("env", "with"):
                if key in step and not isinstance(step[key], dict):
                    raise ValueError("step '%s' must be a mapping" % key)
    return triggers, jobs


def _is_public_repository(event):
    repository = event.get("repository")
    if not isinstance(repository, dict):
        return True
    private = repository.get("private")
    return not (private is True or str(private).lower() == "true")


def _is_fork_pull_request(event):
    pull_request = event.get("pull_request")
    if not isinstance(pull_request, dict):
        return False

    head = pull_request.get("head")
    if not isinstance(head, dict):
        return False

    head_repo = head.get("repo")
    if isinstance(head_repo, dict):
        if head_repo.get("fork") is True:
            return True
        head_name = head_repo.get("full_name")
        base_name = (event.get("repository") or {}).get("full_name")
        if head_name and base_name and str(head_name).lower() != str(base_name).lower():
            return True

    return False


def _is_write_all(permissions):
    return isinstance(permissions, str) and permissions.strip().lower() == "write-all"


def _grants_id_token_write(permissions):
    return (
        isinstance(permissions, dict)
        and str(permissions.get("id-token", "")).lower() == "write"
    )


def _is_self_hosted(runs_on):
    if isinstance(runs_on, str):
        return "self-hosted" in runs_on.lower()
    if isinstance(runs_on, list):
        return any(_is_self_hosted(value) for value in runs_on)
    if isinstance(runs_on, dict):
        return any(_is_self_hosted(value) for value in runs_on.values())
    return False


def _is_checkout_action(uses):
    if not isinstance(uses, str):
        return False
    name = uses.split("@", 1)[0].strip().lower()
    return name == "actions/checkout" or name.startswith("actions/checkout/")


def _is_unpinned_action(uses):
    if not isinstance(uses, str) or not uses.strip():
        return False

    uses = uses.strip()
    if uses.startswith("./") or uses.startswith("docker://"):
        return False

    if "@" not in uses:
        return True

    reference = uses.rsplit("@", 1)[1].strip()
    if not reference:
        return True
    if _FULL_SHA_RE.fullmatch(reference):
        return False
    if _VERSION_REF_RE.fullmatch(reference):
        return False
    return True


def _contains_secret_expression(value):
    if isinstance(value, str):
        return bool(_SECRET_EXPRESSION_RE.search(value))
    if isinstance(value, dict):
        return any(_contains_secret_expression(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_secret_expression(item) for item in value)
    return False


def _jobs_expose_secrets(jobs):
    for job in jobs.values():
        if str(job.get("secrets", "")).lower() == "inherit":
            return True
        for key in ("env", "with", "container", "services", "secrets"):
            if _contains_secret_expression(job.get(key)):
                return True
        for step in job.get("steps", []):
            for key in ("run", "env", "with", "shell", "working-directory"):
                if _contains_secret_expression(step.get(key)):
                    return True
    return False


def _is_event_expression(expression):
    normalized = re.sub(r"\s+", "", expression).lower()
    return (
        "github.event" in normalized
        or "github['event']" in normalized
        or 'github["event"]' in normalized
        or "github.head_ref" in normalized
        or "github.ref_name" in normalized
    )


def _contains_eval(run):
    return bool(_EVAL_RE.search(run) or _SHELL_EVAL_RE.search(run))


def _checks_out_pull_request_head(step):
    if not _is_checkout_action(step.get("uses")):
        return False

    checkout_with = step.get("with")
    if not isinstance(checkout_with, dict):
        return False

    for key in ("ref", "repository"):
        value = checkout_with.get(key)
        if isinstance(value, str) and (
            _PR_HEAD_RE.search(value) or _PULL_REF_RE.search(value)
        ):
            return True
    return False


def _is_artifact_download(uses):
    if not isinstance(uses, str):
        return False
    name = uses.split("@", 1)[0].strip().lower()
    return name.endswith("/download-artifact") or name in {
        "actions/download-artifact",
        "dawidd6/action-download-artifact",
    }


def _has_artifact_digest(step):
    step_with = step.get("with")
    if not isinstance(step_with, dict):
        return False

    for key, value in step_with.items():
        normalized = str(key).lower()
        if normalized in _DIGEST_KEYS or "digest" in normalized:
            if value is not None and str(value).strip():
                return True
    return False


def _has_trusted_workflow_run_source(step, job):
    for condition in (step.get("if"), job.get("if")):
        if not isinstance(condition, str):
            continue
        normalized = re.sub(r"\s+", "", condition).lower()
        checks_head_repository = "workflow_run.head_repository" in normalized
        checks_current_repository = (
            "github.repository" in normalized
            or "workflow_run.repository" in normalized
        )
        if checks_head_repository and checks_current_repository:
            return True
    return False


def _is_truthy(value):
    if value is True:
        return True
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes", "on"}
    if isinstance(value, (int, float)):
        return value == 1
    return False
