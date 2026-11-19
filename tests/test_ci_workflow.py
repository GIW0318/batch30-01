import pytest

import ci_workflow as cw


def workflow(**overrides):
    data = {
        "on": {"pull_request": {}},
        "permissions": {"contents": "read"},
        "jobs": {
            "build": {
                "runs-on": "ubuntu-latest",
                "steps": [{"uses": "actions/checkout@v4"}],
            }
        },
    }
    data.update(overrides)
    return data


def test_safe_workflow_has_no_findings():
    assert cw.audit_workflow(workflow(), {"repository": {"private": False}}) == []


def test_pull_request_target_checkout_pr_head():
    wf = workflow(on={"pull_request_target": {}})
    wf["jobs"]["build"]["steps"] = [{"uses": "actions/checkout@v4", "with": {"ref": "${{ github.event.pull_request.head.sha }}"}}]
    assert cw.audit_workflow(wf, {"repository": {"private": False}}) == ["untrusted_pull_request_target_checkout"]


def test_expression_in_run():
    wf = workflow()
    wf["jobs"]["build"]["steps"] = [{"run": "echo ${{ github.event.pull_request.title }}"}]
    assert cw.audit_workflow(wf, {"repository": {"private": False}}) == ["expression_in_run"]


def test_write_all_permissions():
    assert cw.audit_workflow(workflow(permissions="write-all"), {"repository": {"private": False}}) == ["write_all_permissions"]


def test_unpinned_action():
    wf = workflow()
    wf["jobs"]["build"]["steps"] = [{"uses": "actions/checkout@main"}]
    assert cw.audit_workflow(wf, {"repository": {"private": False}}) == ["unpinned_action"]


def test_secret_on_fork_pull_request():
    wf = workflow()
    wf["jobs"]["build"]["steps"] = [{"run": "deploy", "env": {"TOKEN": "${{ secrets.DEPLOY }}"}}]
    assert cw.audit_workflow(wf, {"repository": {"private": False}, "pull_request": {"head": {"repo": {"fork": True}}}}) == ["secret_on_fork"]


def test_self_hosted_on_public_repo():
    wf = workflow()
    wf["jobs"]["build"]["runs-on"] = "self-hosted"
    assert cw.audit_workflow(wf, {"repository": {"private": False}}) == ["self_hosted_public"]


def test_id_token_without_environment():
    wf = workflow(permissions={"id-token": "write", "contents": "read"})
    assert cw.audit_workflow(wf, {"repository": {"private": False}}) == ["id_token_without_environment"]


def test_workflow_run_untrusted_artifact():
    wf = workflow(on={"workflow_run": {"workflows": ["build"]}})
    wf["jobs"]["build"]["steps"] = [{"uses": "actions/download-artifact@v4"}]
    assert cw.audit_workflow(wf, {"repository": {"private": False}}) == ["workflow_run_untrusted_artifact"]


def test_persist_credentials():
    wf = workflow()
    wf["jobs"]["build"]["steps"] = [{"uses": "actions/checkout@v4", "with": {"persist-credentials": "true"}}]
    assert cw.audit_workflow(wf, {"repository": {"private": False}}) == ["persist_credentials"]


def test_shell_eval():
    wf = workflow()
    wf["jobs"]["build"]["steps"] = [{"run": "eval \"$INPUT\""}]
    assert cw.audit_workflow(wf, {"repository": {"private": False}}) == ["shell_eval"]


def test_issue_title_in_run():
    wf = workflow()
    wf["jobs"]["build"]["steps"] = [{"run": "echo ${{ github.event.issue.title }}"}]
    assert cw.audit_workflow(wf, {"repository": {"private": False}}) == ["expression_in_run"]


def test_pull_request_target_with_secret():
    wf = workflow(on={"pull_request_target": {}})
    wf["jobs"]["build"]["steps"] = [{"run": "deploy", "env": {"TOKEN": "${{ secrets.DEPLOY }}"}}]
    assert cw.audit_workflow(wf, {"repository": {"private": False}}) == ["pull_request_target_secret"]


def test_artifact_download_without_digest_check():
    wf = workflow()
    wf["jobs"]["build"]["steps"] = [{"uses": "actions/download-artifact@v4", "with": {"name": "build"}}]
    assert cw.audit_workflow(wf, {"repository": {"private": False}}) == ["unverified_artifact"]


def test_malformed_workflow_is_rejected():
    with pytest.raises(ValueError):
        cw.audit_workflow({"on": "push"}, {"repository": {"private": False}})
