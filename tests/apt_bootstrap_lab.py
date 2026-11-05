#!/usr/bin/env python3
"""Exercise actual APT bootstrap tasks with synthetic acquisition and real dpkg comparison.

This networkless contract lab is not an Ubuntu VM/package-upgrade test. It never
invokes host apt-get; wrappers reject acquisition without the required mitigation.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import yaml

FIXED = "2.8.4ubuntu0.1"
PACKAGES = ("apt", "libapt-pkg6.0t64")

WRAPPER = r'''
import json,os,pathlib,subprocess,sys
root=pathlib.Path(os.environ['VPN_APT_LAB_ROOT'])
state=json.loads((root/'state.json').read_text())
program=pathlib.Path(sys.argv[0]).name
args=sys.argv[1:]
with (root/'commands.jsonl').open('a') as log:
    log.write(json.dumps({'program':program,'args':args})+'\n')
if program=='dpkg-query':
    assert args[:2]==['-W','-f=${db:Status-Status} ${Version}'],args
    package=state['packages'][args[2]]
    print(package['status']+' '+package['version'])
elif program=='dpkg':
    assert args[0]=='--compare-versions',args
    raise SystemExit(subprocess.run(['/usr/bin/dpkg',*args]).returncode)
elif program=='apt-get':
    assert [a for a in args if a.startswith('Acquire::Retries=')]==['Acquire::Retries=0'],args
    assert not any('unauthenticated' in a or 'AllowInsecure' in a or 'AllowWeak' in a for a in args),args
    if 'update' in args:
        assert 'APT::Update::Error-Mode=any' in args,args
        if state['scenario']=='repo_failure': raise SystemExit(100)
    else:
        assert 'install' in args and '--only-upgrade' in args and '--yes' in args,args
        assert args[-2:]==['apt','libapt-pkg6.0t64'],args
        if state['scenario']!='no_fix':
            for package in state['packages'].values(): package.update(status='installed',version='2.8.4ubuntu0.1')
            (root/'state.json').write_text(json.dumps(state))
else:
    raise AssertionError('Unexpected executable')
'''


def run_case(root, scenario, versions, *, installed=True, release="24.04", expected_success=True, repeat=False):
    directory = root / scenario; directory.mkdir()
    binaries = directory / "bin"; binaries.mkdir()
    state = {"scenario": scenario, "packages": {package: {"status": "installed" if installed else "config-files", "version": version}
                                                for package, version in zip(PACKAGES, versions)}}
    (directory / "state.json").write_text(json.dumps(state))
    for command in ("dpkg-query", "dpkg", "apt-get"):
        path = binaries / command
        path.write_text("#!" + sys.executable + "\n" + WRAPPER)
        path.chmod(0o755)
    sentinel = directory / "package-module-reached"
    tasks = Path("infra/roles/node/tasks/apt-security.yml").resolve()
    play = [{"name": "Synthetic acquisition contract only", "hosts": "localhost", "gather_facts": False,
             "vars": {"ansible_python_interpreter": sys.executable,
                      "ansible_facts": {"distribution": "Ubuntu", "distribution_version": release}},
             "environment": {"PATH": str(binaries) + os.pathsep + os.environ["PATH"], "VPN_APT_LAB_ROOT": str(directory)},
             "tasks": [{"ansible.builtin.include_tasks": str(tasks)},
                       {"name": "Reached following package operation only after the security gate",
                        "ansible.builtin.command": {"argv": [sys.executable, "-c",
                            "from pathlib import Path; Path(" + repr(str(sentinel)) + ").write_text('gate passed')"]},
                        "changed_when": False}]}]
    playbook = directory / "playbook.yml"; playbook.write_text(yaml.safe_dump(play))
    command = ["ansible-playbook", "-i", "localhost,", "-c", "local", str(playbook)]
    result = subprocess.run(command, text=True, capture_output=True)
    assert (result.returncode == 0) == expected_success, scenario + "\n" + result.stdout[-5000:] + result.stderr[-1000:]
    assert sentinel.exists() == expected_success, scenario
    events = [json.loads(line) for line in (directory / "commands.jsonl").read_text().splitlines()] if (directory / "commands.jsonl").exists() else []
    acquisition = [event for event in events if event["program"] == "apt-get"]
    if scenario in ("vulnerable", "mixed", "no_fix"):
        assert len(acquisition) == 2, events
        assert "update" in acquisition[0]["args"] and "install" in acquisition[1]["args"], acquisition
    elif scenario == "repo_failure":
        assert len(acquisition) == 1 and "update" in acquisition[0]["args"], acquisition
    else:
        assert not acquisition, acquisition
    if repeat:
        assert expected_success
        result = subprocess.run(command, text=True, capture_output=True)
        assert result.returncode == 0, result.stdout[-3000:] + result.stderr[-1000:]
        repeated = [json.loads(line) for line in (directory / "commands.jsonl").read_text().splitlines()]
        assert [event for event in repeated if event["program"] == "apt-get"] == acquisition, repeated
        assert "changed=0" in result.stdout, result.stdout[-1000:]
    print("PASS: " + scenario, flush=True)


def run():
    if os.name != "posix" or not Path("/usr/bin/dpkg").is_file():
        raise SystemExit("Run this contract lab in the Linux tooling container with native dpkg")
    role = yaml.safe_load(Path("infra/roles/node/tasks/main.yml").read_text())
    assert role[0].get("ansible.builtin.include_tasks") == "apt-security.yml", "APT gate must run before package modules"
    with tempfile.TemporaryDirectory(prefix="vpn-apt-contract-") as temporary:
        root = Path(temporary)
        run_case(root, "vulnerable", ("2.8.3", "2.8.3"), repeat=True)
        run_case(root, "mixed", (FIXED, "2.8.3"))
        run_case(root, "already_fixed", (FIXED, "2.8.4ubuntu0.2"), repeat=True)
        run_case(root, "repo_failure", ("2.8.3", "2.8.3"), expected_success=False)
        run_case(root, "no_fix", ("2.8.3", "2.8.3"), expected_success=False)
        run_case(root, "unconfigured", (FIXED, FIXED), installed=False, expected_success=False)
        run_case(root, "unsupported_release", (FIXED, FIXED), release="22.04", expected_success=False)
    print("PASS: actual Ansible gate with synthetic package backend rejects unsafe acquisition and unavailable fixes; native dpkg version checks and repeat idempotency verified. No host APT or network used.")


if __name__ == "__main__": run()
