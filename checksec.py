#!/usr/bin/env python3
import json
import sys
import asyncio
import os
from pathlib import Path
from urllib import request

# PE files
winchecksec_required_all = {
    "aslr": "Present",  # randomised virtual memory layouts
    "dynamicBase": "Present",  # enables the program to by loaded anywhere in memory (PIC)
    "gs": "Present",  # stack protection
    "nx": "Present",  # this binary can run with stack set to non executable etc. (DEP)
}
# Removed this flag since it is only valid for 64 bit binaries and it is on by default anyhow
#    "highEntropyVA": "Present",  #  high entropy virtual address support , better ASLR

winchecksec_should_all = {
    "cfg": "Present",  # binary contain map on where it is allowed to jmp/ret, CFG
    "seh": "Present",  # structured exception handlers
}

# ELF files
checksec_required_all = {
    "relro": "full",  # Relocation Read-Only, makes some binary sections read-only (like the GOT)
    "canary": "yes",  # stack protections
    "nx": "yes",  # supports non executable mem segments
}

# ELF executables
checksec_required_exe = {
    "pie": "yes"  # code can be loaded randomly in memory: openbsd.org/papers/nycbsdcon08-pie
}

# ELF files in release mode
checksec_should_release = {
    # only check if CMAKE_BUILD_TYPE=Release
    "fortify_source": "yes"  # fortify should be on but only works for release binaries
}

checksec_should_all = {
    "rpath": "no",  # rpath is dangerous but only a warning
    "runpath": "no",  # runpath is dangerous but only a warning
}

gh_token = os.getenv("GITHUB_TOKEN")
gh_comment_url = os.getenv("GITHUB_COMMENT_URL")


def post_pr_comment(msg):
    if (
        gh_token is None
        or gh_comment_url is None
        or gh_token == ""
        or gh_comment_url == ""
    ):
        print("[x] no GITHUB_TOKEN or GITHUB_COMMENT_URL env, printing to log:")
        print(msg)
        return
    req = request.Request(
        gh_comment_url, data=bytes(json.dumps({"body": msg}), encoding="utf-8")
    )
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"token {gh_token}")
    resp = request.urlopen(req)


def verify_pe(file, output, exe=True):
    o = json.loads(output)
    e = []
    w = []
    try:
        for key in winchecksec_required_all:
            if o["mitigations"][key]["presence"] != winchecksec_required_all[key]:
                e.append(
                    f":no_entry: failed {key} check ({o['mitigations'][key]['description']})"
                )
    except Exception as e:
        e.append(f"Failed checking for {key}: {str(e)}")
    try:
        for key in winchecksec_should_all:
            if o["mitigations"][key]["presence"] != winchecksec_should_all[key]:
                w.append(
                    f":warning: failed {key} check ({o['mitigations'][key]['description']})"
                )
    except Exception as e:
        w.append(f"Failed checking for {key}: {str(e)}")
    return (e, w)


def verify_elf(file, output, exe=True):
    o = list(json.loads(output).values())[0]
    e = []
    w = []
    try:
        for key in checksec_required_all:
            if o[key] != checksec_required_all[key]:
                e.append(f":no_entry: failed {key} check")
        if exe:
            for key in checksec_required_exe:
                if o[key] != checksec_required_exe[key]:
                    e.append(f":no_entry: failed {key} check")
    except Exception as e:
        e.append(f"Failed checking for {key}: {str(e)}")
    try:
        for key in checksec_should_all:
            if o[key] != checksec_should_all[key]:
                w.append(f":warning: failed {key} check")
    except Exception as e:
        w.append(f"Failed checking for {key}: {str(e)}")
    return (e, w)


async def checksec(file_tuple_tuple):
    action_home = Path(sys.argv[0]).resolve().parent
    (orig_file, file), exe = file_tuple_tuple
    if os.getenv("OS") == "Windows_NT":
        wincheckdir = action_home / "winchecksec" / "x64"
        os.chdir(wincheckdir)
        proc = await asyncio.create_subprocess_exec(
            "./winchecksec.exe",
            "-j",
            file,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        print(f"[cmd exited with {proc.returncode}]")
        if proc.returncode != 0:
            m = f"**winchecksec failed for {orig_file}** :x:\n\n{stderr.decode('utf-8')}"
            return (1, [m], [], orig_file, [])
        else:
            e, w = verify_pe(file, stdout, exe)
    else:
        proc = await asyncio.create_subprocess_exec(
            action_home / "checksec.sh/checksec",
            "--output=json",
            f"--file={file}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        print(f"[cmd exited with {proc.returncode}]")
        if proc.returncode != 0:
            m = f"**checksec.sh failed for {orig_file}** :x:\n\n{stderr.decode('utf-8')}"
            return (1, [m], [], orig_file, [])
        else:
            e, w = verify_elf(file, stdout, exe)

    msg = []
    if os.getenv("CHECKSEC_VERBOSE") == "on":
        msg = ["| Flag | Status |", "| :------------- | -----------: |"]
        if os.getenv("OS") == "Windows_NT":
            o = json.loads(stdout)["mitigations"]
            msg += [f"|{k}|{o[k]['presence']}|" for k in o]
        else:
            o = list(json.loads(stdout).values())[0]
            msg += [f"|{k}|{o[k]}|" for k in o]
        msg += ["\n"]

    return (0, e, w, orig_file, msg)


async def main():
    files = []
    paths = []
    cwd = Path(os.getcwd())
    if os.path.exists(".executables"):
        with open(".executables", "r") as r:
            paths += [(f, True) for f in r.read().splitlines()]
    if os.path.exists(".libraries"):
        with open(".libraries", "r") as r:
            paths += [(f, False) for f in r.read().splitlines()]
    print(paths)
    for (p, t) in paths:
        if p.startswith("/"):
            file = Path(p)
        else:
            file = cwd / p
        if not file.exists():
            if os.getenv("CHECKSEC_VERBOSE") == "on":
                p.replace("\\", "/")
                m = f"**There is no file called {str(p)}, ignoring it** :thinking:"
                post_pr_comment(m)
        else:
            files.append(((p, str(file)), t))
    print(f"files: {files}")

    exit_value = 0
    msg = []
    for (r, e, w, f, flag_table) in await asyncio.gather(*[checksec(x) for x in files]):
        if r != 0:
            exit_value += r
        if len(e) != 0 or len(w) != 0:
            msg += [f"**checksec issues with {f}**:"]
        if len(e):
            msg += [f"**errors:**"]
            msg += [f"{m}" for m in e]
        if len(w):
            msg += [f"**warnings:**"]
            msg += [f"{m}" for m in w]
        if len(flag_table):
            if len(e) == 0 and len(w) == 0:
                msg += [f"**checksec results for {f}** :heavy_check_mark:"]
            msg += flag_table

    if (len(msg)):
        post_pr_comment("\n".join(msg))

    return exit_value


asyncio.run(main())
