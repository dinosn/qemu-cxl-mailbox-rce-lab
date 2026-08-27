# Security and disclosure policy

This repository contains a working vulnerability reproduction and must remain
**Private**. Access is limited to authorized researchers, application owners,
and remediation engineers with a need to know.

## Authorized use only

Run the lab only on infrastructure you own or are explicitly authorized to
test. The supported workflow is the provided disposable Docker environment.
Do not adapt the proof to production targets, add caller-selected commands, or
attach privileged host resources to the container.

The lab proves execution in the QEMU process context. It does not prove delivery
from a booted KVM guest or escape from Docker to the outer host. Report those as
separate claims unless and until independently validated.

## Reporting a problem

Do not open a public issue, public pull request, discussion, gist, or paste
containing this material. Report suspected repository exposure, leaked
artifacts, a lab safety problem, or a newly validated impact through the
private channel supplied by the repository owner.

For an upstream disclosure, verify and follow the QEMU project's current
official security process. Coordinate timing and content with the authorized
application owner before publishing any technical detail.

## Repository hygiene

Before every push:

1. Run `./lab verify`.
2. Review `git status --short` and `git diff --cached`.
3. Confirm no generated `artifacts/`, binaries, archives, images, sockets,
   tokens, credentials, private target identifiers, workstation paths, or raw
   receipts are staged.
4. Confirm the GitHub repository visibility is still Private.

If the repository or an evidence artifact is accidentally exposed, stop
sharing it, restrict access, notify the repository owner immediately, and
rotate any credential that may have been present. Git history must be treated
as exposed even after a normal file deletion.
