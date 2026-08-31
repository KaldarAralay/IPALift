# Security and lawful use

## Supported versions

Security fixes are applied to the current `0.1.x` release line. Older snapshots
and locally modified builds are not supported.

## Reporting a vulnerability

Use the repository's **Security** tab to open a private GitHub Security
Advisory. Do not open a public issue for a suspected vulnerability. Include a
minimal synthetic reproducer, affected version, platform, and impact when
possible. Never attach an IPA, extracted application data, signing material,
credentials, or proprietary decompiler output.

If private security reporting is not enabled, ask the repository owner to
enable it without disclosing technical details publicly.

## Security boundaries

- Treat every IPA as untrusted input. Run IPALift as an unprivileged user and
  write results to a dedicated directory.
- IPALift bounds archive extraction and rejects traversal and unsafe link
  targets, but its output contains data copied or derived from the analyzed
  application. Protect the entire workspace as you would protect the IPA.
- Ghidra and Java are external tools. Obtain them from their official sources,
  verify the publisher's release material, and keep them patched. IPALift does
  not download or sandbox them.
- Do not publish analysis workspaces, reconstruction packets, pseudocode, or
  extracted assets unless you have confirmed that you may distribute them.
- GitHub Actions use read-only repository permissions and no project secrets.

## Lawful-use policy

Use IPALift only with software you own or are authorized to inspect, and comply
with applicable law, contracts, licenses, and platform rules. IPALift does not
decrypt protected executables, bypass access controls, or provide DRM-removal
instructions. Static-analysis output is not original source code and may be
incomplete or incorrect. This policy is operational guidance, not legal advice.
