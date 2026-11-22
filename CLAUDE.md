# MinControl — agent rules

- Spec: `docs/SPEC.md` is the source of truth. Read §2 (invariants) before touching any enforcement code.
- Workspace root is `D:\Coding_Project\MinControl\`. **Never write files outside it.**
- Each branch lives in its own subfolder of the root as a git worktree:
  `git worktree add ..\<branch> -b <branch>` from `main\`. Never switch branches inside `main\`.
- Never run enforcement (WFP filters, logoff, kill, registry policies) on the dev machine —
  only inside the Hyper-V test VM.
- Never commit secrets (Cloudflare tokens, keys, pairing codes).
- Reply/report to Minh in Vietnamese; code, comments and docs in English.
