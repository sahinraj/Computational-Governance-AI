# Repository setup

The repository is published at:

`https://github.com/sahinraj/Computational-Governance-AI`

## Local development

```bash
git clone https://github.com/sahinraj/Computational-Governance-AI.git
cd Computational-Governance-AI
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m evaluation.run_benchmark --check
python -m evaluation.failure_harness --check
```

The benchmark is runtime-agnostic. The reference adapter in `evaluation/`
exists only to demonstrate one implementation; alternative systems should
implement the adapter protocol in `governancebench.scoring`.

## GitHub Pages

The workflow in `.github/workflows/pages.yml` publishes the static site from `docs/`.

In GitHub, open **Settings → Pages** and set **Build and deployment → Source** to **GitHub Actions**. The intended site URL is:

`https://sahinraj.github.io/Computational-Governance-AI/`

## Recommended repository metadata

**Description**

A formal model, reference implementation, and runtime-agnostic benchmark for runtime governance of autonomous systems.

**Website**

`https://sahinraj.github.io/Computational-Governance-AI/`

**Topics**

- `ai-governance`
- `autonomous-agents`
- `agentic-ai`
- `policy-as-code`
- `formal-methods`
- `agent-safety`
- `multi-agent-systems`
- `benchmark`
- `python`
- `runtime-security`

## Branch and contribution policy

- `main` should remain runnable.
- Implement one numbered milestone per branch and pull request.
- Add acceptance tests before marking a milestone complete.
- Foundations v1 changes require implementation evidence, semantic ambiguity, or reviewer evidence.
- GovernanceBench must remain independent of the reference implementation.
