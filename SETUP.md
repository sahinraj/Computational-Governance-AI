# Publishing this repo

## 1. Create the repo and push

```bash
cd computational-governance      # this folder
git init
git add .
git commit -m "Initial commit: Foundations v1, reference impl M1-M3, GovernanceBench schema"
git branch -M main
git remote add origin https://github.com/<you>/computational-governance.git
git push -u origin main
```

## 2. Turn on GitHub Pages

Repo Settings → Pages → Build and deployment → Source: **GitHub Actions**.
The included `.github/workflows/pages.yml` deploys `docs/` on every push to main.
Your site will be at `https://<you>.github.io/computational-governance/`.

## 3. Fix the placeholder links

In `docs/index.html`, replace every `OWNER/REPO` with your `<you>/computational-governance`.

## 4. (Optional) suggested repo metadata

- Description: "A formal model, reference implementation, and runtime-agnostic benchmark for runtime governance of autonomous systems."
- Topics: `ai-governance`, `autonomous-agents`, `policy-as-code`, `formal-methods`, `agent-safety`, `benchmark`
