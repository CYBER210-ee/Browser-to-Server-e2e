# Git Workflow & Rules of Engagement (ROE)

**Team:** 3 developers · **Project:** Next.js website

## Branching Model

```
main  ◄── (protected, merge every Sunday) ──  weekX-integration  ◄──  feature branches
```

| Branch                | Purpose                                                        | Who pushes here              |
| --------------------- | ------------------------------------------------------------- | ---------------------------- |
| `main`                | **Protected.** Always deployable. Updated **only** on Sundays. | Nobody directly — PR only    |
| `weekX-integration`   | Active workspace for the week (e.g. `week1-integration`).       | Via PR from feature branches |
| `<your-feature>`      | One developer's task (e.g. `dev1/login-page`).                 | You                          |

**Rules of engagement**

* `main` is a **protected branch**. No direct pushes, no force-push. All changes arrive through a PR.
* Each week we cut a fresh integration branch off `main`: `weekX-integration` (e.g. `week2-integration`).
* All three developers branch their work **off the current `weekX-integration` branch** — *not* off `main`.
* Day-to-day PRs target `weekX-integration`, reviewed by **at least one teammate**.
* **Every Sunday** we open one PR `weekX-integration → main`, review together, and merge. That's the only time `main` changes.
* Keep your feature branch small and short-lived. Pull `weekX-integration` often to avoid drift.

## Prerequisites

* Git, VS Code, and Node.js (LTS) installed
* Repo cloned locally
* `node_modules/`, `.next/`, `.env*`, `.venv/`, and dataset files listed in `.gitignore` (don't commit them!)

## 0. Sync the weekly integration branch first

At the start of each week (and before starting any new task), grab the latest integration branch:

```powershell
git fetch origin
git checkout week1-integration        # use the current week's branch name
git pull
```

> If the week's integration branch doesn't exist yet, one person creates it off `main`:
> ```powershell
> git checkout main
> git pull
> git checkout -b week1-integration
> git push -u origin week1-integration
> ```

## 1. Create your own feature branch (off `weekX-integration`)

Confirm the bottom-left of VS Code shows `week1-integration`, then branch:

```powershell
git checkout -b dev1/my-changes       # name it <you>/<task>, e.g. dev2/contact-form
```

(Your modified files come with you.)

## 2. Stage and commit your changes

```powershell
git add .
git commit -m "Describe your changes"
```

_VS Code GUI alternative:_ Source Control panel (`Ctrl+Shift+G`) → type message → click ✓ Commit.

## 3. Push your branch to GitHub

```powershell
git push -u origin dev1/my-changes
```

This uploads your branch. A PR is only possible **after** this step.

## 4. Create the Pull Request (base: `weekX-integration`)

After pushing, click the link printed in the terminal, or:

1. Go to the repo on GitHub
2. Click the yellow banner: **"Compare & pull request"**
   * Or: **Pull requests** tab → **New pull request** → base: `week1-integration` ← compare: `dev1/my-changes`
3. Add a **title** and **description** (tag a teammate with `@username` for review)
4. Click **Create pull request**

> ⚠️ Base is **`weekX-integration`**, not `main`. Only the Sunday integration PR targets `main`.

## 5. Add more changes after opening the PR

Commit and push to the **same branch** — the PR updates automatically:

```powershell
git add .
git commit -m "Address review feedback"
git push
```

## 6. Sunday merge to `main` (whole team)

Once per week, on **Sunday**, promote the week's work to the protected `main` branch:

1. Make sure all feature PRs for the week are merged into `weekX-integration`.
2. Open a PR: base `main` ← compare `week1-integration`.
3. The team reviews together; required reviews + passing checks must be green (enforced by branch protection).
4. **Merge to `main`.** Tag the release if you like (e.g. `git tag week1 && git push --tags`).
5. Cut next week's branch off the freshly-updated `main`:
   ```powershell
   git checkout main
   git pull
   git checkout -b week2-integration
   git push -u origin week2-integration
   ```

## Quick Reference (all steps)

```powershell
git fetch origin                          # 0. sync
git checkout week1-integration            #    use current week's branch
git pull
git checkout -b dev1/my-changes           # 1. branch off the integration branch
git add .                                 # 2. stage
git commit -m "My update"                 #    commit
git push -u origin dev1/my-changes        # 3. push
# 4. open PR on GitHub (base: week1-integration <- compare: dev1/my-changes)
# Sunday: open PR base: main <- compare: week1-integration, review, merge
```

## Faster: GitHub CLI (optional)

After `gh auth login`, skip the browser:

```powershell
gh pr create --base week1-integration --title "My update" --body "What I changed and why"
```

## Protecting `main` (one-time setup, repo admin)

GitHub → **Settings → Branches → Add branch protection rule**, pattern `main`:

* ✅ Require a pull request before merging — **1+ approval**
* ✅ Require status checks to pass before merging (build/lint)
* ✅ Require branches to be up to date before merging
* ✅ Do not allow bypassing the above settings
* ✅ Block force pushes / deletions

(Optional: add the same rule for `*-integration` requiring 1 review.)

## Base Website Folder Structure (Next.js — App Router)

```
my-website/
├── app/                      # App Router: routes, layouts, pages
│   ├── layout.tsx            # Root layout (html/body, shared chrome)
│   ├── page.tsx              # Home page  ("/")
│   ├── globals.css           # Global styles
│   ├── about/
│   │   └── page.tsx          # "/about"
│   └── api/
│       └── hello/route.ts    # Route handler ("/api/hello")
├── components/               # Reusable UI components
│   ├── ui/                   # Buttons, inputs, cards, etc.
│   └── Navbar.tsx
├── lib/                      # Helpers, API clients, utils
├── hooks/                    # Custom React hooks
├── public/                   # Static assets served as-is (images, favicon)
│   └── favicon.ico
├── styles/                   # Extra/module CSS (optional)
├── .env.local                # Local secrets — NEVER committed
├── .gitignore
├── next.config.js
├── package.json
├── tsconfig.json
└── README.md
```

> Using the older **Pages Router**? Swap `app/` for a `pages/` directory
> (`pages/index.tsx`, `pages/_app.tsx`, `pages/api/hello.ts`). Everything else stays the same.

## `.gitignore` (Next.js)

Drop this in the repo root (this is the official Next.js template, plus the Python lines for any dataset/notebook work):

```gitignore
# See https://help.github.com/articles/ignoring-files/ for more about ignoring files.

# dependencies
/node_modules
/.pnp
.pnp.*
.yarn/*
!.yarn/patches
!.yarn/plugins
!.yarn/releases
!.yarn/versions

# testing
/coverage

# next.js
/.next/
/out/

# production
/build

# misc
.DS_Store
*.pem

# debug
npm-debug.log*
yarn-debug.log*
yarn-error.log*
.pnpm-debug.log*

# env files (keep secrets out of git)
.env
.env*.local

# vercel
.vercel

# typescript
*.tsbuildinfo
next-env.d.ts

# --- Python (datasets / notebooks, if used) ---
.venv/
__pycache__/
*.py[cod]
.ipynb_checkpoints/
data/
*.csv
*.parquet
```

## Notes

* **Push before the PR** — there's nothing to pull-request until your branch is on GitHub.
* **Branch off `weekX-integration`, PR back into it** — only the Sunday PR touches `main`.
* On GitHub it's a **Pull Request**; "merge request" is GitLab's term for the same thing.
* Keep `node_modules/`, `.next/`, `.env*`, `.venv/` and large dataset files out of commits via `.gitignore`.
* If two devs touch the same file, the second to merge resolves conflicts — pull `weekX-integration` before pushing.
```
