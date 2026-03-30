# GitHub Release Checklist

Before publishing codewash to GitHub and PyPI, ensure all items below are complete:

## ✅ Code & Testing
- [x] All 145 tests passing
- [x] Code formatted with ruff
- [x] Type checking with mypy complete
- [x] No linting errors

## ✅ Documentation
- [x] README.md with quick start, features, CLI reference
- [x] docs/patterns.md with pattern reference
- [x] CONTRIBUTING.md with development guidelines
- [x] SECURITY.md with vulnerability reporting and best practices
- [x] CHANGELOG.md with version history

## ✅ Project Configuration
- [x] pyproject.toml with complete metadata
- [x] Project URLs, keywords, classifiers
- [x] Python 3.10+ version specification
- [x] Minimal dependencies (typer, rich, pyyaml)

## ✅ GitHub Files
- [x] .gitignore for Python projects
- [x] LICENSE (MIT)
- [x] .github/workflows/tests.yml (CI/CD)
- [x] .github/ISSUE_TEMPLATE/bug_report.md
- [x] .github/ISSUE_TEMPLATE/feature_request.md
- [x] MANIFEST.in for distribution

## ✅ Developer Experience
- [x] Makefile with common tasks
- [x] Install instructions in README
- [x] Development setup guide in CONTRIBUTING.md
- [x] Example .codewash.yaml in tests/testdata

## 📋 Before Publishing to PyPI

1. **Create GitHub Repository:**
   ```bash
   git init
   git add .
   git commit -m "Initial commit: codewash v0.1.0"
   git remote add origin https://github.com/your-username/codewash.git
   git branch -M main
   git push -u origin main
   ```

2. **Update README Links:**
   - Replace `your-username` with your actual GitHub username
   - Update email in `pyproject.toml` authors section

3. **Create a Release:**
   - Go to GitHub → Releases → Create new release
   - Tag: `v0.1.0`
   - Title: `codewash v0.1.0 - Initial Release`
   - Description: Copy from CHANGELOG.md

4. **Build and Publish to PyPI:**
   ```bash
   pip install build twine
   python -m build
   python -m twine upload dist/*
   ```

   Or use the Makefile:
   ```bash
   make publish
   ```

   Requires PyPI account and ~/.pypirc credentials.

## 🚀 Post-Release

- [ ] Verify package appears on PyPI
- [ ] Test installation: `pip install codewash`
- [ ] Create GitHub Discussions or Wiki
- [ ] Add topics to GitHub repo: security, devops, anonymization, ai
- [ ] Share on relevant communities (Reddit, HN, Twitter, etc.)

## 📊 Repository Badges

Consider adding these to README:

```markdown
[![PyPI version](https://badge.fury.io/py/codewash.svg)](https://badge.fury.io/py/codewash)
[![Downloads](https://img.shields.io/pypi/dm/codewash.svg)](https://pypi.org/project/codewash/)
[![GitHub Actions](https://github.com/your-username/codewash/workflows/Tests/badge.svg)](https://github.com/your-username/codewash/actions)
```

## 🔄 Continuous Updates

- Monitor GitHub Issues for bug reports
- Track feature requests in Discussions
- Update CHANGELOG.md with each release
- Keep dependencies up to date
- Review security advisories regularly

---

**Status:** ✅ Ready for GitHub release
**Date:** 2026-03-30
**Version:** 0.1.0
