# PyPI Release Guide

## Prerequisites

Before publishing to PyPI, ensure you have:

1. **PyPI Account**
   - Create account at https://pypi.org/account/register/
   - Configure 2FA if required

2. **TestPyPI Account** (optional but recommended)
   - Create account at https://test.pypi.org/account/register/
   - Use for testing before production release

3. **API Token**
   - Generate token at https://pypi.org/manage/account/tokens/
   - Keep it secure (do not commit to repository)

## GitHub Secrets Setup

Add the following secrets to your GitHub repository:

1. **For PyPI (Production)**
   - Go to: Settings → Secrets and variables → Actions
   - Add secret: `PYPI_API_TOKEN` with your PyPI token

2. **For TestPyPI (Testing)**
   - Go to: Settings → Secrets and variables → Actions
   - Add secret: `TESTPYPI_API_TOKEN` with your TestPyPI token

3. **Environment Configuration**
   - Create environment at: Settings → Environments
   - Name: `pypi`
   - Add deployment branch rules (e.g., `main`, `v*`)
   - Set required reviewers if desired

## Building Locally

### Install Build Tools

```bash
pip install build twine
```

### Build Distribution

```bash
python -m build
```

This creates:
- `dist/proof-of-work-1.0.0.tar.gz` (source distribution)
- `dist/proof-of-work-1.0.0-py3-none-any.whl` (wheel)

### Validate Distribution

```bash
twine check dist/*
```

### Test Upload to TestPyPI

```bash
twine upload --repository testpypi dist/* --verbose
```

Then verify at: https://test.pypi.org/project/proof-of-work/

### Install from TestPyPI

```bash
pip install --index-url https://test.pypi.org/simple/ proof-of-work
```

## Production Release

### Option 1: GitHub Actions (Automated)

1. **Create Release Tag**
   ```bash
   git tag -a v1.0.0 -m "Release version 1.0.0"
   git push origin v1.0.0
   ```

2. **Create GitHub Release**
   - Go to: Releases → Draft new release
   - Tag: `v1.0.0`
   - Title: `Version 1.0.0`
   - Description: Add changelog and features
   - Click: "Publish release"

   This automatically triggers the `publish-pypi.yml` workflow which:
   - Builds the distribution
   - Publishes to PyPI
   - Creates automatic release notes

### Option 2: Manual Upload

```bash
twine upload dist/* --verbose
```

Then verify at: https://pypi.org/project/proof-of-work/

## Verification

After upload, verify the package:

```bash
# Install from PyPI
pip install proof-of-work

# Test import
python -c "from python.utils_client import PoWClient; print('Success!')"

# Check version
pip show proof-of-work
```

## Release Checklist

- [ ] Update version in `setup.py`
- [ ] Update version in `pyproject.toml`
- [ ] Update `CHANGELOG.md`
- [ ] Update `README.md` if needed
- [ ] Run tests locally: `python python/main.py win 64`
- [ ] Build locally: `python -m build`
- [ ] Validate: `twine check dist/*`
- [ ] Test on TestPyPI: `twine upload --repository testpypi dist/*`
- [ ] Tag release: `git tag -a vX.Y.Z -m "Release version X.Y.Z"`
- [ ] Push tag: `git push origin vX.Y.Z`
- [ ] Create GitHub Release
- [ ] Verify on PyPI: https://pypi.org/project/proof-of-work/

## Troubleshooting

### "Filename already exists"
- The version already exists on PyPI
- Increment version number and retry

### "Invalid distribution"
- Run `twine check dist/*` to see specific errors
- Fix issues in `setup.py` or `pyproject.toml`

### "Unauthorized"
- Verify API token is correct
- Check token hasn't expired
- Verify PyPI secret is set in GitHub

### Build Failures
- Ensure all Python files are in `python/` directory
- Verify `MANIFEST.in` includes all necessary files
- Check `pyproject.toml` for correct package paths

## Version Numbering

Follow [Semantic Versioning](https://semver.org/):

- **MAJOR.MINOR.PATCH** (e.g., 1.0.0)
- MAJOR: Breaking changes
- MINOR: New features (backward compatible)
- PATCH: Bug fixes

## Resources

- [PyPI Help](https://pypi.org/help/)
- [Packaging Guide](https://packaging.python.org/)
- [Setuptools Docs](https://setuptools.pypa.io/)
- [Twine Documentation](https://twine.readthedocs.io/)
