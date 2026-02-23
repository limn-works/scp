# Cross-Branch Parameter Naming

**Problem**: When working with multiple worktree branches based on `main`, later branches may have outdated API signatures if earlier branches change them. Merging both branches causes conflicts.

**Solution**: When refactoring APIs across branches:
1. Note which branches depend on the changed API
2. After merging the API-changing branch, rebase dependent branches
3. Or keep branches in sync by using the same parameter names until merged

For parallel work: prefer additive changes (new methods) over breaking changes (renamed parameters).
