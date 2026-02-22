# Conventions

Naming, structure, and git conventions.

## File Naming

| Type | Convention | Example |
|------|------------|---------|
| Swift files | `PascalCase.swift` | `UserRepository.swift` |
| One primary type per file | File named after type | `User.swift` contains `User` |
| Views | `*View.swift` | `UserListView.swift` |
| View Models | `*ViewModel.swift` | `UserListViewModel.swift` |
| Protocols | `*Protocol.swift` or descriptive | `UserRepository.swift` (protocol) |
| Extensions | `Type+Extension.swift` | `String+Validation.swift` |
| Tests | `*Tests.swift` | `UserRepositoryTests.swift` |

## Folder Structure

- **PascalCase** for all folders: `Features/`, `Core/`, `Data/`
- Group by feature first, then by type within feature
- Shared code lives in `Core/`, `UI/`, `Data/`, `Network/`
- Feature-specific code lives in `Features/[FeatureName]/`

## Casing Rules

| Context | Style | Example |
|---------|-------|---------|
| Types (class, struct, enum, protocol) | `PascalCase` | `UserRepository` |
| Functions, methods, properties | `camelCase` | `fetchUsers()` |
| Constants | `camelCase` | `let maxRetryCount = 3` |
| Enum cases | `camelCase` | `case inProgress` |
| Static constants | `camelCase` | `static let defaultTimeout` |
| Acronyms | Lowercase in middle, uppercase at start | `urlString`, `HTTPClient` |

## Git Commits

**Format:**
```
<type>(<scope>): <subject>

[optional body]
```

**Types:**
- `feat` — New feature
- `fix` — Bug fix
- `refactor` — Code change that neither fixes nor adds
- `docs` — Documentation only
- `test` — Adding or updating tests
- `chore` — Maintenance, dependencies, config

**Scope:** Module or feature affected.

**Subject:**
- Imperative mood ("add" not "added")
- Lowercase, no period
- Under 50 characters

**Scope guidelines:**
- **Atomic commits**: Each commit is one logical concern that can be independently reverted
- Each commit should build and pass tests
- Don't mix refactoring with feature work
- When a task produces changes across multiple concerns, break them into structured commits ordered by dependency (foundations first, then layers that build on them)

## Branch Naming

```
<type>/<short-description>
```

**Examples:**
```
feat/user-profiles
fix/auth-token-crash
refactor/repository-protocols
```

## Code Organization Within Files

```swift
// MARK: - Type Declaration
struct SomeViewModel {

    // MARK: - Properties (public, then private)

    // MARK: - Initialization

    // MARK: - Public Methods

    // MARK: - Private Methods
}

// MARK: - Protocol Conformances (each in extension)
extension SomeViewModel: Identifiable { }
```

## Import Order

1. Foundation/Swift standard library
2. Apple frameworks (SwiftUI, SwiftData, etc.)
3. Third-party dependencies
4. Local modules

Separate groups with blank line:
```swift
import Foundation

import SwiftUI
import SwiftData

import SomeThirdParty

import Core
import Data
```
