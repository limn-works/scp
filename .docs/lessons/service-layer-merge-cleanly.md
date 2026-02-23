# Service Layer Changes Merge Cleanly, UI Layer Doesn't

When two branches independently add features to the same area, **service-layer** changes (protocols + implementations) tend to merge cleanly because each side adds independent methods. **UI-layer** changes conflict because both sides modify the same flow differently.

**Practical implication**: When planning parallel feature work, structure it so divergent branches add at the service layer and share a single integration point. Avoid two branches rewriting the same coordinator or controller — one will always clobber the other.
