# ProGuard/R8 rules for scp-sdk-kotlin-android
# Provenance: GitHub issue #144 — R8 minification breaks Robolectric Compose tests

# Keep Compose runtime classes needed by Robolectric for reflection-based
# test instrumentation. R8 strips or renames these in the release variant,
# causing RuntimeException at RoboMonitoringInstrumentation.
-keep class androidx.compose.** { *; }
-keep class androidx.activity.ComponentActivity { *; }

# Keep SCP public API classes — these are the library's surface.
-keep class com.limn.scp.android.** { *; }

# Keep kotlinx.coroutines internals used via reflection by coroutines-test
-keep class kotlinx.coroutines.** { *; }
