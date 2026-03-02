# Consumer ProGuard/R8 rules for scp-sdk-kotlin-android
# Applied automatically to downstream consumers of this library.
# Provenance: GitHub issue #144

# Keep SCP Android SDK public API
-keep class com.limn.scp.android.** { *; }
-keep class com.limn.scp.android.compose.** { *; }
-keep class com.limn.scp.android.platform.** { *; }
