/**
 * The one skip rule for real-NAPI test files: a file skips only when no native
 * addon is installed.
 *
 * CRITERION: a real-NAPI guard skips its suite when, and only when,
 * `loadNativeAddon()` throws `NATIVE_ADDON_ABSENT_CODE`. Every other failure a
 * guard catches — an installed addon that fails to load, an addon missing a
 * method the suite calls, a throw in the `SCP` wrapper's constructor — fails
 * the file, because skipping on it lets `bun test` exit 0 over zero executed
 * NAPI assertions. `bindings/python/tests/conftest.py` applies the same rule to
 * the Python extension through `extension_is_absent`.
 */

import { ScpError } from "../src/errors";
import { loadNativeAddon, NATIVE_ADDON_ABSENT_CODE } from "../src/internal/native";

/**
 * Returns a skip reason when no native addon is installed, and rethrows
 * `error` otherwise.
 *
 * Call it from a guard's `catch`. The guard's own error does not decide the
 * outcome, because a guard catches whatever its setup threw — the `SCP`
 * constructor, a method call, a check on an export — and that error need not
 * come from the loader at all. This function asks the loader directly, so the
 * loader, the one component that sees whether the package resolves, decides
 * absence. When the loader itself throws
 * a code other than `NATIVE_ADDON_ABSENT_CODE`, that loader error is thrown,
 * since it names the load failure more precisely than `error` does.
 *
 * @param error - The error the guard caught.
 * @param load - The loader to ask; tests pass a stand-in, guards pass nothing.
 */
export function skipReasonIfAddonAbsent(
  error: unknown,
  load: () => unknown = loadNativeAddon,
): string {
  try {
    load();
  } catch (loadError) {
    if (loadError instanceof ScpError && loadError.code === NATIVE_ADDON_ABSENT_CODE) {
      return `native addon not installed: ${loadError.message}`;
    }
    throw loadError;
  }
  throw error;
}
