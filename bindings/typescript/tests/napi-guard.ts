/**
 * The one skip rule for real-NAPI test files: a file skips only when no native
 * addon is installed.
 *
 * CRITERION: a real-NAPI guard skips its suite when, and only when,
 * `loadNativeAddon()` throws `NATIVE_ADDON_ABSENT_CODE`. Every other failure a
 * guard catches — an installed addon that fails to load, an addon missing a
 * method the suite calls, a throw in the `SCP` wrapper's constructor — fails
 * the file, because skipping on it lets `bun test` exit 0 over zero executed
 * NAPI assertions.
 *
 * {@link napiSuite} is the one place a test file may skip: every real-NAPI
 * file builds its suite through it, and `dispatcher-invariant.test.ts` fails
 * on any other skip construct under `tests/`.
 */

import { describe, test } from "bun:test";
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

/**
 * Throws when the environment variable `variable` is `"1"` and `suite` skips,
 * so a CI run that sets the variable fails the file instead of passing over a
 * skipped suite. `bun test` exits 0 when every suite skips.
 *
 * @param suite - The suite {@link napiSuite} returned.
 * @param variable - The variable that demands the suite run.
 * @param env - The environment to read; tests pass a stand-in.
 */
export function requireSuiteRuns(
  suite: NapiSuite<unknown>,
  variable: string,
  env: Record<string, string | undefined> = process.env,
): void {
  if (env[variable] === "1" && suite.skipReason !== "") {
    throw new Error(`${variable}=1, but the suite skips: ${suite.skipReason}`);
  }
}

/** A real-NAPI suite: the value its probe built, or why it skips. */
export interface NapiSuite<T> {
  /** The probe's value, or `undefined` when no native addon is installed. */
  readonly addon: T | undefined;
  /** Why the suite skips; empty when the probe succeeded. */
  readonly skipReason: string;
  /**
   * Registers `body` under `name` and passes it the probe's value. When no
   * native addon is installed it registers `name` as a skipped suite holding
   * one test that states the reason, and never calls `body`.
   */
  describe(name: string, body: (addon: T) => void): void;
}

/**
 * Runs `probe`, which loads the addon and checks every export the file needs,
 * and returns the suite to register the file's real-NAPI tests under.
 *
 * When `probe` throws or rejects, the {@link skipReasonIfAddonAbsent} rule
 * decides: the suite skips only when the loader reports the addon absent, and
 * any other failure (an addon that fails to load, a missing export, a throw in
 * the `SCP` constructor) is rethrown and fails the file.
 *
 * @param probe - Builds what the file's tests use; throws on any failure.
 * @param load - The loader to ask; tests pass a stand-in, files pass nothing.
 */
export async function napiSuite<T>(
  probe: () => T | Promise<T>,
  load: () => unknown = loadNativeAddon,
): Promise<NapiSuite<T>> {
  let addon: T;
  try {
    addon = await probe();
  } catch (error) {
    const skipReason = skipReasonIfAddonAbsent(error, load);
    return {
      addon: undefined,
      skipReason,
      describe: (name) =>
        describe.skip(name, () => {
          test(`skipped: ${skipReason}`, () => {});
        }),
    };
  }
  return {
    addon,
    skipReason: "",
    describe: (name, body) => describe(name, () => body(addon)),
  };
}
