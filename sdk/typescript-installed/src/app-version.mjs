import { createRequire } from "node:module";
import { fail, ErrorKind } from "./errors.mjs";

const NUMBER = "(?:0|[1-9][0-9]*)";
const PRE_PART = `(?:${NUMBER}|[0-9]*[A-Za-z-][0-9A-Za-z-]*)`;
const IDENTIFIER = "[0-9A-Za-z-]+";
const VERSION_PATTERN = new RegExp(
  `^${NUMBER}(?:\\.${NUMBER}){0,3}(?:-${PRE_PART}(?:\\.${PRE_PART})*)?(?:\\+${IDENTIFIER}(?:\\.${IDENTIFIER})*)?$`,
);
const LANGUAGE_PATTERN = /^[a-z][a-z0-9-]{0,15}$/;
const PLATFORM_PATTERN = /^[a-z0-9][a-z0-9_.-]{0,31}$/;
const OS_NAMES = { darwin: "macos", win32: "windows" };
const ARCH_NAMES = { x64: "x86_64", arm64: "aarch64", ia32: "x86" };
const LANGUAGE = "ts-installed";

/** `N[.N[.N[.N]]][-PRE][+BUILD]` in at most 32 bytes. */
export function validAppVersion(value) {
  return typeof value === "string" && value.length <= 32 && VERSION_PATTERN.test(value);
}

/** Validates an application-supplied version before any request uses it. */
export function configuredAppVersion(value) {
  if (value === undefined) return null;
  if (!validAppVersion(value)) throw fail(ErrorKind.CONFIGURATION, "invalid_app_version");
  return value;
}

/** An `Orbit-Client` value, or null when a part is outside the header grammar. */
export function formatClientHeader(language, sdkVersion, platform) {
  if (typeof language !== "string" || typeof platform !== "string" || !LANGUAGE_PATTERN.test(language) ||
      !PLATFORM_PATTERN.test(platform) || !validAppVersion(sdkVersion)) return null;
  const header = `${language}/${sdkVersion} (${platform})`;
  return header.length <= 128 ? header : null;
}

function platformName() {
  const os = OS_NAMES[process.platform] ?? process.platform;
  const arch = ARCH_NAMES[process.arch] ?? process.arch;
  const value = `${os}-${arch}`.toLowerCase().replace(/[^a-z0-9_.-]/g, "_").slice(0, 32);
  return PLATFORM_PATTERN.test(value) ? value : "unknown";
}

/** This package's version from its package.json metadata. */
export const SDK_VERSION = (() => {
  const { version } = createRequire(import.meta.url)("../package.json");
  if (validAppVersion(version)) return version;
  const core = String(version ?? "").split("+")[0].split("-")[0];
  return validAppVersion(core) ? core : "0.0.0";
})();

export const CLIENT_HEADER = formatClientHeader(LANGUAGE, SDK_VERSION, platformName()) ??
  formatClientHeader(LANGUAGE, SDK_VERSION, "unknown");

/** Optional `update_available` version; a malformed hint invalidates the reply. */
export function updateHint(reply) {
  if (reply === null || typeof reply !== "object" || !Object.hasOwn(reply, "update_available")) return null;
  const hint = reply.update_available;
  if (hint === null || typeof hint !== "object" || Array.isArray(hint) || !validAppVersion(hint.version)) {
    throw fail(ErrorKind.INVALID_RESPONSE, "invalid_update_available");
  }
  return hint.version;
}
