# Changelog

Notable changes to the OPNsense Devices add-on are documented here.

## [1.1.0] - 2026-11-15

### Added
- Compact (optional) per-device whitelist and blacklist (enable in settings).
- Create or reuse the OPNsense MAC aliases when the optional alias setting is enabled.
- List-status filtering for devices on either list.
- An animated saving spinner during alias updates.

### Changed
- Added clear, dark-mode-aware card tints for whitelist and blacklist membership, including a split tint when a device is on both lists.
- Restyled each card with a full-width device header and moved the NEW badge to the lower-left corner.
- Made list updates compatible with Home Assistant Ingress and return to the dashboard after saving.
- Decode OPNsense alias option maps and send only editable fields to `setItem`.
- Made alias API calls and related controls configurable; alias management is disabled by default.
- Documented required OPNsense API permissions and troubleshooting guidance.
