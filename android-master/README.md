# MinControl master (Android)

Kotlin + Compose Material 3, portrait only, Vietnamese UI, light theme (Be Vietnam Pro). Screens follow
`docs/design/master-app/project/*.dc.html`: Tổng quan (+ lock confirm sheet), Hoạt động (Dòng TG / Web / Ứng dụng / Ảnh),
Cảnh báo, Quy tắc (policy editor with diff + biometric apply), Thêm máy tính (pairing + choose managed users → policy v1),
Cài đặt (keys, seal-key backup, devices/revoke, re-register), first-run Setup. Extras: Glance home-screen widget
(time left per child) and Quick Settings tile "Khóa tất cả".

## Layout
| Package | What |
|---|---|
| `security/` | Keystore keys `sign` (BiometricPrompt every use) + `read` (no auth); Ed25519 on API 33+ else P-256 (StrongBox when available, DER→P1363); X25519 seal key encrypted by a Keystore AES-GCM key; libsodium `crypto_box_seal_open` on BouncyCastle; Argon2id passphrase backup |
| `envelope/` | SignedBody serialised once → signed → SignedEnvelope; seq = max(server, local) + 1 per (device, kind) |
| `data/api` | OkHttp client for every endpoint of `protocol/API.md` §5 with `X-MC-Auth` (read key, unix-seconds ts) |
| `data/db` | Room cache (devices, alerts + local ack, web history, last policy) for offline viewing |
| `data/protocol` | Kotlin mirrors of the schemas (`Policy.kt`, `Command.kt`, `Envelope.kt`) and API DTOs |
| `policy/` | defaults for new children, diff ("N thay đổi"), semantic validation |
| `push/` | FCM data messages → notifications (channels critical / warn / info), token upload |
| `widget/`, `tile/` | Glance widget, Quick Settings tile + translucent lock-all activity |

## Build
Git Bash, toolchain inside `D:/Coding_Project/MinControl/tools`:

    source /d/Coding_Project/MinControl/tools/env-android.sh
    ./gradlew :app:assembleDebug          # tests: ./gradlew :app:testDebugUnitTest (lead runs them)

## Firebase (push) — optional at build time
`app/google-services.json` is **not** committed. Without it the app builds and runs; push is disabled.
To enable: create a Firebase project, add an Android app with id `io.github.nevminhnh.mincontrol.master`,
download `google-services.json` into `android-master/app/`, rebuild. The Gradle script applies the
`com.google.gms.google-services` plugin only when that file exists. The cloud needs the matching FCM
service-account credentials to send data messages (API.md §6).

## Tests (JVM, `app/src/test`)
`ProtocolContractTest` / `CommandRoundTripTest` (schemas + fixtures), `SigFormatTest` (keyId KAT, DER↔P1363),
`SealedBoxTest` (RFC 7748 / NaCl known answers + sealed-box KAT + Argon2id backup), `EnvelopeBuilderTest`
(Ed25519 + ES256 envelopes validated against the schemas, signature over the exact payload bytes),
`SeqAllocatorTest`, `PolicyDiffTest` (diff, fixtures round trip, semantic-invalid fixtures rejected), `AuthHeaderTest`.

`local.properties` (sdk.dir) is gitignored. Font certs in `res/values/font_certs.xml` come from android/compose-samples.
