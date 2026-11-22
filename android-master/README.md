# MinControl master (Android) - M0 skeleton

Kotlin + Compose Material 3, portrait only, Vietnamese UI, 4 placeholder tabs (Tong quan / Hoat dong / Canh bao / Quy tac).
`data/protocol/` mirrors `../protocol/*.schema.json`; `security/MasterKeyStore` is an empty interface for now.

Build (Git Bash, toolchain lives in `D:/Coding_Project/MinControl/tools`):

    source /d/Coding_Project/MinControl/tools/env-android.sh
    ./gradlew :app:testDebugUnitTest :app:assembleDebug

Tests: `ProtocolContractTest` validates every fixture in `../protocol/fixtures` against its schema (networknt, draft 2020-12);
`CommandRoundTripTest` decodes/re-encodes valid command fixtures. Do not edit `../protocol`.
`local.properties` (sdk.dir) is gitignored. Font certs in `res/values/font_certs.xml` come from android/compose-samples.
