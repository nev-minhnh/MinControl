package io.github.nevminhnh.mincontrol.master.security

/**
 * Holds the master signing key.
 *
 * Planned implementation: Android Keystore, StrongBox when available, non-exportable,
 * user authentication required (BiometricPrompt per signature). Ed25519 when the device Keystore
 * supports it, otherwise ECDSA P-256 (ES256). No implementation yet (M0 skeleton).
 */
interface MasterKeyStore
