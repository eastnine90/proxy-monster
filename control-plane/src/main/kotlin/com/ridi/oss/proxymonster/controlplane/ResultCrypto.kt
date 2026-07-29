package com.ridi.oss.proxymonster.controlplane

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * AES-256-GCM at-rest encryption for APPROVER_EXEC query results — the one path where the
 * control-plane persists PII-bearing rows. The stored blob is `iv(12) || ciphertext+tag`; GCM gives
 * confidentiality + integrity (a tampered blob fails to decrypt). The key comes from `PM_RESULT_KEY`
 * (env, 32 bytes); when it's unset, [QueryResultStore] isn't constructed and approver-exec execution
 * is refused fail-closed. A per-result random IV keeps identical results from producing identical blobs.
 */
class ResultCrypto(keyBytes: ByteArray) {
    init {
        require(keyBytes.size == 32) { "result-encryption key must be 32 bytes (AES-256)" }
    }

    private val key = SecretKeySpec(keyBytes, "AES")
    private val random = SecureRandom()

    fun encrypt(plaintext: ByteArray): ByteArray {
        val iv = ByteArray(IV_LEN).also { random.nextBytes(it) }
        val cipher = Cipher.getInstance(TRANSFORM).apply {
            init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
        }
        return iv + cipher.doFinal(plaintext)
    }

    fun decrypt(blob: ByteArray): ByteArray {
        require(blob.size > IV_LEN) { "ciphertext too short" }
        val iv = blob.copyOfRange(0, IV_LEN)
        val cipher = Cipher.getInstance(TRANSFORM).apply {
            init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
        }
        return cipher.doFinal(blob, IV_LEN, blob.size - IV_LEN)
    }

    private companion object {
        const val TRANSFORM = "AES/GCM/NoPadding"
        const val IV_LEN = 12
        const val TAG_BITS = 128
    }
}
