package nl.tudelft.ipv8.attestation.wallet

import mu.KotlinLogging
import nl.tudelft.ipv8.attestation.Authority
import nl.tudelft.ipv8.attestation.WalletAttestation
import nl.tudelft.ipv8.attestation.wallet.cryptography.bonehexact.BonehPrivateKey
import nl.tudelft.ipv8.attestation.wallet.payloads.AttestationChunkPayload
import nl.tudelft.ipv8.keyvault.PublicKey
import nl.tudelft.ipv8.keyvault.defaultCryptoProvider
import nl.tudelft.ipv8.messaging.*
import nl.tudelft.ipv8.util.hexToBytes

private val logger = KotlinLogging.logger {}

class AttestationBlob(
    val attestationHash: ByteArray,
    val blob: ByteArray,
    val key: ByteArray,
    val idFormat: String,
    val metadata: String?,
    val signature: ByteArray?,
    val attestorKey: PublicKey?,
) : Serializable {
    override fun serialize(): ByteArray {
        logger.error { "Serializing attestation. Format: $idFormat, size: ${blob.size}, metadata: ${metadata ?: "empty"}" }
        // Keys are serialized using varlen here but they are fixed length
        return (
            attestationHash + serializeVarLen(blob) + serializeVarLen(key) + serializeVarLen(idFormat.toByteArray()) +
            (
                if (metadata != null && signature != null && attestorKey != null)
                        serializeVarLen(metadata.toByteArray()) +
                        serializeVarLen(signature) + serializeVarLen(attestorKey.keyToBin())
                    else byteArrayOf()
                    )
            )
    }

    companion object Deserializer : Deserializable<AttestationBlob> {
        override fun deserialize(buffer: ByteArray, offset: Int): Pair<AttestationBlob, Int> {
            var localOffset = offset

            val attestationHash = buffer.copyOfRange(localOffset,
                localOffset + SERIALIZED_SHA1_HASH_SIZE)
            localOffset += SERIALIZED_SHA1_HASH_SIZE

            val (blob, blobSize) = deserializeVarLen(buffer, localOffset)
            localOffset += blobSize

            val (key, keySize) = deserializeVarLen(buffer, localOffset)
            localOffset += keySize

            val (idFormatBytes, idFormatSize) = deserializeVarLen(buffer, localOffset)
            localOffset += idFormatSize

            return if (buffer.lastIndex > localOffset) {
                val (metadataBytes, metadataSize) = deserializeVarLen(buffer, localOffset)
                localOffset += metadataSize

                val (signature, signatureSize) = deserializeVarLen(buffer, localOffset)
                localOffset += signatureSize

                val (attestorKey, attestorkeySize) = deserializeVarLen(buffer, localOffset)
                localOffset += attestorkeySize

                val attestationBlob = AttestationBlob(
                    attestationHash,
                    blob,
                    key,
                    String(idFormatBytes),
                    String(metadataBytes),
                    signature,
                    defaultCryptoProvider.keyFromPublicBin(attestorKey))
                Pair(attestationBlob, localOffset)
            } else {
                val payload = AttestationBlob(
                    attestationHash,
                    blob,
                    key,
                    String(idFormatBytes),
                    null, null, null)
                Pair(payload, localOffset)
            }

        }
    }
}

interface AttestationStore {
    fun getAllAttestations(): List<AttestationBlob>

    fun insertAttestation(
        attestation: WalletAttestation,
        attestationHash: ByteArray,
        privateKey: BonehPrivateKey,
        idFormat: String,
        metadata: String? = null,
        signature: ByteArray? = null,
        attestorKey: PublicKey? = null,
    )

    fun getAttestationByHash(attestationHash: ByteArray): ByteArray?

    fun deleteAttestationByHash(attestationHash: ByteArray)

    fun getAllAuthorities(): List<Authority>

    fun insertAuthority(publicKey: PublicKey, hash: String)

    fun getAuthorityByPublicKey(publicKey: PublicKey): Authority?

    fun getAuthorityByHash(hash: String): Authority?

    fun deleteAuthorityByHash(hash: String)
}
