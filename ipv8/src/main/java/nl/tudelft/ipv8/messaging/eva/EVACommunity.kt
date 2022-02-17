package nl.tudelft.ipv8.messaging.eva

import mu.KotlinLogging
import nl.tudelft.ipv8.Community
import nl.tudelft.ipv8.Peer
import nl.tudelft.ipv8.keyvault.PrivateKey
import nl.tudelft.ipv8.messaging.Packet

private val logger = KotlinLogging.logger {}

abstract class EVACommunity(
    //private val community: T
): Community() {

    var evaProtocolEnabled = false
    var evaProtocol: EVAProtocol? = null

    override fun load() {
        super.load()
        if (evaProtocolEnabled)
            evaProtocol = EVAProtocol(this, scope)
    }

    lateinit var evaSendCompleteCallback: (
        peer: Peer,
        info: String,
        nonce: ULong
    ) -> Unit
    val isEvaSendCompleteCallbackInitialized get() = this::evaSendCompleteCallback.isInitialized

    lateinit var evaReceiveProgressCallback: (
        peer: Peer,
        info: String,
        progress: TransferProgress
    ) -> Unit
    val isEvaReceiveProgressCallbackInitialized get() = this::evaReceiveProgressCallback.isInitialized

    lateinit var evaReceiveCompleteCallback: (
        peer: Peer,
        info: String,
        id: String,
        data: ByteArray?
    ) -> Unit
    val isEvaReceiveCompleteCallbackInitialized get() = this::evaReceiveCompleteCallback.isInitialized

    lateinit var evaErrorCallback: (
        peer: Peer,
        exception: TransferException
    ) -> Unit
    val isEvaErrorCallbackInitialized get() = this::evaErrorCallback.isInitialized

    init {
        messageHandlers[MessageId.EVA_WRITE_REQUEST] = ::onEVAWriteRequestPacket
        messageHandlers[MessageId.EVA_ACKNOWLEDGEMENT] = ::onEVAAcknowledgementPacket
        messageHandlers[MessageId.EVA_DATA] = ::onEVADataPacket
        messageHandlers[MessageId.EVA_ERROR] = ::onEVAErrorPacket
    }

    /**
     * EVA protocol on receive handlers
     */
    fun onEVAWriteRequest(peer: Peer, payload: EVAWriteRequestPayload) {
        logger.debug { "ON EVA write request: $payload" }

        evaProtocol?.onWriteRequest(peer, payload)
    }

    fun onEVAAcknowledgement(peer: Peer, payload: EVAAcknowledgementPayload) {
        logger.debug { "ON EVA acknowledgement: $payload" }
        evaProtocol?.onAcknowledgement(peer, payload)
    }

    fun onEVAData(peer: Peer, payload: EVADataPayload) {
        logger.debug { "ON EVA acknowledgement: Block ${payload.blockNumber} with nonce ${payload.nonce}." }
        evaProtocol?.onData(peer, payload)
    }

    fun onEVAError(peer: Peer, payload: EVAErrorPayload) {
        logger.debug { "ON EVA error: $payload" }
        evaProtocol?.onError(peer, payload)
    }

    /**
     * EVA protocol on receive packet handlers
     *
     * @param packet specific packets for the EVA protocol (write request, ack, data, error)
     */
    internal fun onEVAWriteRequestPacket(packet: Packet) {
        val (peer, payload) = packet.getAuthPayload(EVAWriteRequestPayload.Deserializer)
        onEVAWriteRequest(peer, payload)
    }

    internal fun onEVAAcknowledgementPacket(packet: Packet) {
        val (peer, payload) = packet.getAuthPayload(EVAAcknowledgementPayload.Deserializer)
        onEVAAcknowledgement(peer, payload)
    }

    internal fun onEVADataPacket(packet: Packet) {
        val (peer, payload) = packet.getDecryptedAuthPayload(
            EVADataPayload.Deserializer, myPeer.key as PrivateKey
        )
        onEVAData(peer, payload)
    }

    internal fun onEVAErrorPacket(packet: Packet) {
        val (peer, payload) = packet.getAuthPayload(EVAErrorPayload.Deserializer)
        onEVAError(peer, payload)
    }

    /**
     * EVA serialized packets for different EVA payloads
     */
    fun createEVAWriteRequest(
        info: String,
        id: String,
        nonce: ULong,
        dataSize: ULong,
        blockCount: UInt,
        blockSize: UInt,
        windowSize: UInt
    ): ByteArray {
        val payload =
            EVAWriteRequestPayload(info, id, nonce, dataSize, blockCount, blockSize, windowSize)
        return serializePacket(MessageId.EVA_WRITE_REQUEST, payload)
    }

    fun createEVAAcknowledgement(
        nonce: ULong,
        ackWindow: UInt,
        unReceivedBlocks: ByteArray
    ): ByteArray {
        val payload = EVAAcknowledgementPayload(nonce, ackWindow, unReceivedBlocks)
        return serializePacket(MessageId.EVA_ACKNOWLEDGEMENT, payload)
    }

    fun createEVAData(peer: Peer, blockNumber: UInt, nonce: ULong, data: ByteArray): ByteArray {
        val payload = EVADataPayload(blockNumber, nonce, data)
        return serializePacket(MessageId.EVA_DATA, payload, encrypt = true, recipient = peer)
    }

    fun createEVAError(info: String, message: String): ByteArray {
        val payload = EVAErrorPayload(info, message)
        return serializePacket(MessageId.EVA_ERROR, payload)
    }

    ////////////////////////////

    fun setEVAOnSendCompleteCallback(
        f: (peer: Peer, info: String, nonce: ULong) -> Unit
    ) {
        this.evaSendCompleteCallback = f
    }

    fun setEVAOnReceiveProgressCallback(
        f: (peer: Peer, info: String, progress: TransferProgress) -> Unit
    ) {
        this.evaReceiveProgressCallback = f
    }

    fun setEVAOnReceiveCompleteCallback(
        f: (peer: Peer, info: String, id: String, data: ByteArray?) -> Unit
    ) {
        this.evaReceiveCompleteCallback = f
    }

    fun setEVAOnErrorCallback(
        f: (peer: Peer, exception: TransferException) -> Unit
    ) {
        this.evaErrorCallback = f
    }

    /**
     * EVA protocol entrypoint to send binary data
     *
     * @param peer the address to deliver the data
     * @param info string that identifies to which communitu or class it should be delivered
     * @param id file/data identifier that identifies the sent data
     * @param data serialized packet in bytes
     * @param nonce an optional unique number that identifies this transfer
     */
    fun evaSendBinary(
        peer: Peer,
        info: String,
        id: String,
        data: ByteArray,
        nonce: Long? = null
    ) = evaProtocol?.sendBinary(peer, info, id, data, nonce)

    object MessageId {
        const val EVA_WRITE_REQUEST = 130
        const val EVA_ACKNOWLEDGEMENT = 131
        const val EVA_DATA = 132
        const val EVA_ERROR = 133
    }
}
