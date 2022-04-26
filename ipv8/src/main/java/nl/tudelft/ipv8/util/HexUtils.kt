package nl.tudelft.ipv8.util

private const val HEX_CHARS = "0123456789abcdef"

/**
 * Converts ByteArray to a hex string.
 * https://gist.github.com/fabiomsr/845664a9c7e92bafb6fb0ca70d4e44fd
 */
fun ByteArray.toHex(): String {
    val result = StringBuffer()

    forEach {
        val octet = it.toInt()
        val firstIndex = (octet and 0xF0).ushr(4)
        val secondIndex = octet and 0x0F
        result.append(HEX_CHARS[firstIndex])
        result.append(HEX_CHARS[secondIndex])
    }

    return result.toString()
}

/**
 * Converts a hex string to ByteArray.
 * https://gist.github.com/fabiomsr/845664a9c7e92bafb6fb0ca70d4e44fd
 */
fun String.hexToBytes(allowZero: Boolean = false): ByteArray {
    if (length % 2 != 0) {
        if (allowZero && this == "0") {
            val result = ByteArray(1).apply {
                this[0] = Integer.valueOf(0).toByte()
            }
            return result
        } else {
            throw IllegalArgumentException("String length must be even ($this)")
        }
    }

    val result = ByteArray(length / 2)

    for (i in 0 until length step 2) {
        val firstIndex = HEX_CHARS.indexOf(this[i].lowercaseChar())
        val secondIndex = HEX_CHARS.indexOf(this[i + 1].lowercaseChar())

        val octet = firstIndex.shl(4).or(secondIndex)
        result[i.shr(1)] = octet.toByte()
    }

    return result
}
