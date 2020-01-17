package nl.tudelft.ipv8

import nl.tudelft.ipv8.keyvault.LibNaClSK
import nl.tudelft.ipv8.messaging.udp.UdpEndpoint
import nl.tudelft.ipv8.peerdiscovery.Network
import nl.tudelft.ipv8.peerdiscovery.strategy.RandomWalk
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress

class Ipv8Test {
    @Test
    fun startAndStop() {
        val myKey = LibNaClSK.generate()
        val address = Address("0.0.0.0", 8090)
        val myPeer = Peer(myKey, address, false)
        val endpoint = UdpEndpoint(8090, InetAddress.getByName("0.0.0.0"))
        val network = Network()
        val community = ExampleCommunity(myPeer, endpoint, network)
        val randomWalk = RandomWalk(
            community,
            timeout = 3.0
        )
        val overlayConfig = OverlayConfiguration(community, listOf(randomWalk))

        val config = Ipv8Configuration(overlays = listOf(overlayConfig), walkerInterval = 5.0)
        val ipv8 = Ipv8(endpoint, config)
        ipv8.start()
        assertTrue(endpoint.isOpen())
        ipv8.stop()
    }
}