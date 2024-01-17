## Nim basic wrapper wround libpcap

import std/[strformat]
import ./wrappcap/libpcap

type
    LibPcapError = object of CatchableError

var errbuf: array[PCAP_ERRBUF_SIZE, char]
proc err*(): cstring {.inline.} =
    ## libpcap error handling
    ##
    ## Example:
    ## ```
    ## let nOfDevs = pcapFindAllDevs(devs, err())
    ## if nOfDevs == 0:
    ##     echo "error: ", $error()
    ## ```
    cast[cstring](errbuf[0].addr)

proc findAllDevs*(): seq[string] =
    ## Return a seq of interfaces as string
    var devs: PcapIf
    let nOfDevs = pcapFindAllDevs(devs, err())
    if nOfDevs != 0:
        raise newException(LibPcapError, fmt"Error with pcapFindAllDevs: {err()}")
    var dev = devs # allow to save devs to free memory later
    while dev.next != nil:
        result.add($dev.name)
        dev = dev.next
    # TODO: fix this not working (valgrind says no leak on my side)
    #pcapFreeAllDevs(devs)

proc openLive*(dev: string, snaplen: int, promisc: bool, to_ms: int): Pcap =
    ## Open the `dev` to capture packets and return the `Pcap` handle
    result = pcapOpenLive(dev.cstring, snaplen.cint, promisc.cint, to_ms.cint, err())
    if result == nil:
        raise newException(LibPcapError, fmt"Error when opening interface {dev}: {err()}")

iterator packets*(dev: string, snaplen: int = 1024, promisc: bool = false, to_ms: int = 10000): (string, string) = 
    var
        pcap = openLive(dev, snaplen, promisc, to_ms)
        packet: ptr byte
        packet_header: PcapPacketHeader

    while pcapNextEx(pcap, packet_header, packet) == 1:
        yield (packet_header.repr, packet.repr)

if pcapInit(0,err()) != 0:
    raise newException(LibPcapError, fmt"Error when running pcapInit: {err()}")
