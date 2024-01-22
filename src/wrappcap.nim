## Nim basic wrapper around libpcap

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

proc setFilter*(pcap: Pcap, filter: string) =
    ## Apply `filter` on `pcap`
    var f: BpfProgram
    if pcapCompile(pcap, f, filter, 0, 0) == -1:
        raise newException(LibPcapError, fmt"Couldnt compile: {filter}")
    if pcapSetFilter(pcap, f) == -1:
        raise newException(LibPcapError, fmt"Couldnt apply filter: {filter}")

iterator packets*(pcap: Pcap, filter: string = ""): (string, string) = 
    ## Listen for packets on `pcap` and yield the packets
    var
        packet: ptr byte
        packet_header: PcapPacketHeader
    if filter.len() > 0: setFilter(pcap, filter)
    while pcapNextEx(pcap, packet_header, packet) == 1:
        yield (packet_header.repr, packet.repr)

## TODO: use https://github.com/PMunch/nim-pcap to parse the packets
proc parse(p: ptr byte) =
    discard

if pcapInit(0,err()) != 0:
    raise newException(LibPcapError, fmt"Error when running pcapInit: {err()}")
