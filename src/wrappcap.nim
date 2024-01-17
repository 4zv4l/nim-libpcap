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
    result = pcapOpenLive(dev.cstring, snaplen.cint, promisc.cint, to_ms.cint, err())
    if result == nil:
        raise newException(LibPcapError, fmt"Error when opening interface {dev}: {err()}")

if pcapInit(0,err()) != 0:
    raise newException(LibPcapError, fmt"Error when running pcapInit: {err()}")
