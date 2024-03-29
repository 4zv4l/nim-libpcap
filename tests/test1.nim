# This is just an example to get you started. You may wish to put all of your
# tests into a single file, or separate them into multiple `test1`, `test2`
# etc. files (better names are recommended, just make sure the name starts with
# the letter 't').
#
# To run these tests, simply execute `nimble test`.

import unittest

import wrappcap

test "get all devs":
    let devs = findAllDevs()
    echo devs.repr

test "open live":
    let dev  = findAllDevs()[0]
    let pcap = openLive(dev, 1024, false, 10000)

test "packets loop":
    let dev = findAllDevs()[0]
    let pcap = openLive(dev, 1024, false, 10000)
    for packet in pcap.packets:
        echo packet.repr
