# placeholder

PLACEHOLDER is a library to parse BACnet bytes into usable Rust structs.

Currently handles (likely imperfectly):
* BVLL
* NPDU

Targeting support for:
* NSDU ([NLM/RPDU](http://www.bacnetwiki.com/wiki/index.php?title=Network_Layer_Message_Type), APDU)
* MS/TP

To assist parsing BACnet IP or BACnet Ethernet, two recommended libraries are:
* [pnet](https://crates.io/crates/pnet)
* [etherparse](https://crates.io/crates/etherparse)

### Why not use [nom](https://crates.io/crates/nom)?

nom is a great library, but I don't think it's well suited to application layer data with weird
formats like BACnet. For example, the weirdness of the NPDU layout where the hop count value's
existence is tied to but may or may not be contiguous with the destination port/address.

Avoiding the use of nom may also lower the barrier to entry for contribution so that a
potential contributor does not also need to learn the nom library.

These are opinions, so if you disagree and would like to use nom for parsing, feel free to make
a pull request that includes nom.
