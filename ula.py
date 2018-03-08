#!/usr/bin/env python3
# encoding: utf-8 (as per PEP 263)

import hashlib
import ipaddress
import sys
import time
import uuid

def generate_ula():
    """This generates a Unique Local IPv6 Unicast Address (ULA) according to
    the algorithm in RFC 4193, section 3.2.2."""

    """
    3.2.2.  Sample Code for Pseudo-Random Global ID Algorithm

       The algorithm described below is intended to be used for locally
       assigned Global IDs.  In each case the resulting global ID will be
       used in the appropriate prefix as defined in Section 3.2.
    """

    # 1) Obtain the current time of day in 64-bit NTP format [NTP].
    tod = time.time()
    tod_int = int(tod)
    tod_frac = int( (tod % 1) * (1<<32) )
    tod_bytes = tod_int.to_bytes(4, 'big') + tod_frac.to_bytes(4, 'big')

    # 2) Obtain an EUI-64 identifier from the system running this
    #    algorithm.  If an EUI-64 does not exist, one can be created from
    #    a 48-bit MAC address as specified in [ADDARCH].  If an EUI-64
    #    cannot be obtained or created, a suitably unique identifier,
    #    local to the node, should be used (e.g., system serial number).
    eui48 = uuid.getnode()
    eui48_bytes = eui48.to_bytes(6, 'big')

    # 3) Concatenate the time of day with the system-specific identifier
    #    in order to create a key.
    key = tod_bytes + eui48_bytes

    # 4) Compute an SHA-1 digest on the key as specified in [FIPS, SHA1];
    #    the resulting value is 160 bits.
    digest = hashlib.sha1(key).digest()

    # 5) Use the least significant 40 bits as the Global ID.
    global_id_len = 5 # 40 bits / 8 bits per byte
    global_id = digest[(len(digest)-global_id_len):]

    # 6) Concatenate FC00::/7, the L bit set to 1, and the 40-bit Global
    #    ID to create a Local IPv6 address prefix.

    # (We are actually computing and outputting the network address, i.e. the
    # address with all host bits set to zero.)
    net_addr = \
        0xfc << (40 + 16 + 64) | \
        1 << (40 + 16 + 64) | \
        int.from_bytes(global_id, 'big') << (16 + 64)

    return ipaddress.IPv6Address(net_addr)

    """
       This algorithm will result in a Global ID that is reasonably unique
       and can be used to create a locally assigned Local IPv6 address
       prefix.
    """


def main():
    print(generate_ula())

if __name__ == '__main__':
    main()
