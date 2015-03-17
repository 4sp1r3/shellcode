#!/bin/python3

import struct
import sys
import os
import telnetlib
from subprocess import Popen, PIPE, check_output

NB_BYTES_ADDR = 4


def set64(integer):
    return struct.pack("<Q", integer)


def set32(integer):
    return struct.pack("<I", integer)


def set16(integer):
    return struct.pack("<H", integer)

  
def setbytes(by):
    return bytes(by)


def setbyte(by):
    return struct.pack("B", by)

  
def int_to_bytes(val, num_bytes):
    return [(val & (0xff << pos*8)) >> pos*8 for pos in range(num_bytes)]


def pad(n, c="C"):
    return str.encode(c) * n


def info(s):
    print("info: %s" % s, file=sys.stderr)


def warn(s):
    print("warn: %s" % s, file=sys.stderr)


def die(s):
    print("err: %s" % s, file=sys.stderr)
    sys.exit(1)


def write(payload):
    info("payload length " + str(len(payload)))
    if payload.find(b"\x00") != -1:
        warn("payload contains null bytes")
    os.write(1, payload)


def net_send_close(host, port, payload):
    tn = net_connect(host, port)
    net_send(tn, payload)
    net_close(tn)


def net_connect(host, port):
    try:
        return telnetlib.Telnet(host, port)
    except Exception as e:
        die(("%s:%d " % (host, port)) + e.__str__())
    return None


def net_send(tn, payload):
    info("payload length " + str(len(payload)))
    if payload.find(b"\x00") != -1:
        warn("payload contains null bytes")
    try:
        s = tn.get_socket()
        s.send(payload)
    except Exception as e:
        die(("%s:%d " % (host, port)) + e.__str__())


def net_close(tn):
    try:
        tn.close()
    except Exception as e:
        die(("%s:%d " % (host, port)) + e.__str__())


def net_interact(host, port):
    try:
        tn = telnetlib.Telnet(host, port)
        info("connected to %s %d " % (host, port))
        tn.interact()
    except Exception as e:
        die(("%s:%d " % (host, port)) + e.__str__())


def run(arg=[], env={}, pipe=False):
    if pipe:
        return Popen(arg, env=env, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    return Popen(arg, env=env, stdin=PIPE)


def execve(arg=[], env={}):
    os.execve(arg[0], arg, env)


def converthex(p):
    ret = ""
    for c in p:
        s = hex(c)[2:]
        if len(s) == 1:
            s = "0" + s
        ret += "\\x" + s
    return ret


def compile_asm(asm):
    fd = open("/tmp/code.asm", "w")
    fd.write(asm)
    fd.close()
    binary = check_output(["/usr/bin/nasm", "/tmp/code.asm", "-o", "/dev/stdout"])
    os.remove("/tmp/code.asm")
    return binary

