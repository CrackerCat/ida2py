import idapro
import os
import sys

cur_dir = os.path.dirname(__file__)

sys.path.append(f"{cur_dir}/..")
idapro.open_database(f"{cur_dir}/binaries/rc4", True)

try:
    import ida2py
    # Angr doesn't like being global hooked in a test environment
    # But it works in normal IDA

    # ida2py.hook(globals())
    key = "SecretKey123"
    ct = b"\x01\x83\xb8#\xba\x8d^\xb6L\xd0}Jx\xc9\xe8"
    with ida2py.angr_exec():
        malloc = ida2py._ida("malloc")
        rc4_init = ida2py._ida("rc4_init")
        rc4_process = ida2py._ida("rc4_process")
        print_bytes = ida2py._ida("print_bytes")
        printf = ida2py._ida("printf")

        state = malloc(0x200) # little bit extra to be safe
        rc4_init(state, key, len(key))

        out = malloc(len(ct))
        rc4_process(state, ct, out, len(ct))
        print_bytes(out, len(ct))

        assert out.bytes() == b"ida2py RC4 demo", out.bytes()

        printf("output: %s\n", out)
finally:
    idapro.close_database(False)