import idapro
import os
import sys

cur_dir = os.path.dirname(__file__)

sys.path = [f"{cur_dir}/.."] + sys.path
idapro.open_database(f"{cur_dir}/binaries/rc4", True)

try:
    import ida2py

    printf: ida2py.FunctionWrapper = ida2py._ida("printf")

    callsites = list(printf.callsites())
    callsites = sorted(callsites)
    expected_args = [b"%02x ", b"Original:  %s\n", b"Original Bytes: ", b"Encrypted Bytes: ", b"Decrypted: %s\n"]
    args = [ida2py._ida(callsite.args[0].obj_ea) for callsite in callsites]
    print(callsites)
    for i, x in enumerate(args):
        assert x.pyval() == expected_args[i], f"Expected {expected_args[i]}, got {x}"

finally:
    idapro.close_database(False)