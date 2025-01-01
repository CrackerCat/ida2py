import idapro
import os
import sys

cur_dir = os.path.dirname(__file__)

sys.path.append(f"{cur_dir}/..")
idapro.open_database(f"{cur_dir}/binaries/flareon_sshd_shellcode", True)

try:
    import ida2py
    # angr doesn't like being global hooked in a test environment
    # But it works in normal IDA

    # ida2py.hook(globals())

    import idc

    idc.set_name(0x401CD2, "setup")
    idc.SetType(0x401CD2, "void __usercall setup(__int64 a1@<rax>, __int64 a2@<rdx>, __int64 a3@<rcx>, __int64 a4@<r8>)")
    setup = ida2py._ida("setup")

    idc.set_name(0x401D49, "decrypt")
    idc.SetType(0x401D49, "void __usercall decrypt(__int64 a1@<rax>, __int64 a2@<rdx>, __int64 a3@<rcx>)")
    decrypt = ida2py._ida("decrypt")

    key = bytes.fromhex("8d ec 91 12 eb 76 0e da 7c 7d 87 a4 43 27 1c 35 d9 e0 cb 87 89 93 b4 d9 04 ae f9 34 fa 21 66 d7")
    nonce = bytes.fromhex("11 11 11 11 11 11 11 11 11 11 11 11")
    ct = bytes.fromhex("A9 F6 34 08 42 2A 9E 1C 0C 03 A8 08 94 70 BB 8D AA DC 6D 7B 24 FF 7F 24 7C DA 83 9E 92 F7 07 1D 02 63 90 2E C1 58")

    with ida2py.angr_exec() as executor:
        state = executor.alloc(0x100)
        buf = executor.buf(ct)
        
        setup(state, key, nonce, 0)
        decrypt(state, buf, len(ct))
        
        print("output:", buf.bytes())
        assert b'supp1y_cha1n_sund4y@flare-on.com' in buf.bytes()
finally:
    idapro.close_database(False)