import idapro
import os
import sys
import angr
import claripy
import idc

cur_dir = os.path.dirname(__file__)

sys.path.append(f"{cur_dir}/..")
idapro.open_database(f"{cur_dir}/binaries/angr_symbolic", True)

try:
    import ida2py
    # angr doesn't like being global hooked in a test environment
    # But it works in normal IDA

    # ida2py.hook(globals())
    idc.SetType(0x4040, "char ciphertext[126];")
    ct = ida2py._ida("ciphertext")
    encrypt = ida2py._ida("encrypt")
    l = len(ct)
    with ida2py.angr_exec() as e:
        msg = claripy.BVS("msg", 8 * l)
        buf = e.buf(msg)
        encrypt(buf, l)
        e.state.add_constraints(buf == ct)
        res = e.state.solver.eval(msg, cast_to=bytes)

        print(res.decode())
        
        assert res == b"Happy New Year!!!\n\nYou climbed a mountain, are you satisfied?\nAs you stand at the top\nYou already wanna do this\nOne more time\n"
finally:
    idapro.close_database(False)