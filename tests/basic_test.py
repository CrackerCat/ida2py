import idapro
import os
import sys

cur_dir = os.path.dirname(__file__)

sys.path.append(f"{cur_dir}/..")
idapro.open_database(f"{cur_dir}/binaries/basic_test", True)

try:
    import ida2py

    ida2py.hook(globals())

    print("names", names)
    assert type(names) is ida2py.PointerWrapper
    assert names.pyval() == b"hell"

    # Variable types will update when set in ida`
    import idc
    idc.SetType(names.address, "char * names[4];")
    print("names2", names)
    assert type(names) is ida2py.ArrayWrapper
    assert len(names) == 4
    assert names[0].pyval() == b"hell"
    assert names.pyval() == [b'hell', b'ow', b'world', b'dl']
    assert names[1][0] == ord('o')
    assert names[-1].pyval() == b"dl"

    array = (uint * 5) @ arr.address
    print("array", array)
    assert type(array) is ida2py.ArrayWrapper
    assert type(array[0]) is ida2py.IntWrapper
    assert array[0] == 1
    assert array[1] + 3 == 5
    assert array[array[0]] == 2, array[array[0]]


    idc.SetType(arr_ptr.address, "int* arr_ptr;")
    assert arr_ptr[0] == 1
    assert arr_ptr[1] == 2


    arr_ptr2 = (ulong * 2).ptr() @ arr_ptr.address

    print(arr_ptr2)
    assert arr_ptr2.pyval() == [8589934593, 17179869187]

    idc.parse_decls("""
    struct Node{
        unsigned long val;
        Node* left;
        Node* right;
    };
    """, 0)
    idc.SetType(n1.address, "Node")

    assert n1.val == 90
    assert n1.pyval() == {'val': 0x5a, 'left': {'val': 0x56, 'left': {'val': 0x1, 'left': None, 'right': None}, 'right': None}, 'right': {'val': 0x41, 'left': None, 'right': None}}
finally:
    idapro.close_database(False)