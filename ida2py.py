import ida_bytes
import idc
import __main__

from ctypes import *
import builtins
import functools

import idc
import ida_typeinf
import ida_bytes
import idaapi
import ida_nalt
import ida_funcs
import idautils

import typing
from copy import copy


state = None

class context:
    print_style = 'dec'
    auto_deref = False

context.print_style = 'dec'

class IntWrapperMeta(type):
    def __new__(cls, name, bases, namespace):
        # List of special methods that return integers and should return IntWrapper instead
        int_returning_methods = [
            '__add__', '__radd__', '__sub__', '__rsub__',
            '__mul__', '__rmul__', '__floordiv__', '__rfloordiv__',
            '__mod__', '__rmod__', '__pow__', '__rpow__',
            '__lshift__', '__rlshift__', '__rshift__', '__rrshift__',
            '__and__', '__rand__', '__or__', '__ror__',
            '__xor__', '__rxor__', '__neg__', '__pos__',
            '__abs__'
        ]
        
        # For each method that returns an int, create a wrapped version
        for method_name in int_returning_methods:
            if method_name not in namespace:  # Only if not already defined
                def make_wrapped_method(method_name):
                    def wrapped_method(self, *args, **kwargs):
                        # Get the original method from int class
                        original_method = getattr(int, method_name)
                        # Call it and wrap the result
                        args = [x.value if isinstance(x, Wrapper) else x for x in args]
                        result = original_method(self.value, *args, **kwargs)
                        return IntWrapper(self.signed, self.bits, self.byte_order, result)
                    return wrapped_method
                
                namespace[method_name] = make_wrapped_method(method_name)
        
        return super().__new__(cls, name, bases, namespace)

@functools.total_ordering
class Wrapper:
    address: int|None = None
    _value: typing.Any|None = None

    @property
    def value(self):
        if self._value is not None:
            return self._value
        self._value = self._get_value()
        return self._value

    def _get_value(self):
        raise NotImplementedError()
    
    def type_name(self):
        raise NotImplementedError()
    
    def array_repr(self):
        raise NotImplementedError()
    
    def addr_repr(self):
        return f' @ {hex(self.address)}' if self.address is not None else ''

    def pyval(self):
        def _pyval(v):
            if isinstance(v, StructWrapper):
                v = {k:_pyval(val[1]) for k,val in v.value.items()}
            if isinstance(v, Wrapper):
                v = _pyval(v.value)
            if isinstance(v, list):
                v = [_pyval(x) for x in v]
            return v
        return _pyval(self)

    def __repr__(self):
        raise NotImplementedError()
    
    def __bytes__() -> bytes:
        raise NotImplementedError()
    
    def __sizeof__(self) -> int:
        raise NotImplementedError()
    
    def __copy__(self) -> "Wrapper":
        raise NotImplementedError()
    
    def __str__(self):
        return repr(self)
    
    def __eq__(self, other):
        if isinstance(other, type(self)):
            return self.value == other.value
        return self.value == other

    def __lt__(self, other):
        if isinstance(other, type(self)):
            return self.value < other.value
        return self.value < other
    
    def __bool__(self):
        return bool(self.value)

        

class _Invalid:
    def __init__(self):
        pass

    def __repr__(self):
        return "Invalid"

Invalid = _Invalid()

class IntWrapper(Wrapper, metaclass=IntWrapperMeta):
    def __init__(self, signed=True, bits=32, byte_order='little', value=None, address = None):
        self.signed = signed
        self.bits = bits
        self.byte_order = byte_order
        self._value = value
        self.address = address
    
    def _get_value(self):
        try:
            return int.from_bytes(idc.get_bytes(self.address, self.bits//8), self.byte_order, signed=self.signed)
        except TypeError:
            return Invalid
    
    def type_name(self):
        return f"{'' if self.signed else 'U'}Int{self.bits}"
    
    def array_repr(self):
        if context.print_style == 'dec':
            return str(self.value)
        else:
            return hex(self.value)
    
    def __repr__(self):
        if self.address is None and self._value is None:
            return self.type_name()
        return f"{self.type_name()}({self.array_repr()})" + self.addr_repr()
    
    def __bytes__(self):
        return int.to_bytes(self.value, self.bits//8, self.byte_order, signed=self.signed)
    
    def __sizeof__(self):
        return self.bits // 8
    
    def __copy__(self):
        return IntWrapper(self.signed, self.bits, self.byte_order, self._value, self.address)
    
    def __int__(self):
        return self.value

    def __index__(self):
        return self.value
    
    def __call__(self, val):
        assert self.address is None and self._value is None
        t = copy(self)
        t.address = None
        if isinstance(val, int):
            t._value = val
            return t
        if isinstance(val, Wrapper):
            val = bytes(val)
            t.address = val.address
        if type(val) != bytes:
            raise TypeError(f"Cannot convert from {val} to {self.type_name()}")
        if context.allow_excess:
            val = val[:self.bits//8]
        assert len(val) == self.bits//8, f"Input size {len(val)} != integer size {self.bits//8}"
        t._value = int.from_bytes(val, self.byte_order, signed=self.signed)
        return t

class ArrayWrapper(Wrapper):
    _t: Wrapper
    _length: int

    def __init__(self, t: Wrapper, length):
        self._t = t
        self._length = length
        self.address = t.address

    def __getitem__(self, index):
        if isinstance(index, slice):
            return self.value.__getitem__(index)
        if index < 0:
            index += self._length
        if index >= self._length:
            raise IndexError(f"Array index {index} out of range for array of size {self._length}")
        if index < 0:
            raise IndexError(f"Array index {index} cannot be negative")
        elem = copy(self._t)
        elem._value = None
        elem.address = self.address + int(index) * elem.__sizeof__()
        return elem
    
    def __len__(self):
        return self._length
    
    def __iter__(self):
        for i in range(self._length):
            yield self[i]
    
    def _get_value(self):
        out = []
        for i in range(self._length):
            out.append(self[i])
        return out

    def __sizeof__(self):
        return self._t.__sizeof__() * self._length
    
    def type_name(self):
        return self._t.type_name() + f"[{self._length}]"
    
    def array_repr(self):
        if self.address is None:
            return ""

        if self._length > 10:
            if self.value:
                items = self.value[:10]
            else:
                items = [self[i] for i in range(10)]
        else:
            items = self.value
        
        return "{" + (", ".join(x.array_repr() for x in items)) + (", ..." if self._length > 10 else '') + "}"
    
    def __bytes__(self):
        out = b""
        for v in self.value:
            out += bytes(v)
        return out
    
    def __copy__(self) -> "Wrapper":
        return ArrayWrapper(self._t, self._length)
    
    def __repr__(self) -> str:
        return self.type_name() + self.array_repr() + self.addr_repr()


class StringWrapper(Wrapper):
    _length: int
    _str_type: str
    def __init__(self, length, str_type, address):
        self._length = length
        self.address = address
        if str_type is None:
            str_type = "char"
        self._str_type = str_type
    
    def __getitem__(self, index):
        return self.value.__getitem__(index)
    
    def __len__(self):
        if self._length:
            return self._length
        return len(self.value)
    
    def __iter__(self):
        return self.value.__iter__()
    
    def __repr__(self):
        ret = self.array_repr()
        if self._str_type == 'wchar_t':
            ret = "L"+ret[1:]
        return ret + self.addr_repr()
    
    def __str__(self):
        return repr(self)
    
    def _get_value(self):
        res = idc.get_strlit_contents(self.address, strtype=ida_nalt.STRTYPE_C_16 if self._str_type == "wchar_t" else ida_nalt.STRTYPE_C)
        if res:
            return res
        try:
            return idc.get_bytes(self.address, self._length)
        except TypeError:
            raise ValueError(f"Could not get bytes at {hex(self.address)}")
       
    def type_name(self):
        if self._length is None:
            return f"{self._str_type}[]"
        return f"{self._str_type}[{self._length}]"
    
    def array_repr(self):
        if self._length is not None and self._length > 256:
            return bytes.__str__(idc.get_bytes(self.address, 256)) + f" and {self._length - 256} more bytes"
        return bytes.__str__(self.value)
    
    def __bytes__(self) -> bytes:
        return self.value
    
    def __sizeof__(self) -> int:
        return len(self) * (2 if self._str_type == "wchar_t" else 1)
    
    def __copy__(self) -> "Wrapper":
        return StringWrapper(self._length, self._str_type, self.address)


class PointerWrapper(Wrapper):
    def __init__(self, is_string, tinfo_hint, address):
        self.address = address
        self._is_string = is_string
        self._tinfo_hint = tinfo_hint
    
    def _get_value(self):
        pointed_addr = read_pointer(self.address)
        if pointed_addr is Invalid:
            return pointed_addr
        if pointed_addr == 0:
            return None
        return self._deref_at_address(pointed_addr, True)
    

    def _deref_at_address(self, pointed_addr, get_whole=False):
        if self._is_string and get_whole:
            tinfo = ida_typeinf.tinfo_t()
            ida_typeinf.parse_decl(tinfo, None, f"char[];", ida_typeinf.PT_SIL)
        else:
            tinfo = None
            if self._tinfo_hint is None:
                tinfo = get_type_at_address(pointed_addr)
            if tinfo is None:
                tinfo = self._tinfo_hint
            
        if tinfo is None:
            print(f"Failed to get type at {hex(pointed_addr)}")
            return UnknownWrapper(pointed_addr)
        return ida2py(tinfo, pointed_addr)
       
    def type_name(self):
        if self.address is None:
            if self._tinfo_hint is None:
                return "Unknown*"
            new_tinfo = ida_typeinf.tinfo_t()
            new_tinfo.create_ptr(self._tinfo_hint)
            return new_tinfo.dstr()
        if self._is_string:
            return self.value.type_name()
        return f"{self.value.type_name()}*"
    
    def array_repr(self):
        if read_pointer(self.address) == 0:
            return "NULL"
        if self._is_string:
            return self.value.array_repr()
        if read_pointer(self.address) is Invalid:
            return "Invalid"
        if context.auto_deref:
            return repr(self)
        return "{" + self.type_name() + "} " + hex(read_pointer(self.address))

    def __repr__(self):
        if self.value is Invalid:
            return f"Pointer to Invalid"
        if self.value is None:
            return "NULL"
        return f"Pointer to ({self.value})" + self.addr_repr()
    
    def __bytes__(self) -> bytes:
        return int.to_bytes(read_pointer(self.address), get_address_size(), get_byteorder())
    
    def __sizeof__(self) -> int:
        return get_address_size()
    
    def __copy__(self) -> "Wrapper":
        return PointerWrapper(self._is_string, self._tinfo_hint, self.address)
    
    def __getitem__(self, index):
        if index == 0 and self.address is None:
            return self.value
        pointed_addr = read_pointer(self.address)
        if pointed_addr is Invalid:
            return pointed_addr
        if self._tinfo_hint is not None:
            tif = self._tinfo_hint
            if tif.is_array() and tif.get_size() == 0:
                tif.remove_ptr_or_array()
            elem_size = tif.get_size()
        else:
            elem_size = self.value.__sizeof__()
        pointed_addr += int(index) * elem_size
        return self._deref_at_address(pointed_addr)
    
    def __call__(self, val):
        assert self.address is None
        t = copy(self)
        t.address = None
        if isinstance(val, Wrapper):
            t.address = val
            return t
    
    def __getattr__(self, key):
        if isinstance(self.value, StructWrapper):
            return self.value.__getattr__(key)
        raise AttributeError(f"PointerWrapper object has no attribute {key}")


class StructWrapper(Wrapper):
    _tif: ida_typeinf.tinfo_t
    _name: str
    _members: dict[str, Wrapper]
    def __init__(self, tif: ida_typeinf.tinfo_t, address):
        self._tif = tif
        self._name = tif.get_type_name()
        self._members = {}
        udt = ida_typeinf.udt_type_data_t()
        self.address = address
        if tif.get_udt_details(udt):
            for udm in udt:
                udm_type: ida_typeinf.tinfo_t = ida_typeinf.tinfo_t(udm.type)
                offset = udm.offset//8
                res = ida2py(udm_type, None)
                self._members[udm.name] = (offset, res)
    
    def _get_value(self):
        assert self.address is not None
        out = {}
        for key in self._members:
            offset, t = self._members[key]
            t = copy(t)
            t._value = None
            t.address = self.address + offset
            out[key] = (offset, t)
        return out
       
    def type_name(self):
        return "struct "+self._name
    
    def array_repr(self, oneliner=True):
        lines = []
        members = sorted(self.value.items(), key=lambda k: k[1][0])
        for name, (offset, type) in members:
            lines.append(("  " if not oneliner else "") + f"{name} = {type.array_repr()}")
        if oneliner:
            return self.type_name() + " {" + ", ".join(lines) + "}"
        else:
            return self.type_name() + " {\n" + ",\n".join(lines) + "\n}"

    def __repr__(self):
        return self.array_repr(False) + self.addr_repr()
    
    def __bytes__(self) -> bytes:
        out = b""
        members = sorted(self.value.items(), key=lambda k: k[1][0])
        for name, (offset, type) in members:
            if len(out) != offset:
                out += b"\0" * (offset - len(out))
            assert len(out) == offset
            out += bytes(type)
        out += (b"\0" * (self.__sizeof__() - len(out)))
        assert len(out) == self.__sizeof__(), (len(out), self.__sizeof__())
        return out
    
    def __sizeof__(self) -> int:
        return self._tif.get_size()
    
    def __copy__(self) -> "Wrapper":
        return StructWrapper(self._tif, self.address)
    
    def __getattr__(self, key):
        if key in self.value:
            offset, t = self.value[key]
            if self.address is None:
                return t
            if t.address is None:
                t = copy(t)
                t.address = self.address + offset
            return t
        raise AttributeError(f"struct '{self._name}' has no member {key}")


class FunctionWrapper(Wrapper):
    _tif: ida_typeinf.tinfo_t
    _func: ida_funcs.func_t
    _func_data: ida_typeinf.func_type_data_t
    def __init__(self, tif, func, address):
        assert tif.is_func(), f"{tif} is not a function type"
        if idc.get_segm_attr(address, idc.SEGATTR_TYPE) == 1:
            # extern
            ea = next(idautils.CodeRefsTo(address, 0), None)
            func = ida_funcs.get_func(ea)
            if func is not None:
                address = next(func.addresses())
        self._tif = tif
        self._func = func
        self._func_data = ida_typeinf.func_type_data_t()
        assert tif.get_func_details(self._func_data)
        self.address = address
    
    @property
    def name(self):
        return idc.get_name(self._func.start_ea)
    
    @property
    def offset_str(self):
        return (f' + {hex(self.address - self._func.start_ea)}' if self.address != self._func.start_ea else '')

    def _get_value(self):
        return f"Function {self.name} at {hex(self.address)}"
       
    def type_name(self):
        return ida_typeinf.print_tinfo("", 0, 0, 0, self._tif, self.name, "")
    
    def array_repr(self):
        if self.offset_str:
            return self.name + self.offset_str
        return f"Function {self.name}"

    def __repr__(self):
        return self.type_name() + self.offset_str + self.addr_repr()
    
    def __bytes__(self) -> bytes:
        raise NotImplementedError("Cannot convert function to bytes")

    def __sizeof__(self) -> int:
        return self._func.size()
    
    def __copy__(self) -> "Wrapper":
        return FunctionWrapper(self._tif, self._func, self.address)
    
    def __call__(self, *args):
        raise NotImplementedError()

class UnknownWrapper(Wrapper):
    def __init__(self, address):
        self.address = address
    
    def _get_value(self):
        raise ValueError("Cannot get value of unknown")
       
    def type_name(self):
        return "Unknown"
    
    def array_repr(self):
        return "Unknown"

    def __repr__(self):
        return "Unknown" + self.addr_repr()
    
    def __bytes__(self) -> bytes:
        raise ValueError("Cannot convert unknown to bytes")
    
    def __sizeof__(self) -> int:
        raise ValueError("Cannot get size of unknown")
    
    def __copy__(self) -> "Wrapper":
        return UnknownWrapper(self.address)
    

def get_byteorder():
    return 'big' if idaapi.inf_is_be() else 'little'

def get_address_size():
    address_size = 8
    if idaapi.inf_is_32bit_exactly():
        address_size = 4
    elif idaapi.inf_is_16bit():
        address_size = 2
    return address_size

def read_pointer(ea):
    try:
        return int.from_bytes(idc.get_bytes(ea, get_address_size()), get_byteorder())
    except TypeError:
        return Invalid

def get_type_at_address(ea) -> ida_typeinf.tinfo_t | None:
    t_str = idc.get_type(ea)
    tinfo = ida_typeinf.tinfo_t()
    if t_str is not None:
        t_str += ";"
        t_str = t_str.replace("(", " x(")
        result = ida_typeinf.parse_decl(tinfo, None, t_str, ida_typeinf.PT_SIL)
        if result is not None:
            return tinfo
    flags = ida_bytes.get_flags(ea)
    if not ida_bytes.is_loaded(ea):
        return None
    if ida_bytes.is_code(flags):
        func = idaapi.get_func(ea)
        if ea == func.start_ea:
            result = ida_typeinf.parse_decl(tinfo, None, "void x();", ida_typeinf.PT_SIL)
            if result is not None:
                return tinfo
        return get_type_at_address(func.start_ea)
    elif ida_bytes.is_off0(flags):
        pointed_addr = read_pointer(ea)
        if pointed_addr is Invalid:
            return
        inner_type = get_type_at_address(pointed_addr)
        if inner_type is None:
            ida_typeinf.parse_decl(tinfo, None, f"void*;", ida_typeinf.PT_SIL)
            return tinfo
        tinfo.create_ptr(inner_type)
        return tinfo
    elif ida_bytes.is_strlit(flags):
        string_type = 'wchar_t' if ida_nalt.get_str_type(ea) & ida_nalt.STRTYPE_C_16 else 'char'
        result = ida_typeinf.parse_decl(tinfo, None, f"{string_type}[];", ida_typeinf.PT_SIL)
        if result is not None:
            return tinfo
    elif ida_bytes.is_data(flags):
        size = ida_bytes.get_item_size(ea)
        result = ida_typeinf.parse_decl(tinfo, None, f"__int{size*8};", ida_typeinf.PT_SIL)
        if result is not None:
            return tinfo

def ida2py(tif: ida_typeinf.tinfo_t, addr: int|None = None) -> Wrapper|None:
    tif = tif.copy()
    size = tif.get_size()
    if tif.is_array():
        tif.remove_ptr_or_array()
        elem_size = tif.get_size()
        tif.clr_const()
        tif.clr_volatile()
        if tif.get_type_name() in ["char", "wchar_t"] or tif.is_char():
            return StringWrapper(size//elem_size if size > 0 else None, tif.get_type_name(), addr)
        assert size % elem_size == 0, (size, elem_size)
        return ArrayWrapper(ida2py(tif, addr), size//elem_size)
    elif tif.is_ptr_or_array():
        tif.remove_ptr_or_array()
        tif.clr_const()
        tif.clr_volatile()
        return PointerWrapper(tif.get_type_name() in ["char", "wchar_t"] or tif.is_char(), tif, addr)
    
    if tif.is_struct():
        return StructWrapper(tif, address=addr)

    if tif.is_integral():
        signed = tif.is_signed()
        size = tif.get_size()
        return IntWrapper(signed, size * 8, get_byteorder(), address=addr)
    
    if tif.is_func():
        func = idaapi.get_func(addr)
        return FunctionWrapper(tif, func, addr)
    
    if tif.is_typedef():
        typename = tif.get_final_type_name()
        tif2 = ida_typeinf.tinfo_t()
        ida_typeinf.parse_decl(tif2, None, f"{typename};", ida_typeinf.PT_SIL)
        return ida2py(tif2, addr)
    
    return UnknownWrapper(addr)

class TypeConstructor:
    tinfo: ida_typeinf.tinfo_t
    wrapper_type: Wrapper

    def __init__(self, tinfo: ida_typeinf.tinfo_t):
        self.tinfo = tinfo
        self.wrapper_type = ida2py(tinfo)

    def ptr(self) -> "TypeConstructor":
        new_tinfo = ida_typeinf.tinfo_t()
        new_tinfo.create_ptr(self.tinfo)
        return TypeConstructor(new_tinfo)
    
    def __mul__(self, length: int) -> "TypeConstructor":
        if not isinstance(length, int):
            raise TypeError("Array length must be an integer")
        if length <= 0:
            raise ValueError("Cannot multiply type by non-positive length")
        new_tinfo = ida_typeinf.tinfo_t()
        new_tinfo.create_array(self.tinfo, length)
        return TypeConstructor(new_tinfo)
        
    def __call__(self, addr: int|None=None) -> Wrapper|None:
        if addr is None:
            addr = idc.here()
        return ida2py(self.tinfo, addr)
    
    def __matmul__(self, addr: int) -> Wrapper|None:
        if addr is None:
            raise ValueError("Address cannot be None when using @ operator")
        return self.__call__(addr)
    
    def __repr__(self):
        return self.wrapper_type.type_name()


def _ida(key):
    if type(key) is int:
        addr = key
    else:
        addr = idc.get_name_ea_simple(key)
        if addr == idc.BADADDR:
            tinfo = ida_typeinf.tinfo_t()
            result = ida_typeinf.parse_decl(tinfo, None, f"{key} x;", ida_typeinf.PT_SIL)
            if result is not None:
                return TypeConstructor(tinfo)
            if key.startswith("u"):
                result = ida_typeinf.parse_decl(tinfo, None, f"unsigned {key[1:]} x;", ida_typeinf.PT_SIL)
                if result is not None:
                    return TypeConstructor(tinfo)
            raise NameError(f"name '{key}' is not defined")
    tinfo = get_type_at_address(addr)
    if tinfo is not None:
        ret = ida2py(tinfo, addr)
        if ret is not None:
            return ret
    return UnknownWrapper(addr)

# In case global hooking doesn't work
def hook(g):
    obase = py_object.from_address(id(g) + 8)
    class fglobals(dict):
        __slots__ = ()
        def __getitem__(self, key, dict=dict, obase=obase):
            try:
                obase.value = dict
                if key == "_ida":
                    return _ida
                if key in self:
                    return self[key]
                if hasattr(builtins, key):
                    return getattr(builtins, key)
                return _ida(key)
            
            finally:
                obase.value = __class__

    obase.value = fglobals


if __name__.startswith("__plugins__"):
    obase = py_object.from_address(id(__main__.__dict__) + 8)
    class fglobals(dict):
        __slots__ = ()
        def __getitem__(self, key, dict=dict, obase=obase):
            try:
                obase.value = dict
                if key == "_ida":
                    return _ida
                if key in self:
                    return self[key]
                if hasattr(builtins, key):
                    return getattr(builtins, key)
                return _ida(key)
            
            finally:
                obase.value = __class__

    obase.value = fglobals
