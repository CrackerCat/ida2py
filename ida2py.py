import __main__

from ctypes import *
import builtins
import functools
import inspect

import idc
import ida_typeinf
import ida_bytes
import idaapi
import ida_nalt
import ida_funcs
import ida_idp
import idautils
import ida_hexrays

import typing
from copy import copy


state = None

class context:
    print_style = 'dec'
    auto_deref = False
    indent_width = 2
    max_line_width = 80
    max_display_count = 16
    executor: typing.Optional["Executor"] = None

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

def auto_indent(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        depth = kwargs.get('depth', 0)
        result = str(func(*args, **kwargs))
        indent = ' ' * depth
        return indent + result.replace('\n', '\n' + indent)
    wrapper.__signature__ = inspect.signature(func)
    return wrapper

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
    
    @auto_indent
    def array_repr(self, depth=0):
        raise NotImplementedError()
    
    def _addr_repr(self):
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
    
    def __dir__(self):
        # Make private properties actually "private"
        prefixes = []
        s = self.__class__
        while s != object:
            prefixes.append(f"_{s.__name__}__")
            s = s.__base__
        hide_names = ["_addr_repr", "_get_value", "_value"]
        return [name for name in super().__dir__() if not (any(name.startswith(prefix) for prefix in prefixes) or name in hide_names)]

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
            return int.from_bytes(idc.get_bytes(int(self.address), self.bits//8), self.byte_order, signed=self.signed)
        except TypeError:
            return Invalid
    
    def type_name(self):
        return f"{'' if self.signed else 'U'}Int{self.bits}"
    
    @auto_indent
    def array_repr(self, depth=0):
        if context.print_style == 'dec':
            return str(self.value)
        else:
            return hex(self.value)
    
    def __repr__(self):
        if self.address is None and self._value is None:
            return self.type_name()
        return f"{self.type_name()}({self.array_repr()})" + self._addr_repr()
    
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
    __t: Wrapper
    __length: int

    def __init__(self, t: Wrapper, length):
        self.__t = t
        self.__length = length
        self.address = t.address

    def __getitem__(self, index):
        if isinstance(index, slice):
            return self.value.__getitem__(index)
        if index < 0:
            index += self.__length
        if index >= self.__length:
            raise IndexError(f"Array index {index} out of range for array of size {self.__length}")
        if index < 0:
            raise IndexError(f"Array index {index} cannot be negative")
        elem = copy(self.__t)
        elem._value = None
        elem.address = self.address + index * elem.__sizeof__()
        return elem
    
    def __len__(self):
        return self.__length
    
    def __iter__(self):
        for i in range(self.__length):
            yield self[i]
    
    def _get_value(self):
        out = []
        for i in range(self.__length):
            out.append(self[i])
        return out

    def __sizeof__(self):
        return self.__t.__sizeof__() * self.__length
    
    def type_name(self):
        return self.__t.type_name() + f"[{self.__length}]"
    
    @auto_indent
    def array_repr(self, depth=0):
        if self.address is None:
            return ""
        if self.__length > context.max_display_count:
            if self.value:
                items = self.value[:context.max_display_count]
            else:
                items = [self[i] for i in range(context.max_display_count)]
        else:
            items = self.value
        if len(items) == 0:
            return "{}"
        parts = [x.array_repr(depth=depth+1) for x in items]
        multiline = parts[0].count("\n") > 0
        line_width = sum(len(part.strip()) + 2 for part in parts)
        if multiline or line_width > context.max_line_width:
            inner = "\n" + ",\n".join(parts) + (", ..." if self.__length > context.max_display_count else '') + "\n"
        else:
            inner = ", ".join(part.strip() for part in parts) + (", ..." if self.__length > context.max_display_count else '')
        return "{" + inner + "}"
    
    def __bytes__(self):
        out = b""
        for v in self.value:
            out += bytes(v)
        return out
    
    def __copy__(self) -> "Wrapper":
        return ArrayWrapper(self.__t, self.__length)
    
    def __repr__(self) -> str:
        return self.type_name() + self.array_repr() + self._addr_repr()


class StringWrapper(Wrapper):
    __length: int
    __str_type: str
    def __init__(self, length, str_type, address):
        self.__length = length
        self.address = address
        if str_type is None:
            str_type = "char"
        self.__str_type = str_type
    
    def __getitem__(self, index):
        return self.value.__getitem__(index)
    
    def __len__(self):
        if self.__length:
            return self.__length
        return len(self.value)
    
    def __iter__(self):
        return self.value.__iter__()
    
    def __repr__(self):
        ret = self.array_repr()
        if self.__str_type == 'wchar_t':
            ret = "L"+ret[1:]
        return ret + self._addr_repr()
    
    def __str__(self):
        return repr(self)
    
    def _get_value(self):
        res = idc.get_strlit_contents(self.address, strtype=ida_nalt.STRTYPE_C_16 if self.__str_type == "wchar_t" else ida_nalt.STRTYPE_C)
        if res:
            return res
        try:
            return idc.get_bytes(self.address, self.__length)
        except TypeError:
            raise ValueError(f"Could not get bytes at {hex(self.address)}")
       
    def type_name(self):
        if self.__length is None:
            return f"{self.__str_type}[]"
        return f"{self.__str_type}[{self.__length}]"
    
    @auto_indent
    def array_repr(self, depth=0):
        if self.__length is not None and self.__length > 256:
            return bytes.__str__(idc.get_bytes(self.address, 256)) + f" and {self.__length - 256} more bytes"
        return bytes.__str__(self.value)
    
    def __bytes__(self) -> bytes:
        return self.value
    
    def __sizeof__(self) -> int:
        return len(self) * (2 if self.__str_type == "wchar_t" else 1)
    
    def __copy__(self) -> "Wrapper":
        return StringWrapper(self.__length, self.__str_type, self.address)


class PointerWrapper(Wrapper):
    tinfo_hint: ida_typeinf.tinfo_t
    def __init__(self, is_string, tinfo_hint, address):
        self.address = address
        self.__is_string = is_string
        self.tinfo_hint = tinfo_hint
    
    def _get_value(self):
        pointed_addr = read_pointer(self.address)
        if pointed_addr is Invalid:
            return pointed_addr
        if pointed_addr == 0:
            return None
        return self.__deref_at_address(pointed_addr, True)
    

    def __deref_at_address(self, pointed_addr, get_whole=False):
        if self.__is_string and get_whole:
            tinfo = ida_typeinf.tinfo_t()
            ida_typeinf.parse_decl(tinfo, None, f"char[];", ida_typeinf.PT_SIL)
        else:
            tinfo = None
            if self.tinfo_hint is None:
                tinfo = get_type_at_address(pointed_addr)
            if tinfo is None:
                tinfo = self.tinfo_hint
            
        if tinfo is None:
            print(f"Failed to get type at {hex(pointed_addr)}")
            return UnknownWrapper(pointed_addr)
        return ida2py(tinfo, pointed_addr)
       
    def type_name(self):
        if self.address is None:
            if self.tinfo_hint is None:
                return "Unknown*"
            new_tinfo = ida_typeinf.tinfo_t()
            new_tinfo.create_ptr(self.tinfo_hint)
            return new_tinfo.dstr()
        if self.__is_string:
            return self.value.type_name()
        return f"{self.value.type_name()}*"
    
    @auto_indent
    def array_repr(self, depth=0):
        if read_pointer(self.address) == 0:
            return "NULL"
        # Strings and functions within structs/arrays can be understood to be pointers
        if self.__is_string or (self.tinfo_hint and self.tinfo_hint.is_func()):
            # Do not increase depth for pointers
            return self.value.array_repr(depth=depth)
        if read_pointer(self.address) is Invalid:
            return "Invalid"
        if context.auto_deref:
            return self.value.array_repr(depth=depth).strip()
        return "{" + self.type_name() + "} " + hex(read_pointer(self.address))

    def __repr__(self):
        if self.value is Invalid:
            return f"Pointer to Invalid"
        if self.value is None:
            return "NULL"
        return f"Pointer to ({self.value})" + self._addr_repr()
    
    def __bytes__(self) -> bytes:
        return int.to_bytes(read_pointer(self.address), get_address_size(), get_byteorder())
    
    def __sizeof__(self) -> int:
        return get_address_size()
    
    def __copy__(self) -> "Wrapper":
        return PointerWrapper(self.__is_string, self.tinfo_hint, self.address)
    
    def __getitem__(self, index):
        if index == 0 and self.address is None:
            return self.value
        if isinstance(index, slice):
            if index.stop is None:
                raise ValueError("Slice must have an end index")
            start, stop, stride = index.indices(index.stop)
            out = []
            for i in range(start, stop, stride):
                out.append(self[i])
            if self.__is_string:
                return bytes(out)
            return out
        pointed_addr = read_pointer(self.address)
        if pointed_addr is Invalid:
            return pointed_addr
        if self.tinfo_hint is not None:
            tif = self.tinfo_hint
            if tif.is_array() and tif.get_size() == 0:
                tif.remove_ptr_or_array()
            elem_size = tif.get_size()
        else:
            elem_size = self.value.__sizeof__()
        pointed_addr += index * elem_size
        return self.__deref_at_address(pointed_addr)
    
    def __call__(self, val):
        assert self.address is None
        t = copy(self)
        t.address = None
        if isinstance(val, Wrapper):
            t.address = val
            return t
    
    def __getattr__(self, key):
        try:
            return object.__getattribute__(self, key)
        except AttributeError:
            if isinstance(self.value, StructWrapper):
                return self.value.__getattr__(key)
            raise AttributeError(f"PointerWrapper object has no attribute {key}")
        
    def __dir__(self):
        if isinstance(self.value, StructWrapper):
            return self.value.__dir__()
        return super().__dir__()


class StructWrapper(Wrapper):
    __tif: ida_typeinf.tinfo_t
    __name: str
    __members: dict[str, Wrapper]
    def __init__(self, tif: ida_typeinf.tinfo_t, address):
        self.__tif = tif
        self.__name = tif.get_type_name()
        self.__members = {}
        udt = ida_typeinf.udt_type_data_t()
        self.address = address
        if tif.get_udt_details(udt):
            for udm in udt:
                udm_type: ida_typeinf.tinfo_t = ida_typeinf.tinfo_t(udm.type)
                offset = udm.offset//8
                res = ida2py(udm_type, None)
                self.__members[udm.name] = (offset, res)
    
    def _get_value(self):
        assert self.address is not None
        out = {}
        for key in self.__members:
            offset, t = self.__members[key]
            t = copy(t)
            t._value = None
            t.address = self.address + offset
            out[key] = (offset, t)
        return out
       
    def type_name(self):
        return "struct "+self.__name
    
    @auto_indent
    def array_repr(self, depth=0, force_multiline=False):
        parts = []
        members = sorted(self.value.items(), key=lambda k: k[1][0])
        for name, (offset, type) in members:
            parts.append(f"{name} = {type.array_repr(depth=depth+1).strip()}")
        line_width = sum(len(part) + 2 for part in parts) + 2
        if line_width > context.max_line_width or force_multiline:
            return "{\n" + ",\n".join(" " * context.indent_width + part for part in parts) + "\n}"
        return "{" + ", ".join(parts) + "}"

    def __repr__(self):
        return self.type_name() + " " + self.array_repr(force_multiline=True) + self._addr_repr()
    
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
        return self.__tif.get_size()
    
    def __copy__(self) -> "Wrapper":
        return StructWrapper(self.__tif, self.address)
    
    def __getattr__(self, key):
        if key in self.value:
            offset, t = self.value[key]
            if self.address is None:
                return t
            if t.address is None:
                t = copy(t)
                t.address = self.address + offset
            return t
        raise AttributeError(f"struct '{self.__name}' has no member {key}")
    
    def __dir__(self):
        return super().__dir__() + list(self.__members.keys())

class FunctionWrapper(Wrapper):
    __tif: ida_typeinf.tinfo_t
    __func: ida_funcs.func_t
    __func_data: ida_typeinf.func_type_data_t
    def __init__(self, tif, func, address):
        assert tif.is_func(), f"{tif} is not a function type"
        if idc.get_segm_attr(address, idc.SEGATTR_TYPE) == 1:
            # extern
            ea = next(idautils.CodeRefsTo(address, 0), None)
            func = ida_funcs.get_func(ea)
            if func is not None:
                address = next(func.addresses())
        self.__tif = tif
        self.__func = func
        self.__func_data = ida_typeinf.func_type_data_t()
        assert tif.get_func_details(self.__func_data)
        self.address = address
    
    @property
    def name(self):
        return idc.get_name(self.__func.start_ea)
    
    @property
    def offset_str(self):
        return (f' + {hex(self.address - self.__func.start_ea)}' if self.address != self.__func.start_ea else '')

    def _get_value(self):
        return f"Function {self.name} at {hex(self.address)}"
       
    def type_name(self):
        return ida_typeinf.print_tinfo("", 0, 0, 0, self.__tif, self.name, "")
    
    @auto_indent
    def array_repr(self, depth=0):
        if self.offset_str:
            return self.name + self.offset_str
        return self.name

    def __repr__(self):
        return self.type_name() + self.offset_str + self._addr_repr()
    
    def __bytes__(self) -> bytes:
        raise NotImplementedError("Cannot convert function to bytes")

    def __sizeof__(self) -> int:
        return self.__func.size()
    
    def __copy__(self) -> "Wrapper":
        return FunctionWrapper(self.__tif, self.__func, self.address)
    
    @staticmethod 
    def argloc_to_simarg(argloc, type):
        import angr
        size = type.get_size()
        if size == idc.BADADDR:
            return
        if not argloc.is_fragmented():
            if argloc.is_reg1():
                return angr.calling_conventions.SimRegArg(
                    ida_idp.get_reg_name(argloc.reg1(), size),
                    size,
                    reg_offset=argloc.regoff()
                )
            elif argloc.in_stack():
                return angr.calling_conventions.SimRegArg(argloc.stkoff(), size)
        raise NotImplementedError("Cannot convert to simarg")
    
    @functools.cached_property
    def cc(self):
        assert context.executor is not None, "Cannot call function without executor"
        import angr


        class UsercallArgSession:
            """
            An argsession for use with SimCCUsercall
            """

            __slots__ = (
                "cc",
                "real_args",
            )

            def __init__(self, cc):
                self.cc = cc
                # The acutual UsercallArgSession has a bug here
                self.real_args = angr.calling_conventions.SerializableListIterator(self.cc.args)

            def getstate(self):
                return self.real_args.getstate()

            def setstate(self, state):
                self.real_args.setstate(state)

        class SimCCUsercall(angr.calling_conventions.SimCC):
            def __init__(self, arch, args, ret_loc):
                super().__init__(arch)
                self.args = args
                self.ret_loc = ret_loc

            ArgSession = UsercallArgSession

            def next_arg(self, session, arg_type):
                return next(session.real_args)

            def return_val(self, ty, **kwargs):
                return self.ret_loc
            
        proj: angr.Project = context.executor.proj
        return SimCCUsercall(
            arch=proj.arch,
            args=[FunctionWrapper.argloc_to_simarg(arg.argloc, arg.type) for arg in self.__func_data],
            ret_loc=FunctionWrapper.argloc_to_simarg(self.__func_data.retloc, self.__func_data.rettype)
        )
    
    def __call__(self, *args):
        assert context.executor is not None, "Cannot call function without executor"
        import angr
        import claripy
        proj: angr.Project = context.executor.proj
        state: angr.SimState = context.executor.state
        def convert_for_angr(val):
            if isinstance(val, AngrPointer):
                return val.pointed_address
            if isinstance(val, StringWrapper) or isinstance(val, IntWrapper):
                val = val.pyval()
            elif isinstance(val, str):
                val = val.encode()
            if isinstance(val, bytes):
                return context.executor.buf(val).pointed_address
            return val
        args = [convert_for_angr(x) for x in args]
        addr = self.address
        if addr < proj.loader.main_object.min_addr:
            addr += proj.loader.main_object.min_addr
        func = proj.factory.callable(addr, base_state=state, concrete_only=True)
        if not self.__func_data.is_vararg_cc():
            if len(self.cc.args) != len(args):
                raise ValueError(f"Function should be called with {len(self.cc.args)} arguments, but {len(args)} provided")
            # potentially support usercall, unless is vararg
            self.cc.RETURN_ADDR = func._cc.return_addr
            func = proj.factory.callable(addr, base_state=state, concrete_only=True, cc=self.cc)
            args = [claripy.BVV(arg, simarg.size * 8) for arg, simarg in zip(args, self.cc.args)]
        result = func(*args)
        stdout = func.result_state.posix.dumps(1)
        # Clean up stdout
        func.result_state.posix.stdout.content = []
        func.result_state.posix.stdout.pos = 0
        context.executor.state = func.result_state
        try:
            print(stdout.decode(),end="")
        except UnicodeDecodeError:
            print(stdout)
        if not self.__func.does_return():
            print(f"Function does not return")
            return UnknownWrapper(None)
        if self.__func_data.rettype.is_void():
            return
        rettype = ida2py(self.__func_data.rettype)
        if rettype is None:
            print(f"Could not determine return type. Raw value is {result}")
            return UnknownWrapper(None)
        if not result.concrete:
            print(f"Return value '{result}' is not concrete")
            return UnknownWrapper(None)
        if isinstance(rettype, PointerWrapper):
            pointed_type = ida2py(rettype.tinfo_hint)
            if pointed_type is None or isinstance(pointed_type, UnknownWrapper):
                pointed_type = IntWrapper(signed=False, bits=8)
            return AngrPointer(result.concrete_value, pointed_type)
        else:
            rettype._value = result.concrete_value
        return rettype

class AngrPointer:
    def __init__(self, pointed_address: int, type: Wrapper):
        self.pointed_address = pointed_address
        self.type = type

    def _get_mem_info(self, idx):
        addr = self.pointed_address + idx * self.type.__sizeof__()
        signed = isinstance(self.type, IntWrapper) and self.type.signed
        bits = (isinstance(self.type, IntWrapper) and self.type.bits) or get_address_size()*8
        type_str = f"{'' if signed else 'u'}int{bits}_t"
        return addr, type_str

    def __getitem__(self, idx: int|slice) -> int|list:
        mem = context.executor.state.mem
        if isinstance(idx, slice):
            if idx.stop is None:
                raise ValueError("Slice must have an end index")
            start, stop, stride = idx.indices(idx.stop)
            out = []
            for i in range(start, stop, stride):
                out.append(self[i])
            return out
        addr, type_str = self._get_mem_info(idx)
        return getattr(mem[addr], type_str).concrete
    
    def __setitem__(self, idx: int|slice, val: int|list):
        mem = context.executor.state.mem
        if isinstance(idx, slice):
            if idx.stop is None:
                raise ValueError("Slice must have an end index")
            start, stop, stride = idx.indices(idx.stop)
            if not isinstance(val, (list, tuple)):
                raise TypeError("Can only assign an iterable to slice")
            val = list(val)  # Convert to list to check length
            if len(val) != len(range(start, stop, stride)):
                raise ValueError("Iterable length does not match slice length")
            for i, v in zip(range(start, stop, stride), val):
                self[i] = v
            return
        addr, type_str = self._get_mem_info(idx)
        setattr(mem[addr], type_str, val)

    def bytes(self, n=None):
        if n is None:
            try:
                return context.executor.state.mem[self.pointed_address].string.concrete
            except ValueError:
                return b""
        return bytes(context.executor.state.mem[self.pointed_address].byte.array(n).concrete)
    
    def set_bytes(self, b):
        for i, x in enumerate(b):
            context.executor.state.mem[self.pointed_address + i].byte = x
    
    def __repr__(self):
        return f"Pointer to {self.type.type_name()} @ Angr[{hex(self.pointed_address)}]"

class Executor:
    def __init__(self, proj, state):
        self.proj = proj
        self.state = state
        self.old = None

    def malloc(self, size: int) -> AngrPointer:
        result = self.state.heap.allocate(size)
        pointed_type = IntWrapper(signed=False, bits=8)
        return AngrPointer(result, pointed_type)
    
    def buf(self, b: bytes):
        buf = self.malloc(len(b))
        buf.set_bytes(b)
        return buf
    
    def __enter__(self):
        self.old = context.executor
        context.executor = self
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        context.executor = self.old


def angr_exec(filepath=None, proj=None, state=None):
    print("Initializing angr...")
    import angr
    import logging
    logging.getLogger('angr').setLevel("WARNING")
    
    if proj is None:
        proj = angr.Project(filepath or idaapi.get_input_file_path(), auto_load_libs=False)

    if state is None:
        state = proj.factory.blank_state(add_options=(
            {
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            } | angr.options.unicorn
        ))
    print("Angr initialized successfully")
    return Executor(proj, state)

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
        return "Unknown" + self._addr_repr()
    
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
    tinfo = ida_typeinf.tinfo_t()
    if ida_nalt.get_tinfo(tinfo, ea):
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
        # Decompile function to get latest type information
        ida_hexrays.decompile(addr, flags=ida_hexrays.DECOMP_WARNINGS)
        tif = get_type_at_address(addr)
        return FunctionWrapper(tif, func, addr)
    
    if hasattr(tif, "is_typedef") and tif.is_typedef():
        typename = tif.get_final_type_name()
        tif2 = ida_typeinf.tinfo_t()
        ida_typeinf.parse_decl(tif2, None, f"{typename};", ida_typeinf.PT_SIL)
        return ida2py(tif2, addr)
    
    return UnknownWrapper(addr)

class TypeConstructor:
    __tinfo: ida_typeinf.tinfo_t
    __wrapper_type: Wrapper

    def __init__(self, tinfo: ida_typeinf.tinfo_t):
        self.__tinfo = tinfo
        self.__wrapper_type = ida2py(tinfo)

    def ptr(self) -> "TypeConstructor":
        new_tinfo = ida_typeinf.tinfo_t()
        new_tinfo.create_ptr(self.__tinfo)
        return TypeConstructor(new_tinfo)
    
    def __mul__(self, length: int) -> "TypeConstructor":
        if not isinstance(length, int):
            raise TypeError("Array length must be an integer")
        if length <= 0:
            raise ValueError("Cannot multiply type by non-positive length")
        new_tinfo = ida_typeinf.tinfo_t()
        new_tinfo.create_array(self.__tinfo, length)
        return TypeConstructor(new_tinfo)
        
    def __call__(self, addr: int|None=None) -> Wrapper|None:
        if addr is None:
            addr = idc.here()
        return ida2py(self.__tinfo, addr)
    
    def __matmul__(self, addr: int) -> Wrapper|None:
        if addr is None:
            raise ValueError("Address cannot be None when using @ operator")
        return self.__call__(addr)
    
    def __repr__(self):
        return self.__wrapper_type.type_name()

class SearchResult(str):
    value: int
    accesses: int
    address: int
    tif: ida_typeinf.tinfo_t

    def __new__(cls, name, address=None, tif=None, accesses=0):
        instance = super().__new__(cls, name)
        instance.accesses = accesses
        # Deprioritize names with leading underscores
        instance.__base_value = -(len(name) - len(name.lstrip("_")))
        # We probably don't care about stuff in the loader segment?
        if idaapi.getseg(address).is_header_segm():
            instance.__base_value -= 1
        instance.address = address
        instance.tif = tif
        return instance
    
    # Higher, the better
    @property
    def value(self):
        # Prioritize names with more accesses
        return self.__base_value + self.accesses

    def __lt__(self, other):
        if not isinstance(other, SearchResult) or self.value == other.value:
            return str(self) < str(other)
        return self.value > other.value

class Ida2py:
    __names: dict[str, SearchResult] = {}
    def __dir__(self):
        results = []
        for address, name in idautils.Names():
            if not ida_bytes.has_user_name(ida_bytes.get_flags(address)):
                continue
            if any(not (c.isalnum() or c == "_") for c in name):
                continue

            tinfo = get_type_at_address(address)
            if tinfo is not None:
                res = SearchResult(name, address, tinfo)
                if name in self.__names:
                    res.accesses = self.__names[name].accesses
                results.append(res)
                self.__names[name] = res
        return results
    
    def __getattr__(self, name):
        caller_name = inspect.currentframe().f_back.f_code.co_name
        if name not in self.__names:
            raise AttributeError(f"name '{name}' is not defined")
        
        # These functions are used in IDA's autocomplete
        if caller_name not in ["build_hints", "maybe_extend_syntactically"]:
            # Return the real value when we actually access it
            self.__names[name].accesses += 1
            return ida2py(self.__names[name].tif, self.__names[name].address)
        else:
            # Return a fake object with the correct type name
            X = type('X', (object,), {})
            X.__name__ = self.__names[name].tif.dstr()
            return X()
        
    def __call__(self, key):
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
                if key in self:
                    return self[key]
                if hasattr(builtins, key):
                    return getattr(builtins, key)
                return _ida(key)
            finally:
                obase.value = __class__
    obase.value = fglobals
    g["_ida"] = _ida
    g["angr_exec"] = angr_exec

_ida = Ida2py()

if __name__.startswith("__plugins__"):
    obase = py_object.from_address(id(__main__.__dict__) + 8)
    class fglobals(dict):
        __slots__ = ()
        def __getitem__(self, key, dict=dict, obase=obase):
            try:
                obase.value = dict
                if key in self:
                    return self[key]
                if hasattr(builtins, key):
                    return getattr(builtins, key)
                return _ida(key)
            finally:
                obase.value = __class__

    obase.value = fglobals
    __main__.__dict__["_ida"] = _ida
    __main__.__dict__["angr_exec"] = angr_exec
