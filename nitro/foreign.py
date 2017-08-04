import struct
import logging
from collections import OrderedDict

# TODO:
# - Turn Field into a base class and make ForeignObject inherit from it and create something like SimpleField for format-based fields
# - Automatic offsets
# - Generate ForeignObjects definitions from header files

class Field:
    """Class representing an individual member of an foreign object"""

    def __init__(self, format, offset, default):
        self.format = format
        self.offset = offset
        self.default = default
    
    def __repr__(self):
        return "<Field format='{}' offset=0x{:x}>".format(self.format, self.offset)


class ForeignObjectMeta(type):

    @classmethod
    def __prepare__(cls, *args, **kwargs):
        return OrderedDict()

    def __new__(cls, name, bases, namespace, **kwargs):
        fields = OrderedDict()
        namespace_ = {}
        for name_, value in namespace.items():
            if isinstance(value, Field):
                fields[name_] = value
            else:
                namespace_[name_] = value
        namespace_["_fields"] = fields
        class_ = super().__new__(cls, name, bases, namespace_)
        return class_


class ForeignObject(metaclass=ForeignObjectMeta):
    """Base class for foreign objects loaded from memory"""

    _modified = set()
    _values = {}
    _process = None
    _address = None

    def __init__(self, **kwargs):
        for name, field in self._fields.items():
            self.__set_field_raw(name, kwargs.get(name, field.default))

    def __setattr__(self, name, value):
        if name in self._fields:
            self.__set_field_raw(name, value)
            self._modified.add(name)
        else:
            super().__setattr__(name, value)
    
    def __set_field_raw(self, name, value):
        """Set field without marking it as modified"""
        self._values[name] = value
        

    def __getattr__(self, name):
        if name in self._fields:
            return self._values[name]
        else:
            raise AttributeError("{!r} object has no attribute {!r}".format(self.__class__, name))
    
    def create(self, process, addr):
        """Writes the object into VM memory"""
        self._process = process
        self._address = addr
        self._modified.update(self._fields.keys())
        self.update()
    
    def update(self):
        """Commits changes into VM memory"""
        logging.debug("Saving %s for %s at %s (pid %d)",
                      ", ".join(self._modified),
                      type(self).__name__,
                      hex(self._address),
                      self._process.pid)
        for name in self._modified:
            field = self._fields[name]
            bytes_ = struct.pack(field.format, self._values[name])
            logging.debug("address: %s; offset: %d, bytes: %r", hex(self._address), field.offset, bytes_)
            self._process.write_memory(self._address + field.offset, bytes_)
        self._modified.clear()
    
    @classmethod
    def get(cls, process, addr):
        """Retrieves an object from VM memory"""
        instance = cls()
        for name, field in cls._fields.items():
            size = struct.calcsize(field.format)
            content = process.read_memory(addr + field.offset, size)
            value, *rest = struct.unpack(field.format, content)
            instance.__set_field_raw(name, value)
        instance._process = process
        instance._address = addr
        return instance

    @property
    def fresh(self):
        return self._address is None and self._process is None

    def items(self):
        return self._values.items()

    def __repr__(self):
        if not self.fresh:
            prop_str = "address=0x{:x} pid={} modified={}".format(self._address, self._process.pid, bool(self._modified))
        else:
            prop_str = "fresh"
        return "<{} {}>" \
            .format(type(self).__name__, prop_str)


