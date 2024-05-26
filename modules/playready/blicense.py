import struct

MAGIC_XMR = 0x584d5200
ATTR_HDR_SIZE = 8

# tag values
TAG_OuterContainer = 0x0001
TAG_PlaybackContainer = 0x0004
TAG_GlobalContainer = 0x0002
TAG_DWORD_Versioned = 0x0032
TAG_SecurityLevel = 0x0034
TAG_WORD = 0x0033
TAG_KeyMaterialContainer = 0x0009
TAG_ContentKey = 0x000a
TAG_ECCDeviceKey = 0x002a
TAG_Signature = 0x000b
TAG_ROOT_CONTAINER = 0x7fff

def tag_name(tag):
    return {
        TAG_OuterContainer: "OuterContainer",
        TAG_PlaybackContainer: "PlaybackContainer",
        TAG_GlobalContainer: "GlobalContainer",
        TAG_DWORD_Versioned: "DWORD_Versioned",
        TAG_SecurityLevel: "SecurityLevel",
        TAG_WORD: "WORD",
        TAG_KeyMaterialContainer: "KeyMaterialContainer",
        TAG_ContentKey: "ContentKey",
        TAG_ECCDeviceKey: "ECCDeviceKey",
        TAG_Signature: "Signature"
    }.get(tag, "Unknown")

def read_attributes(data):
    attributes = []
    bi = ByteInput(data)
    len_data = len(data)

    while len_data > 0:
        bi.skip(2)
        tag = bi.peek_2()
        bi.skip(-2)
        attr = Attr(bi)
        attributes.append(attr)
        len_data -= attr.len() + ATTR_HDR_SIZE

    return attributes

class ByteInput:
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def read_2(self):
        val = struct.unpack_from('>H', self.data, self.offset)[0]
        self.offset += 2
        return val

    def read_4(self):
        val = struct.unpack_from('>I', self.data, self.offset)[0]
        self.offset += 4
        return val

    def read_n(self, n):
        val = self.data[self.offset:self.offset + n]
        self.offset += n
        return val

    def skip(self, n):
        self.offset += n

    def peek_2(self):
        return struct.unpack_from('>H', self.data, self.offset)[0]

    def remaining_data(self):
        return self.data[self.offset:]

class Attr:
    def __init__(self, bi):
        self.lvl = bi.read_2()
        self.tag = bi.read_2()
        self.len = bi.read_4()
        self.data = bi.read_n(self.len - 8)
        self.name = tag_name(self.tag)

    def __init__(self, len, tag, data):
        self.len = len
        self.tag = tag
        self.data = data
        self.name = tag_name(self.tag)

    def name(self):
        return self.name

    def lvl(self):
        return self.lvl

    def tag(self):
        return self.tag

    def len(self):
        return self.len

    def data(self):
        return self.data

    @staticmethod
    def parse(attr):
        if attr.tag in [TAG_OuterContainer, TAG_PlaybackContainer, TAG_GlobalContainer, TAG_KeyMaterialContainer]:
            return ContainerAttr.get(attr.tag, attr.data)
        elif attr.tag == TAG_SecurityLevel:
            return SecurityLevel.get(attr.data)
        elif attr.tag == TAG_ContentKey:
            return ContentKey.get(attr.data)
        return attr

    def print(self):
        pp = Shell.get_pp()
        pp.println(f"attr: {Utils.hex_value(self.tag, 4)} {self.name}")
        if self.data:
            pp.printhex("data", self.data)

class SecurityLevel(Attr):
    def __init__(self, len, tag, data):
        super().__init__(len, tag, data)
        bi = ByteInput(data)
        self.security_level = bi.read_2()

    @staticmethod
    def get(data):
        return SecurityLevel(len(data), TAG_SecurityLevel, data)

    def print(self):
        pp = Shell.get_pp()
        pp.println("SecurityLevel")
        pp.pad(2, "")
        pp.println(f"level: {MSPR.SL2string(self.security_level)}")
        pp.leave()

class ContentKey(Attr):
    def __init__(self, len, tag, data):
        super().__init__(len, tag, data)
        bi = ByteInput(data)
        self.key_id = bi.read_n(0x10)
        self.v1 = bi.read_2()
        self.v2 = bi.read_2()
        self.enc_data_len = bi.read_2()
        self.enc_data = bi.read_n(self.enc_data_len)

    def key_id(self):
        return self.key_id

    def enc_data(self):
        return self.enc_data

    @staticmethod
    def get(data):
        return ContentKey(len(data), TAG_ContentKey, data)

    def print(self):
        pp = Shell.get_pp()
        pp.println("ContentKey")
        pp.pad(2, "")
        pp.printhex("key_id", self.key_id)
        pp.println(f"v1:           {self.v1}")
        pp.println(f"v2:           {self.v2}")
        pp.println(f"enc_data_len: {Utils.hex_value(self.enc_data_len, 4)}")
        pp.printhex("enc_data", self.enc_data)
        pp.leave()

class ContainerAttr(Attr):
    def __init__(self, len, tag, data, attributes=None):
        super().__init__(len, tag, data)
        self.attributes = attributes if attributes else []

    def cnt(self):
        return len(self.attributes)

    def get(self, i):
        if i < self.cnt():
            return self.attributes[i]
        return None

    def add_attr(self, a):
        self.attributes.append(a)

    def lookup_attr_by_name(self, name):
        for attr in self.attributes:
            if attr.name() == name:
                return attr
        return None

    @staticmethod
    def read_attr(data):
        return read_attributes(data)[0]

    @staticmethod
    def get(tag, data):
        attributes = read_attributes(data)
        if attributes:
            if len(attributes) == 1 and tag != TAG_ROOT_CONTAINER:
                return Attr.parse(attributes[0])
            else:
                new_attributes = []
                container = ContainerAttr(len(data), tag, data, new_attributes)
                for attr in attributes:
                    new_attr = Attr.parse(attr)
                    new_attributes.append(new_attr)
                return container
        return None

    def print(self):
        pp = Shell.get_pp()
        if self.tag != TAG_ROOT_CONTAINER:
            pp.println(f"attr: {Utils.hex_value(self.tag, 4)} {self.name}")
        pp.pad(2, "")
        for attr in self.attributes:
            attr.print()
        pp.leave()

class BLicense:
    def __init__(self, data):
        self.data = data
        bi = ByteInput(data)
        magic = bi.read_4()
        if magic == MAGIC_XMR:
            self.version = bi.read_4()
            self.unknown_data = bi.read_n(0x10)
            self.root = ContainerAttr.get(TAG_ROOT_CONTAINER, bi.remaining_data())

    @staticmethod
    def tokenize_path(path):
        return path.split(".")

    def get_attr(self, attrpath):
        path_elem = self.tokenize_path(attrpath)
        curpos = self.root
        res = None
        for elem in path_elem:
            if isinstance(curpos, ContainerAttr):
                res = curpos.lookup_attr_by_name(elem)
            if res is None:
                break
            curpos = res
        return res

    def print(self):
        pp = Shell.get_pp()
        pp.println("XMR LICENSE")
        pp.pad(1, "")
        pp.println(f"version: {self.version}")
        self.root.print()
        pp.leave()


