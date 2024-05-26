import os
import sys
import struct
import hashlib
import binascii
import random
import string

class BCert:
    BASE_DIR = "secrets"

    BCERT_CHAIN = 0x43484149
    BCERT_CERT = 0x43455254

    TAG_IDS = 0x00010001
    TAG_KEYINFO = 0x00010006
    TAG_SIGNATURE = 0x00010008
    TAG_NAMES = 0x00000007

    TAG_KEY = 0x00010200

    KEY_SIGNING = 0x0
    KEY_ENCRYPTION = 0x1

    DIGEST_SIZE = 0x20
    SIGNATURE_SIZE = 0x40
    PUB_KEY_SIZE = 0x40

    BO_SIZE = 0x400

    def __init__(self, source):
        self.source = source

    @staticmethod
    def load_file(name):
        path = os.path.join(BCert.BASE_DIR, name)
        with open(path, 'rb') as f:
            return f.read()

    def save_file(self, name, data):
        path = os.path.join(BCert.BASE_DIR, name)
        with open(path, 'wb') as f:
            f.write(data)

    @staticmethod
    def from_file(name):
        data = BCert.load_file(name)

        if data is not None:
            bi = ByteInput(name, data)

            magic = bi.peek_4()

            if magic == BCert.BCERT_CHAIN:
                return CertificateChain(bi)
            elif magic == BCert.BCERT_CERT:
                return Certificate(bi)

        return None

    class CertAttr:
        def __init__(self, bi, pos):
            self.pos = pos

            self.tag = bi.read_4()
            self.len = bi.read_4()

            self.pos += 8

            self.data = bi.read_n(self.len - 8)

        def tag(self):
            return self.tag

        def len(self):
            return self.len

        def data(self):
            return self.data

        def pos(self):
            return self.pos

        def print(self):
            pp = Shell.get_pp()
            pp.println("attr: " + Utils.hex_value(self.tag, 8))
            pp.printhex("data", self.data())

    class CertificateChain(BCert):
        def __init__(self):
            super().__init__(None)

            self.certs = []

        def __init__(self, bi):
            super().__init__(bi.source())

            self.magic = bi.read_4()
            self.word1 = bi.read_4()
            self.total_len = bi.read_4()
            self.word3 = bi.read_4()
            self.cert_cnt = bi.read_4()

            self.certs = []

            for i in range(self.cert_cnt):
                cert = Certificate(bi)
                self.certs.append(cert)

        def cert_cnt(self):
            return self.cert_cnt

        def get(self, idx):
            res = None

            if idx < len(self.certs):
                return self.certs[idx]

            return res

        def add(self, cert):
            self.certs.append(cert)
            self.cert_cnt += 1

        def insert(self, cert):
            chain = CertificateChain()

            chain.add(cert)

            for i in range(len(self.certs)):
                chain.add(self.certs[i])

            return chain

        def print(self, debug):
            pp = Shell.get_pp()

            pp.println("CERT CHAIN: " + self.source)
            pp.pad(2, "")

            for i in range(len(self.certs)):
                cert = self.certs[i]

                cert.print()

            pp.leave()

        def body(self):
            bo = ByteOutput(BCert.BO_SIZE)

            total_len = 0

            for i in range(len(self.certs)):
                cert = self.certs[i]

                total_len += len(cert.body())

            total_len += 5 * 4

            bo.write_4(BCert.BCERT_CHAIN)
            bo.write_4(0x00000001)
            bo.write_4(total_len)
            bo.write_4(0x00000000)
            bo.write_4(self.cert_cnt)

            for i in range(len(self.certs)):
                cert = self.certs[i]

                cert_data = cert.body()

                bo.write_n(cert_data)

            return bo.bytes()

    class Certificate(BCert):
        def __init__(self):
            super().__init__(None)

            self.attributes = []

        def __init__(self, bi):
            super().__init__(bi.source())

            start_pos = bi.get_pos()

            self.magic = bi.read_4()
            self.word1 = bi.read_4()
            self.total_len = bi.read_4()
            self.cert_len = bi.read_4()

            self.attributes = []

            len = self.total_len - 0x10

            while len > 0:
                attr = CertAttr(bi, bi.get_pos() - start_pos)
                self.attributes.append(attr)

                len -= attr.len()

            end_pos = bi.get_pos()

            n = end_pos - start_pos

            bi.set_pos(start_pos)
            self.data = bi.read_n(n)

        def verify_signing_key(self):
            if self.prvkey_sign is not None and self.pubkey_sign is not None:
                k = ECC.make_bi(self.prvkey_sign, 0, 0x20)

                pub = ECC.ECPoint(self.pubkey_sign)
                genpoint = ECC.GEN().op_multiply(k)

                if not ECC.on_curve(genpoint):
                    ERR.log("Device cert signing key not on curve")
                if not genpoint.equals(pub):
                    ERR.log("Device cert prv signing key does not match public key")

        def set_names(self, names):
            self.names = names

        def set_random(self, random):
            self.random = random

        def set_seclevel(self, seclevel):
            self.seclevel = seclevel

        def set_digest(self, digest):
            self.digest = digest

        def set_uniqueid(self, uniqueid):
            self.uniqueid = uniqueid

        def set_prvkey_sign(self, prvkey_sign):
            self.prvkey_sign = prvkey_sign

            self.verify_signing_key()

        def set_pubkey_sign(self, pubkey_sign):
            self.pubkey_sign = pubkey_sign

            self.verify_signing_key()

        def set_pubkey_enc(self, pubkey_enc):
            self.pubkey_enc = pubkey_enc

        def set_signature(self, signature):
            self.signature = signature

        def set_signing_key(self, signing_key):
            self.signing_key = signing_key

        def read_data(self, tag, off, len):
            res = None

            attr = self.lookup_tag(tag)

            if attr is not None:
                data = attr.data()

                bi = ByteInput(data)
                bi.set_pos(off)

                return bi.read_n(len)

            return res

        def get_names(self):
            if self.source is not None and self.names is None:
                res = []

                attr = self.lookup_tag(BCert.TAG_NAMES)

                if attr is not None:
                    vstr = []

                    data = attr.data()
                    len = len(data)

                    bi = ByteInput(data)

                    while len > 0:
                        size = bi.read_4()

                        if size > 0:
                            size = (size + 3) & 0xfffffffc

                            s = bi.read_string(size)
                            vstr.append(s)

                            len -= size

                        len -= 4

                    res = vstr

                self.names = res

            return self.names

        def get_random(self):
            if self.source is not None and self.random is None:
                self.random = self.read_data(BCert.TAG_IDS, 0, 0x10)

            return self.random

        def get_seclevel(self):
            if self.source is not None and self.seclevel == 0:
                attr = self.lookup_tag(BCert.TAG_IDS)

                if attr is not None:
                    data = attr.data()

                    bi = ByteInput(data)
                    bi.set_pos(0x10)

                    self.seclevel = bi.read_4()

            return self.seclevel

        def get_digest(self):
            if self.source is not None and self.digest is None:
                self.digest = self.read_data(BCert.TAG_IDS, 0x1c, BCert.DIGEST_SIZE)

            if self.source is None:
                pubkey = self.get_pubkey_for_signing()
                self.digest = Crypto.SHA256(pubkey)

            return self.digest

        def get_uniqueid(self):
            if self.source is not None and self.uniqueid is None:
                self.uniqueid = self.read_data(BCert.TAG_IDS, 0x40, 0x10)

            return self.uniqueid

        def get_pubkey(self, keyidx):
            res = None

            attr = self.lookup_tag(BCert.TAG_KEYINFO)

            if attr is not None:
                data = attr.data()
                len = len(data)

                bi = ByteInput(data)
                keycnt = bi.read_4()

                if keyidx < keycnt:
                    keysize = 0x50
                    bi.skip(keyidx * keysize)

                    tag = bi.read_4()

                    if tag == BCert.TAG_KEY:
                        bi.skip(4)
                        res = bi.read_n(BCert.PUB_KEY_SIZE)

            return res

        def get_pubkey_pos(self, keyidx):
            attr = self.lookup_tag(BCert.TAG_KEYINFO)

            if attr is not None:
                pos = attr.pos()

                data = attr.data()
                len = len(data)

                bi = ByteInput(data)
                keycnt = bi.read_4()
                pos += 4

                if keyidx < keycnt:
                    keysize = 0x50
                    bi.skip(keyidx * keysize)
                    pos += keyidx * keysize

                    tag = bi.read_4()
                    pos += 4

                    if tag == BCert.TAG_KEY:
                        bi.skip(4)
                        pos += 4
                        return pos

            return -1

        def get_digest_pos(self):
            attr = self.lookup_tag(BCert.TAG_IDS)

            return attr.pos + 0x1c

        def get_prvkey_for_signing(self):
            return self.prvkey_sign

        def get_pubkey_for_signing(self):
            if self.source is not None and self.pubkey_sign is None:
                self.pubkey_sign = self.get_pubkey(BCert.KEY_SIGNING)

            return self.pubkey_sign

        def get_pubkey_for_encryption(self):
            if self.source is not None and self.pubkey_enc is None:
                self.pubkey_enc = self.get_pubkey(BCert.KEY_ENCRYPTION)

            return self.pubkey_enc

        def get_signature(self):
            if self.source is not None and self.signature is None:
                self.signature = self.read_data(BCert.TAG_SIGNATURE, 0x04, BCert.SIGNATURE_SIZE)

            return self.signature

        def get_signature_pos(self):
            attr = self.lookup_tag(BCert.TAG_SIGNATURE)

            return attr.pos + 0x04

        def get_signkey(self):
            if self.source is not None and self.signing_key is None:
                self.signing_key = self.read_data(BCert.TAG_SIGNATURE, 0x04 + BCert.SIGNATURE_SIZE + 0x04, BCert.PUB_KEY_SIZE)

            if self.signing_key is None:
                return Device.get_group_pubkey().bytes()

            return self.signing_key

        def get_signkey_pos(self):
            attr = self.lookup_tag(BCert.TAG_SIGNATURE)

            return attr.pos + 0x04 + BCert.SIGNATURE_SIZE + 0x04

        def verify_signature(self):
            signature = self.get_signature()
            ecsig = ECC.ECSignature(signature)

            signkey = self.get_signkey()
            pubkey = ECC.ECPoint(signkey)

            signed_data = self.get_signed_data()
            digest = Crypto.SHA256(signed_data)

            return ecsig.verify(digest, pubkey)

        def sign(self, root_signing_key, cert_signing_key):
            pubkey_pos = self.get_pubkey_pos(BCert.KEY_SIGNING) + 8
            self.pubkey_sign = cert_signing_key.pub().bytes()
            self.data[pubkey_pos:pubkey_pos + len(self.pubkey_sign)] = self.pubkey_sign

            digest_pos = self.get_digest_pos() + 8
            self.digest = Crypto.SHA256(self.pubkey_sign)
            self.data[digest_pos:digest_pos + len(self.digest)] = self.digest

            signed_data = self.get_signed_data()
            digest = Crypto.SHA256(signed_data)

            ecsig = ECC.ECSignature.get(digest, root_signing_key.prv())
            self.signature = ecsig.bytes()

            signature_pos = self.get_signature_pos() + 8
            self.data[signature_pos:signature_pos + len(self.signature)] = self.signature

            self.signing_key = root_signing_key.pub().bytes()
            signkey_pos = self.get_signkey_pos() + 8
            self.data[signkey_pos:signkey_pos + len(self.signing_key)] = self.signing_key

        def print(self, debug):
            pp = Shell.get_pp()

            pp.println("### CERT")
            if debug:
                pp.pad(2, "")

                for i in range(len(self.attributes)):
                    attr = self.attributes[i]

                    attr.print()

                pp.leave()

            pp.pad(2, "- ")

            names = self.get_names()

            if names is not None:
                pp.println("names")

                pp.pad(2, "* ")

                for i in range(len(names)):
                    pp.println(names[i])

                pp.leave()

            random = self.get_random()

            if random is not None:
                pp.printhex("- random", random)

            pp.println("seclevel " + str(self.get_seclevel()))

            uniqueid = self.get_uniqueid()

            if uniqueid is not None:
                pp.printhex("- uniqueid", uniqueid)

            pubkey_sign = self.get_pubkey_for_signing()

            if pubkey_sign is not None:
                pp.printhex("- pubkey_sign", pubkey_sign)

            pubkey_enc = self.get_pubkey_for_encryption()

            if pubkey_enc is not None:
                pp.printhex("- pubkey_enc", pubkey_enc)

            digest = self.get_digest()

            if digest is not None:
                pp.printhex("- digest", digest)

            signature = self.get_signature()

            if signature is not None:
                pp.printhex("- signature", signature)

            signkey = self.get_signkey()

            if signkey is not None:
                pp.printhex("- signkey", signkey)

            if signature is not None and signkey is not None:
                status = self.verify_signature()

                sig_status = "sig status: "

                if status:
                    sig_status += "OK"
                else:
                    sig_status += "BAD SIGNATURE"

                pp.println(sig_status)

            pp.leave()

        def lookup_tag(self, tag):
            for i in range(len(self.attributes)):
                attr = self.attributes[i]

                if attr.tag() == tag:
                    return attr

            return None

        def get_signed_data(self):
            if self.data is not None:
                signed_data = self.data[:len(self.data) - 2 * 0x40 - 0x10]

                return signed_data

            bo = ByteOutput(BCert.BO_SIZE)
            bo.write_4(BCert.BCERT_CERT)
            bo.write_4(0x00000001)

            cert_len_pos = bo.get_pos()
            bo.skip(4)

            cert_len_no_sig_pos = bo.get_pos()
            bo.skip(4)

            bo.write_4(BCert.TAG_IDS)
            bo.write_4(0x58)

            random = self.get_random()
            if random is None:
                ERR.log("missing random attr for BCert")
            bo.write_n(random)

            seclevel = self.get_seclevel()
            if seclevel == 0:
                ERR.log("missing security level attr for BCert")
            bo.write_4(seclevel)

            bo.write_4(0x00000000)
            bo.write_4(0x00000002)

            digest = self.get_digest()
            if digest is None:
                ERR.log("cannot evaulate digest attr for BCert")
            bo.write_n(digest)

            bo.write_4(0xffffffff)

            id = self.get_uniqueid()
            if id is None:
                ERR.log("missing uniqueid attr for BCert")
            bo.write_n(id)

            bo.write_4(0x00010004)
            bo.write_4(0x14)

            bo.write_4(0x00002800)
            bo.write_4(0x00003C00)
            bo.write_4(0x00000002)

            bo.write_4(0x00010005)
            bo.write_4(0x10)

            bo.write_4(0x00000001)
            bo.write_4(0x00000004)

            bo.write_4(BCert.TAG_KEYINFO)
            bo.write_4(0xac)

            bo.write_4(0x00000002)

            bo.write_4(0x00010200)
            bo.write_4(0x00000000)

            pubkey_sign = self.get_pubkey_for_signing()
            if pubkey_sign is None:
                ERR.log("missing public key for signing attr in BCert")
            bo.write_n(pubkey_sign)
            bo.write_4(0x00000001)
            bo.write_4(0x00000001)

            bo.write_4(0x00010200)
            bo.write_4(0x00000000)

            pubkey_enc = self.get_pubkey_for_encryption()
            if pubkey_enc is None:
                ERR.log("missing public key for encryption attr in BCert")
            bo.write_n(pubkey_enc)
            bo.write_4(0x00000001)
            bo.write_4(0x00000002)

            cur_pos = bo.get_pos()

            signed_data_len = bo.length()
            signature_size = 0x90

            bo.set_pos(cert_len_pos)
            bo.write_4(signed_data_len + signature_size)

            bo.set_pos(cert_len_no_sig_pos)
            bo.write_4(signed_data_len)

            bo.set_pos(cur_pos)

            signed_data = bo.bytes()

            return signed_data

        def body(self):
            if self.data is not None:
                return self.data

            bo = ByteOutput(BCert.BO_SIZE)
            bo.write_4(BCert.BCERT_CERT)
            bo.write_4(0x00000001)

            cert_len_pos = bo.get_pos()
            bo.skip(4)

            cert_len_no_sig_pos = bo.get_pos()
            bo.skip(4)

            bo.write_4(BCert.TAG_IDS)
            bo.write_4(0x58)

            random = self.get_random()
            if random is None:
                ERR.log("missing random attr for BCert")
            bo.write_n(random)

            seclevel = self.get_seclevel()
            if seclevel == 0:
                ERR.log("missing security level attr for BCert")
            bo.write_4(seclevel)

            bo.write_4(0x00000000)
            bo.write_4(0x00000002)

            digest = self.get_digest()
            if digest is None:
                ERR.log("cannot evaulate digest attr for BCert")
            bo.write_n(digest)

            bo.write_4(0xffffffff)

            id = self.get_uniqueid()
            if id is None:
                ERR.log("missing uniqueid attr for BCert")
            bo.write_n(id)

            bo.write_4(0x00010004)
            bo.write_4(0x14)

            bo.write_4(0x00002800)
            bo.write_4(0x00003C00)
            bo.write_4(0x00000002)

            bo.write_4(0x00010005)
            bo.write_4(0x10)

            bo.write_4(0x00000001)
            bo.write_4(0x00000004)

            bo.write_4(BCert.TAG_KEYINFO)
            bo.write_4(0xac)

            bo.write_4(0x00000002)

            bo.write_4(0x00010200)
            bo.write_4(0x00000000)

            pubkey_sign = self.get_pubkey_for_signing()
            if pubkey_sign is None:
                ERR.log("missing public key for signing attr in BCert")
            bo.write_n(pubkey_sign)
            bo.write_4(0x00000001)
            bo.write_4(0x00000001)

            bo.write_4(0x00010200)
            bo.write_4(0x00000000)

            pubkey_enc = self.get_pubkey_for_encryption()
            if pubkey_enc is None:
                ERR.log("missing public key for encryption attr in BCert")
            bo.write_n(pubkey_enc)
            bo.write_4(0x00000001)
            bo.write_4(0x00000002)

            cur_pos = bo.get_pos()

            signed_data_len = bo.length()
            signature_size = 0x90

            bo.set_pos(cert_len_pos)
            bo.write_4(signed_data_len + signature_size)

            bo.set_pos(cert_len_no_sig_pos)
            bo.write_4(signed_data_len)

            bo.set_pos(cur_pos)

            signed_data = bo.bytes()

            signed_digest = Crypto.SHA256(signed_data)

            bo.write_4(BCert.TAG_SIGNATURE)
            bo.write_4(signature_size)

            bo.write_4(0x00010040)

            ecsig = ECC.ECSignature.get(signed_digest, Device.get_group_prvkey())
            self.signature = ecsig.bytes()

            bo.write_n(self.signature)

            bo.write_4(0x00000200)

            group_pubkey = Device.get_group_pubkey()
            pubkey_data = group_pubkey.bytes()
            bo.write_n(pubkey_data)

            self.data = bo.bytes()

            return self.data

    def print(self, debug):
        pp = Shell.get_pp()

        self.print(debug)

    def print(self):
        pp = Shell.get_pp()

        pp.println("### CERT")
        if debug:
            pp.pad(2, "")

            for i in range(len(self.attributes)):
                attr = self.attributes[i]

                attr.print()

            pp.leave()

        pp.pad(2, "- ")

        names = self.get_names()

        if names is not None:
            pp.println("names")

            pp.pad(2, "* ")

            for i in range(len(names)):
                pp.println(names[i])

            pp.leave()

        random = self.get_random()

        if random is not None:
            pp.printhex("- random", random)

        pp.println("seclevel " + str(self.get_seclevel()))

        uniqueid = self.get_uniqueid()

        if uniqueid is not None:
            pp.printhex("- uniqueid", uniqueid)

        pubkey_sign = self.get_pubkey_for_signing()

        if pubkey_sign is not None:
            pp.printhex("- pubkey_sign", pubkey_sign)

        pubkey_enc = self.get_pubkey_for_encryption()

        if pubkey_enc is not None:
            pp.printhex("- pubkey_enc", pubkey_enc)

        digest = self.get_digest()

        if digest is not None:
            pp.printhex("- digest", digest)

        signature = self.get_signature()

        if signature is not None:
            pp.printhex("- signature", signature)

        signkey = self.get_signkey()

        if signkey is not None:
            pp.printhex("- signkey", signkey)

        if signature is not None and signkey is not None:
            status = self.verify_signature()

            sig_status = "sig status: "

            if status:
                sig_status += "OK"
            else:
                sig_status += "BAD SIGNATURE"

            pp.println(sig_status)

        pp.leave()

    def lookup_tag(self, tag):
        for i in range(len(self.attributes)):
            attr = self.attributes[i]

            if attr.tag() == tag:
                return attr

        return None

    def get_signed_data(self):
        if self.data is not None:
            signed_data = self.data[:len(self.data) - 2 * 0x40 - 0x10]

            return signed_data

        bo = ByteOutput(BCert.BO_SIZE)
        bo.write_4(BCert.BCERT_CERT)
        bo.write_4(0x00000001)

        cert_len_pos = bo.get_pos()
        bo.skip(4)

        cert_len_no_sig_pos = bo.get_pos()
        bo.skip(4)

        bo.write_4(BCert.TAG_IDS)
        bo.write_4(0x58)

        random = self.get_random()
        if random is None:
            ERR.log("missing random attr for BCert")
        bo.write_n(random)

        seclevel = self.get_seclevel()
        if seclevel == 0:
            ERR.log("missing security level attr for BCert")
        bo.write_4(seclevel)

        bo.write_4(0x00000000)
        bo.write_4(0x00000002)

        digest = self.get_digest()
        if digest is None:
            ERR.log("cannot evaulate digest attr for BCert")
        bo.write_n(digest)

        bo.write_4(0xffffffff)

        id = self.get_uniqueid()
        if id is None:
            ERR.log("missing uniqueid attr for BCert")
        bo.write_n(id)

        bo.write_4(0x00010004)
        bo.write_4(0x14)

        bo.write_4(0x00002800)
        bo.write_4(0x00003C00)
        bo.write_4(0x00000002)

        bo.write_4(0x00010005)
        bo.write_4(0x10)

        bo.write_4(0x00000001)
        bo.write_4(0x00000004)

        bo.write_4(BCert.TAG_KEYINFO)
        bo.write_4(0xac)

        bo.write_4(0x00000002)

        bo.write_4(0x00010200)
        bo.write_4(0x00000000)

        pubkey_sign = self.get_pubkey_for_signing()
        if pubkey_sign is None:
            ERR.log("missing public key for signing attr in BCert")
        bo.write_n(pubkey_sign)
        bo.write_4(0x00000001)
        bo.write_4(0x00000001)

        bo.write_4(0x00010200)
        bo.write_4(0x00000000)

        pubkey_enc = self.get_pubkey_for_encryption()
        if pubkey_enc is None:
            ERR.log("missing public key for encryption attr in BCert")
        bo.write_n(pubkey_enc)
        bo.write_4(0x00000001)
        bo.write_4(0x00000002)

        cur_pos = bo.get_pos()

        signed_data_len = bo.length()
        signature_size = 0x90

        bo.set_pos(cert_len_pos)
        bo.write_4(signed_data_len + signature_size)

        bo.set_pos(cert_len_no_sig_pos)
        bo.write_4(signed_data_len)

        bo.set_pos(cur_pos)

        signed_data = bo.bytes()

        return signed_data

    def body(self):
        if self.data is not None:
            return self.data

        bo = ByteOutput(BCert.BO_SIZE)
        bo.write_4(BCert.BCERT_CERT)
        bo.write_4(0x00000001)

        cert_len_pos = bo.get_pos()
        bo.skip(4)

        cert_len_no_sig_pos = bo.get_pos()
        bo.skip(4)

        bo.write_4(BCert.TAG_IDS)
        bo.write_4(0x58)

        random = self.get_random()
        if random is None:
            ERR.log("missing random attr for BCert")
        bo.write_n(random)

        seclevel = self.get_seclevel()
        if seclevel == 0:
            ERR.log("missing security level attr for BCert")
        bo.write_4(seclevel)

        bo.write_4(0x00000000)
        bo.write_4(0x00000002)

        digest = self.get_digest()
        if digest is None:
            ERR.log("cannot evaulate digest attr for BCert")
        bo.write_n(digest)

        bo.write_4(0xffffffff)

        id = self.get_uniqueid()
        if id is None:
            ERR.log("missing uniqueid attr for BCert")
        bo.write_n(id)

        bo.write_4(0x00010004)
        bo.write_4(0x14)

        bo.write_4(0x00002800)
        bo.write_4(0x00003C00)
        bo.write_4(0x00000002)

        bo.write_4(0x00010005)
        bo.write_4(0x10)

        bo.write_4(0x00000001)
        bo.write_4(0x00000004)

        bo.write_4(BCert.TAG_KEYINFO)
        bo.write_4(0xac)

        bo.write_4(0x00000002)

        bo.write_4(0x00010200)
        bo.write_4(0x00000000)

        pubkey_sign = self.get_pubkey_for_signing()
        if pubkey_sign is None:
            ERR.log("missing public key for signing attr in BCert")
        bo.write_n(pubkey_sign)
        bo.write_4(0x00000001)
        bo.write_4(0x00000001)

        bo.write_4(0x00010200)
        bo.write_4(0x00000000)

        pubkey_enc = self.get_pubkey_for_encryption()
        if pubkey_enc is None:
            ERR.log("missing public key for encryption attr in BCert")
        bo.write_n(pubkey_enc)
        bo.write_4(0x00000001)
        bo.write_4(0x00000002)

        cur_pos = bo.get_pos()

        signed_data_len = bo.length()
        signature_size = 0x90

        bo.set_pos(cert_len_pos)
        bo.write_4(signed_data_len + signature_size)

        bo.set_pos(cert_len_no_sig_pos)
        bo.write_4(signed_data_len)

        bo.set_pos(cur_pos)

        signed_data = bo.bytes()

        signed_digest = Crypto.SHA256(signed_data)

        bo.write_4(BCert.TAG_SIGNATURE)
        bo.write_4(signature_size)

        bo.write_4(0x00010040)

        ecsig = ECC.ECSignature.get(signed_digest, Device.get_group_prvkey())
        self.signature = ecsig.bytes()

        bo.write_n(self.signature)

        bo.write_4(0x00000200)

        group_pubkey = Device.get_group_pubkey()
        pubkey_data = group_pubkey.bytes()
        bo.write_n(pubkey_data)

        self.data = bo.bytes()

        return self.data


