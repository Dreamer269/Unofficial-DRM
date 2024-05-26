import os

class KeyExtractor:
    class KeyConfig:
        def __init__(self, keyfile, start_sym, end_sym):
            self.keyfile = keyfile
            self.start_sym = start_sym
            self.end_sym = end_sym

    K1_CONFIG = KeyConfig("k1", "__img_keys_start", "__img_template_start")
    T1_CONFIG = KeyConfig("t1", "__img_template_start", "__img_template_end")
    G1_CONFIG = KeyConfig("g1", "__img_template_end", "__img_bgc_end")
    Z1_CONFIG = KeyConfig("z1", "__img_bgc_end", "__img_zgp_end")

    @staticmethod
    def extract_data(elf, kc):
        sym1 = elf.lookup_symbol(kc.start_sym)
        sym2 = elf.lookup_symbol(kc.end_sym)

        if sym1 is not None and sym2 is not None:
            off = sym1.value()
            size = sym2.value() - off
            return elf.read_n(off, size)
        
        return None

    @staticmethod
    def extract_keys(binarypath, keypair):
        try:
            elf = ELF.load(binarypath)
            pp = PaddedPrinter.getInstance()

            k1_enc_data = KeyExtractor.extract_data(elf, KeyExtractor.K1_CONFIG)

            if k1_enc_data is None:
                Shell.err_string = "cannot find K1 encrypted data"
                return False

            pp.println("- decrypting keys image (K1)")

            k1_data = RSA.decrypt_oaep(k1_enc_data, keypair)

            if k1_data is None:
                Shell.err_string = "failed to decrypt K1 encrypted data"
                return False

            pp.printhex("K1", k1_data)

            key = k1_data[0x00:0x10]
            iv = k1_data[0x50:0x60]

            pp.printhex("aes key", key)
            pp.printhex("aes iv", iv)

            t1_enc_data = KeyExtractor.extract_data(elf, KeyExtractor.T1_CONFIG)

            if t1_enc_data is None:
                Shell.err_string = "cannot find T1 encrypted data"
                return False

            pp.println("- decrypting template certificate (T1)")

            t1_data = Crypto.aes_cbc_decrypt(t1_enc_data, iv, key)

            if t1_data is None:
                Shell.err_string = "failed to decrypt T1 encrypted data"
                return False

            pp.printhex("T1", t1_data)

            g1_enc_data = KeyExtractor.extract_data(elf, KeyExtractor.G1_CONFIG)

            if g1_enc_data is None:
                Shell.err_string = "cannot find G1 encrypted data"
                return False

            pp.println("- decrypting binary group certificate (G1)")

            g1_data = Crypto.aes_cbc_decrypt(g1_enc_data, iv, key)

            if g1_data is None:
                Shell.err_string = "failed to decrypt G1 encrypted data"
                return False

            pp.printhex("G1", g1_data)

            z1_enc_data = KeyExtractor.extract_data(elf, KeyExtractor.Z1_CONFIG)

            if z1_enc_data is None:
                Shell.err_string = "cannot find Z1 encrypted data"
                return False

            pp.println("- decrypting private ECC group key (Z1)")

            z1_data = Crypto.aes_cbc_decrypt(z1_enc_data, iv, key)

            if z1_data is None:
                Shell.err_string = "failed to decrypt Z1 encrypted data"
                return False

            pp.printhex("Z1", z1_data)
        except Exception as e:
            pass

        return True


