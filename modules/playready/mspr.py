class MSPR:
    WMRMECC256PubKey = "C8B6AF16EE941AADAA5389B4AF2C10E356BE42AF175EF3FACE93254E7B0B3D9B982B27B5CB2341326E56AA857DBFD5C634CE2CF9EA74FCA8F2AF5957EFEEA562"

    SL150 = 150
    SL2000 = 2000
    SL3000 = 3000

    GROUP_CERT = "g1"
    GROUP_CERT_PRV_KEY = "z1"

    AES_KEY_SIZE = 0x10
    NONCE_SIZE = 0x10

    class XmlKey:
        def __init__(self):
            self.shared_point = ECC.ECKey()
            self.shared_key = pub().x()

        def pub(self):
            return self.shared_point.pub()

        def prv(self):
            return self.shared_point.prv()

        def setup_aes_key(self):
            shared_data = ECC.bi_bytes(self.shared_key)

            self.aes_iv = [0] * AES_KEY_SIZE
            self.aes_key = [0] * AES_KEY_SIZE

            self.aes_iv[:AES_KEY_SIZE] = shared_data[:AES_KEY_SIZE]
            self.aes_key[:AES_KEY_SIZE] = shared_data[0x10:AES_KEY_SIZE]

        def set_aes_iv(self, iv):
            if len(iv) != AES_KEY_SIZE:
                ERR.log("Invalid AES IV length")

            self.aes_iv = iv

        def set_aes_key(self, key):
            if len(key) != AES_KEY_SIZE:
                ERR.log("Invalid AES key length")

            self.aes_key = key

        def aes_iv(self):
            if self.aes_iv is None:
                self.setup_aes_key()

            return self.aes_iv

        def aes_key(self):
            if self.aes_key is None:
                self.setup_aes_key()

            return self.aes_key

        def print(self):
            pp = Shell.get_pp()

            pp.println("XML key (AES/CBC)")
            pp.pad(2, "")
            pp.printhex("iv ", self.aes_iv())
            pp.printhex("key", self.aes_key())
            pp.leave()

        def bytes(self):
            data = [0] * (2 * AES_KEY_SIZE)
            data[:AES_KEY_SIZE] = self.aes_iv()
            data[AES_KEY_SIZE:2 * AES_KEY_SIZE] = self.aes_key()

            return data

    def __init__(self):
        self.xmlkey = None
        self.WMRMpubkey = None

    def fixed_identity(self):
        return Vars.get_int("MSPR_DEBUG") == 1

    def SL2string(self, level):
        if level == self.SL150:
            return "SL150"
        elif level == self.SL2000:
            return "SL2000"
        elif level == self.SL3000:
            return "SL3000"

        return str(level)

    def string2SL(self, s):
        if s is not None:
            if s == "SL150":
                return self.SL150
            elif s == "SL2000":
                return self.SL2000
            elif s == "SL3000":
                return self.SL3000

        return -1

    def getXmlKey(self):
        if self.xmlkey is None:
            self.xmlkey = self.XmlKey()

        return self.xmlkey

    def XML_HEADER_START(self):
        s = ""

        s += "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
        s += "<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
        s += "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" "
        s += "xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">"

        return s

    def SOAP_BODY_START(self):
        return "<soap:Body>"

    def ACQUIRE_LICENSE_HEADER_START(self):
        s = ""
        s += "<AcquireLicense xmlns=\"http://schemas.microsoft.com/DRM/2007/03/protocols\">"
        s += "<challenge><Challenge xmlns=\"http://schemas.microsoft.com/DRM/2007/03/protocols/messages\">"

        return s

    def LA_HEADER_START(self):
        s = ""

        s += "<LA xmlns=\"http://schemas.microsoft.com/DRM/2007/03/protocols\" Id=\"SignedData\" xml:space=\"preserve\">"
        s += "<Version>1</Version>"

        return s

    def CONTENT_HEADER(self, wrmheader):
        s = ""

        s += "<ContentHeader>"
        s += wrmheader
        s += "</ContentHeader>"

        return s

    def CLIENT_INFO(self):
        return "<ClientInfo><ClientVersion>1.2.0.1404</ClientVersion></ClientInfo>"

    def LICENSE_NONCE(self, nonce):
        s = ""

        s += "<LicenseNonce>"
        s += nonce
        s += "</LicenseNonce>"

        # not sure of this
        s += "  "

        return s

    def ENCRYPTED_DATA_START(self):
        s = ""

        s += "<EncryptedData xmlns=\"http://www.w3.org/2001/04/xmlenc#\" Type=\"http://www.w3.org/2001/04/xmlenc#Element\">"
        s += "<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"></EncryptionMethod>"

        return s

    def KEY_INFO(self, keydata):
        s = ""

        s += "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
        s += "<EncryptedKey xmlns=\"http://www.w3.org/2001/04/xmlenc#\">"
        s += "<EncryptionMethod Algorithm=\"http://schemas.microsoft.com/DRM/2007/03/protocols#ecc256\"></EncryptionMethod>"
        s += "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
        s += "<KeyName>WMRMServer</KeyName>"
        s += "</KeyInfo>"
        s += "<CipherData>"
        s += "<CipherValue>"
        s += keydata
        s += "</CipherValue>"
        s += "</CipherData>"
        s += "</EncryptedKey>"
        s += "</KeyInfo>"

        return s

    def CIPHER_DATA(self, cipherdata):
        s = ""

        s += "<CipherData><CipherValue>"
        s += cipherdata
        s += "</CipherValue></CipherData>"

        return s

    def ENCRYPTED_DATA_END(self):
        s = ""

        s += "</EncryptedData>"

        return s

    def LA_HEADER_END(self):
        s = ""

        s += "</LA>"

        return s

    def SIGNED_INFO(self, digest):
        s = ""

        s += "<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
        s += "<CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\">"
        s += "</CanonicalizationMethod>"
        s += "<SignatureMethod Algorithm=\"http://schemas.microsoft.com/DRM/2007/03/protocols#ecdsa-sha256\">"
        s += "</SignatureMethod>"
        s += "<Reference URI=\"#SignedData\">"
        s += "<DigestMethod Algorithm=\"http://schemas.microsoft.com/DRM/2007/03/protocols#sha256\">"
        s += "</DigestMethod>"
        s += "<DigestValue>"
        s += digest
        s += "</DigestValue>"
        s += "</Reference>"
        s += "</SignedInfo>"

        return s

    def SIGNATURE_START(self):
        s = ""

        s += "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"

        return s

    def SIGNATURE(self, signature):
        s = ""

        s += "<SignatureValue>"
        s += signature
        s += "</SignatureValue>"

        return s

    def PUBLIC_KEY(self, pubkey):
        s = ""

        s += "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
        s += "<KeyValue><ECCKeyValue><PublicKey>"
        s += pubkey
        s += "</PublicKey>"
        s += "</ECCKeyValue>"
        s += "</KeyValue>"
        s += "</KeyInfo>"

        return s

    def SIGNATURE_END(self):
        s = ""

        s += "</Signature>"

        return s

    def ACQUIRE_LICENSE_HEADER_END(self):
        s = ""

        s += "</Challenge></challenge></AcquireLicense>"

        return s

    def SOAP_BODY_END(self):
        s = ""

        s += "</soap:Body>"

        return s

    def XML_HEADER_END(self):
        s = ""

        s += "</soap:Envelope>"

        return s

    def CERT_CHAIN_START(self):
        s = ""

        s += "<Data><CertificateChains><CertificateChain>"

        return s

    def CERT_CHAIN_END(self):
        s = ""

        s += "</CertificateChain></CertificateChains></Data>"

        return s

    def build_digest_content(self, wrmheader, nonce, keydata, cipherdata):
        xml_req = ""

        xml_req += self.LA_HEADER_START()
        xml_req += self.CONTENT_HEADER(wrmheader)
        xml_req += self.CLIENT_INFO()
        xml_req += self.LICENSE_NONCE(nonce)
        xml_req += self.ENCRYPTED_DATA_START()
        xml_req += self.KEY_INFO(keydata)
        xml_req += self.CIPHER_DATA(cipherdata)
        xml_req += self.ENCRYPTED_DATA_END()
        xml_req += self.LA_HEADER_END()

        return xml_req

    def build_signed_content(self, digest):
        xml_req = ""

        return xml_req

    def build_signature(self, dev, data):
        pp = Shell.get_pp()

        cert = dev.get_cert()

        prvkey_sign = cert.get_prvkey_for_signing()
        prv_sign_key = ECC.make_bi(prvkey_sign, 0, 0x20)

        signature_bytes = Crypto.ecdsa(data.getBytes(), prv_sign_key)

        signature = Crypto.base64_encode(signature_bytes)

        pp.println("XML SIGNATURE")
        pp.pad(2, "")
        pp.println(signature)
        pp.leave()

        pubkey_sign = cert.get_pubkey_for_signing()

        pubkey = Crypto.base64_encode(pubkey_sign)

        pp.println("PUBKEY")
        pp.pad(2, "")
        pp.println(pubkey)
        pp.leave()

        xml_req = ""
        xml_req += self.SIGNATURE(signature)
        xml_req += self.PUBLIC_KEY(pubkey)
        xml_req += self.SIGNATURE_END()

        return xml_req

    def build_license_request(self, dev, wrmheader, nonce, keydata, cipherdata):
        pp = Shell.get_pp()

        xml_req = ""

        xml_req += self.XML_HEADER_START()
        xml_req += self.SOAP_BODY_START()
        xml_req += self.ACQUIRE_LICENSE_HEADER_START()

        digest_content = self.build_digest_content(wrmheader, nonce, keydata, cipherdata)
        xml_req += digest_content

        digest_bytes = Crypto.SHA256(digest_content.getBytes())
        digest = Crypto.base64_encode(digest_bytes)

        pp.println("XML DIGEST")
        pp.pad(2, "")
        pp.println(digest)
        pp.leave()

        xml_req += self.SIGNATURE_START()

        signed_info = self.SIGNED_INFO(digest)
        xml_req += signed_info

        if self.fixed_identity():
            r = ECC.make_bi(Utils.reverse_hex_string("2238f95e2961b5eea60a64925b14d7fa42d4ba11eb99d7cb956aa056838b6d38"))
            ECC.set_random(r)

        signature = self.build_signature(dev, signed_info)

        xml_req += signature

        xml_req += self.ACQUIRE_LICENSE_HEADER_END()
        xml_req += self.SOAP_BODY_END()
        xml_req += self.XML_HEADER_END()

        return xml_req

    def pad16(self, s):
        len = (s.length() + 0x0f) & 0xfffffff0

        data = [0] * len
        data[:s.length()] = s.getBytes()

        pad = s.length() % 0x10

        if pad != 0:
            cnt = 0x10 - pad

            for i in range(cnt):
                data[s.length() + i] = cnt

        return data

    def wrmhdr_from_prothdr(self, phdr):
        data = Crypto.base64_decode(phdr)

        bi = ByteInput(data)
        bi.little_endian()
        bi.skip(8)

        size = bi.read_2()

        if len(data) != (size + 10):
            ERR.log("Unexpected PROTECTIONHEADER")

        cnt = size / 2

        wrmhdr = [0] * cnt

        for i in range(cnt):
            ch = bi.read_2()

            wrmhdr[i] = ch

        return "".join(wrmhdr)

    def get_nonce(self):
        data = ECC.bi_bytes(ECC.random())

        nonce = [0] * NONCE_SIZE
        nonce[:NONCE_SIZE] = data[:NONCE_SIZE]

        Utils.print_buf(0, "nonce", nonce)

        return Crypto.base64_encode(nonce)

    def get_cipherdata(self, dev, xmlkey):
        dchain = dev.get_cert_chain()
        chain_data = dchain.body()

        b64_certchain = Crypto.base64_encode(chain_data)

        s = ""

        s += self.CERT_CHAIN_START()
        s += " "
        s += b64_certchain
        s += " "
        s += self.CERT_CHAIN_END()

        cert_data = self.pad16(s)

        enc_cert_data = Crypto.aes_cbc_encrypt(cert_data, xmlkey.aes_iv(), xmlkey.aes_key())

        iv_len = len(xmlkey.aes_iv())
        enc_data_len = len(enc_cert_data)

        ciphertext = [0] * (iv_len + enc_data_len)

        ciphertext[:iv_len] = xmlkey.aes_iv()
        ciphertext[iv_len:] = enc_cert_data

        return Crypto.base64_encode(ciphertext)

    def get_keydata(self, dev, xmlkey):
        keydata = xmlkey.bytes()

        encrypted = Crypto.ecc_encrypt(keydata, getWMRMpubkey())

        return Crypto.base64_encode(encrypted)

    def get_license_request(self, dev, wrmheader):
        pp = Shell.get_pp()

        xkey = self.XmlKey()

        if self.fixed_identity():
            xkey.set_aes_iv(Utils.parse_hex_string("4869b8f5a3dc1cee30ea2c045dde6ec5"))
            xkey.set_aes_key(Utils.parse_hex_string("577c79adfd93be07c3d909e92787ed8a"))

        xkey.print()

        if self.fixed_identity():
            r = ECC.make_bi("6d51282ad8c51aa7cc342f031c894534")
            ECC.set_random(r)

        nonce = self.get_nonce()
        pp.println("NONCE")
        pp.pad(2, "")
        pp.println(nonce)
        pp.leave()

        if self.fixed_identity():
            r = ECC.make_bi(Utils.reverse_hex_string("bf2aea21c2547e71342a09ead1cc27971342424e32e88c3140942cb11b5b0cfd"))
            ECC.set_random(r)

        keydata = self.get_keydata(dev, xkey)
        pp.println("KEYDATA")
        pp.pad(2, "")
        pp.println(keydata)
        pp.leave()

        if self.fixed_identity():
            r = ECC.make_bi(Utils.reverse_hex_string("062dd035241da79eedbc2abc9d99ab5b159788bb78d56aedcc3b603018ec02f7"))
            ECC.set_random(r)

        cipherdata = self.get_cipherdata(dev, xkey)
        pp.println("CIPHERDATA")
        pp.pad(2, "")
        pp.println(cipherdata)
        pp.leave()

        xml_req = self.build_license_request(dev, wrmheader, nonce, keydata, cipherdata)

        return xml_req

    def getWMRMpubkey(self):
        return self.WMRMpubkey

    def verify_group_cert_keys(self):
        k = ECC.ECKey.from_file(BCert.BASE_DIR + File.separatorChar + self.GROUP_CERT_PRV_KEY)

        bc = BCert.from_file(self.GROUP_CERT)

        if k is None:
            ERR.log("Cannot find private group cert key file: " + self.GROUP_CERT_PRV_KEY)
        if bc is None:
            ERR.log("Cannot find group cert file: " + self.GROUP_CERT)

        chain = bc

        cert = chain.get(0)

        if cert is not None:
            pubdata = cert.get_pubkey_for_signing()

            pubkey_from_cert = ECC.ECPoint(pubdata)
            pubkey_from_prvkey = k.pub()

            if pubkey_from_cert.equals(pubkey_from_prvkey):
                return True

        return False

    def align_x10(self, size):
        return ((size + 0x0f) & 0xfffffff0)

    def aes_ctr_decrypt(self, data, off, size, iv, content_key):
        asize = self.align_x10(size)

        ciphertext = [0] * asize
        ciphertext[:size] = data[off:off + size]

        decrypted = Crypto.aes_ctr_decrypt(ciphertext, iv, content_key)

        plaintext = [0] * size
        plaintext[:size] = decrypted[:size]

        return plaintext

