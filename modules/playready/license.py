import base64
from xml.etree import ElementTree as ET
from Crypto.Cipher import ECC
from Crypto.PublicKey import ECC as ECCKey

class License:
    def __init__(self, xml):
        self.data = xml
        self.root = self.parse_xml(xml)
        self.license_data = None
        self.custom_data = None
        self.custom_root = None
        self.UserToken = None
        self.BrandGuid = None
        self.ClientId = None
        self.LicenseType = None
        self.BeginDate = None
        self.ExpirationDate = None
        self.ErrorCode = None
        self.TransactionId = None
        self.blicense = None
        self.content_key = None

        licresp_node = self.select_first(self.root, "soap:Envelope.soap:Body.AcquireLicenseResponse.AcquireLicenseResult.Response.LicenseResponse")
        if licresp_node is not None:
            license = self.get_value(licresp_node, "Licenses.License")
            custom = self.get_value(licresp_node, "CustomData")

            try:
                self.license_data = base64.b64decode(license)
                self.custom_data = base64.b64decode(custom)
                self.parse_customdata()
                self.parse_license()
            except Exception as e:
                print(e)

    def parse_xml(self, xml_data):
        return ET.parse(xml_data)

    def select_first(self, root, path):
        return root.find(path)

    def get_value(self, root, tag):
        element = root.find(tag)
        return element.text if element is not None else None

    def parse_customdata(self):
        if self.custom_data is not None:
            self.custom_root = self.parse_xml(self.custom_data)
            licresp_cdata_node = self.select_first(self.custom_root, "LicenseResponseCustomData")

            if licresp_cdata_node is not None:
                self.UserToken = self.get_value(self.custom_root, "UserToken")
                self.BrandGuid = self.get_value(self.custom_root, "BrandGuid")
                self.ClientId = self.get_value(self.custom_root, "ClientId")
                self.LicenseType = self.get_value(self.custom_root, "LicenseType")
                self.BeginDate = self.get_value(self.custom_root, "BeginDate")
                self.ExpirationDate = self.get_value(self.custom_root, "ExpirationDate")
                self.ErrorCode = self.get_value(self.custom_root, "ErrorCode")
                self.TransactionId = self.get_value(self.custom_root, "TransactionId")

    def parse_license(self):
        self.blicense = BLicense(self.license_data)

    def get_key_id(self):
        ck = self.blicense.get_attr("OuterContainer.KeyMaterialContainer.ContentKey")
        if ck is not None:
            return ck.key_id()
        return None

    def get_encrypted_data(self):
        ck = self.blicense.get_attr("OuterContainer.KeyMaterialContainer.ContentKey")
        if ck is not None:
            return ck.enc_data()
        return None

    def get_content_key(self):
        if self.content_key is None:
            encrypted_data = self.get_encrypted_data()
            cur_dev = Device.cur_device()
            plaintext = Crypto.ecc_decrypt(encrypted_data, cur_dev.enc_key().prv())
            self.content_key = plaintext[0x10:0x20]
        return self.content_key

    def print(self):
        pp = Shell.get_pp()
        pp.println("LICENSE")
        pp.pad(2, "")
        pp.println("CUSTOM DATA")
        pp.pad(2, "")
        pp.println(f"UserToken:       {self.UserToken}")
        pp.println(f"BrandGuid:       {self.BrandGuid}")
        pp.println(f"LicenseType:     {self.LicenseType}")
        pp.println(f"BeginDate:       {self.BeginDate}")
        pp.println(f"ExpirationDate:  {self.ExpirationDate}")
        pp.println(f"ErrorCode:       {self.ErrorCode}")
        pp.println(f"TransactionId:   {self.TransactionId}")
        pp.leave()
        self.blicense.print()
        pp.printhex("content_key", self.get_content_key())
        pp.leave()
