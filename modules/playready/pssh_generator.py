import base64
import struct
import binascii

def create_playready_pssh(kid, la_url):
    # PlayReady Header XML
    playready_header_xml = f"""
    <WRMHEADER xmlns="http://schemas.microsoft.com/DRM/2007/03/PlayReadyHeader" version="4.0.0.0">
        <DATA>
            <PROTECTINFO>
                <KID>{kid}</KID>
            </PROTECTINFO>
            <LA_URL>{la_url}</LA_URL>
        </DATA>
    </WRMHEADER>
    """
    print("PlayReady Header XML:", playready_header_xml)

    # Base64 encode the PlayReady Header XML
    playready_header_b64 = base64.b64encode(playready_header_xml.encode('utf-8')).decode('utf-8')
    print("Base64 Encoded PlayReady Header:", playready_header_b64)

    # Decode the Base64 encoded XML to bytes
    playready_header_bytes = base64.b64decode(playready_header_b64)
    print("PlayReady Header Bytes:", playready_header_bytes)

    # Create the PSSH box
    system_id = '9a04f07998404286ab92e65be0885f95'  # PlayReady SystemID
    system_id_bytes = binascii.unhexlify(system_id)

    pssh_box_header = struct.pack('>I4sI16sI', 
                                  32 + len(playready_header_bytes),  # Size of the box
                                  b'pssh',                            # Box type
                                  0,                                  # Version and flags
                                  system_id_bytes,                    # SystemID
                                  len(playready_header_bytes))        # Size of PlayReady Header

    pssh_box = pssh_box_header + playready_header_bytes

    return base64.b64encode(pssh_box).decode('utf-8')

# Example Usage
kid = 'u2pn6zTLll67z2FmMPGj2g=='  # Example Key ID
la_url = 'http://playready.directtaps.net/pr/svc/rightsmanager.asmx?PlayRight=1&ContentKey=EAtsIJQPd5pFiRUrV9Layw=='

pssh_data_base64 = create_playready_pssh(kid, la_url)
print('PlayReady PSSH Data (Base64):', pssh_data_base64)
