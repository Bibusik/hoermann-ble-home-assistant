"""Port of RegisterDeviceData.ParseDataForVersionN (Hoermann.BleApp / SAL.BlueConnect.API.Devices.Register).
Extracts the Base64 RegistrationKey (RSA public key, X.509 SubjectPublicKeyInfo DER) from the raw QR text.
"""


def parse_qr(qr_text: str):
    qr_text = qr_text.strip()
    version = int(qr_text[0:2], 16)
    product_class_hex = qr_text[2:6]
    product_class = int(product_class_hex[0:2], 16)
    product_id = int(product_class_hex[2:4], 16)
    pos = 6

    if version == 1:
        pos += 3 + 2 + 2 + 7  # serial fields (string form)
        registration_key = qr_text[pos:]
    elif version in (2, 3, 4):
        pos += 7 + 2 + 2 + 5 + 7
        if version in (3, 4):
            pos += 2  # CustomerID
        registration_key = qr_text[pos:] if version != 4 else ""
    else:
        raise ValueError(f"Unknown QR version {version}")

    return {
        "version": version,
        "product_class": product_class,
        "product_id": product_id,
        "registration_key_b64_len": len(registration_key),
        "registration_key_b64": registration_key,
    }


if __name__ == "__main__":
    import sys
    path = sys.argv[1]
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    info = parse_qr(text)
    # Print only non-secret metadata, never the key itself
    print("version:", info["version"])
    print("product_class:", info["product_class"], "product_id:", info["product_id"])
    print("registration_key_b64_len:", info["registration_key_b64_len"])
    import base64
    try:
        raw = base64.b64decode(info["registration_key_b64"])
        print("decoded RSA pubkey DER length:", len(raw), "bytes")
        print("starts with 0x30 (ASN.1 SEQUENCE)?", raw[0] == 0x30)
    except Exception as e:
        print("base64 decode FAILED:", e)
