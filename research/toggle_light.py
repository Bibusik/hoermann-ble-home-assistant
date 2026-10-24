"""
Reuses (or creates+registers once) our own root key, then sends the signed
Light (CHANNEL_2) command N times with a pause between, toggling the light.
The key is persisted locally so we don't need the device's pairing window
open on every run. Never prints key material.
"""
import asyncio
import base64
import os
import struct
import sys
import time

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_public_key
from bleak import BleakClient, BleakScanner

sys.path.insert(0, os.path.dirname(__file__))
from qr_parser import parse_qr  # noqa: E402

ADDR = "E5:9B:6B:D2:84:D9"
NOTIFY_UUID = "669a900a-0008-968f-e311-6050405558b3"
WRITE_UUID = "669a900c-0008-968f-e311-6050405558b3"
SERVICE_UUID = "669a9001-0008-968f-e311-6050405558b3"
QR_FILE = r"C:\Users\serge\HoermannBLE\secret\qr_code.txt"
KEY_FILE = r"C:\Users\serge\HoermannBLE\secret\our_root_key.bin"  # our own generated secret, never printed
CHANNEL_LIGHT = 0x0012

TOGGLES = int(sys.argv[1]) if len(sys.argv) > 1 else 4
PAUSE = float(sys.argv[2]) if len(sys.argv) > 2 else 3.0

notif_chunks = []


def on_notify(_, data):
    notif_chunks.append(bytes(data))


async def write_chunks(client, blob: bytes):
    for i in range(0, len(blob), 20):
        chunk = blob[i:i + 20]
        try:
            await client.write_gatt_char(WRITE_UUID, chunk, response=True)
        except OSError as e:
            print(f"  (ignoring spurious write error: {e})")
            await asyncio.sleep(0.3)
        await asyncio.sleep(0.01)


async def collect_for(seconds: float):
    await asyncio.sleep(seconds)
    result = b"".join(notif_chunks)
    notif_chunks.clear()
    return result


SIGNED_INNER_TYPE_ENABLED = 4
SIGNED_INNER_TYPE_ROOT_REGISTRATION_POSSIBLE = 20


def current_challenge(reassembled: bytes, want_inner_type: int = None):
    # Signed-channel notification layout (SignedReader.ReadPackage):
    #   outer: [1][len_lo][len_hi]
    #   inner: [8-byte challenge][2-byte SignedNotificationType][2-byte ...]
    # EVERY type=1 notification carries a fresh challenge in cache.Challenge,
    # but which ONE is valid to sign with depends on context: the plain
    # "ENABLED" (4) notification sent right on connect is NOT the same
    # challenge as "ROOT_REGISTRATION_POSSIBLE" (20) sent later once the
    # device is actually ready for RegisterRootCmd - using the wrong one
    # yields a SECURITY_ERROR (65284 / 0xFF04) rejection.
    if len(reassembled) < 13 or reassembled[0] != 1:
        return None
    inner_type = reassembled[11] | (reassembled[12] << 8)
    if want_inner_type is not None and inner_type != want_inner_type:
        return None
    return reassembled[3:11]


def hmac_sign(key, *parts):
    import hmac as hmaclib
    import hashlib
    h = hmaclib.new(key, digestmod=hashlib.sha256)
    for p in parts:
        h.update(p)
    return h.digest()


def build_signed_frame(root_id, command, payload, key, challenge):
    length = 6 + len(payload) + 32
    header = struct.pack("<HHH", root_id, command, length)
    message = header + payload
    sig = hmac_sign(key, message, challenge)
    inner = message + sig
    return bytes([1]) + struct.pack("<H", len(inner) + 3) + inner


def build_register_root_cmd(root_id, key, challenge, username="ArnoNym"):
    uname = username.encode("utf-8")[:16]
    uname += b"\x00" * (16 - len(uname))
    payload = bytes([0]) + uname
    return build_signed_frame(root_id, 1, payload, key, challenge)


def build_switch_relais_cmd(root_id, channel_command, key, challenge):
    ts = int(time.time())
    payload = struct.pack("<Q", ts)
    return build_signed_frame(root_id, channel_command, payload, key, challenge)


async def get_key():
    # File format: [2-byte RootId LE][32-byte final operational key]. The
    # "final" key is NOT what we generated and RSA-delivered - RootKeyNotification
    # (SAL.BlueConnect.IO.Signed.RootKeyNotification.ReadStream) returns the
    # real key XORed against ours, so it must be un-XORed once at registration
    # time; see the save path below.
    if os.path.exists(KEY_FILE) and os.path.getsize(KEY_FILE) == 34:
        print("Reusing previously registered key.")
        with open(KEY_FILE, "rb") as f:
            data = f.read()
        return data[0] | (data[1] << 8), data[2:]

    print("No saved key - registering a new one (device must be in BLE pairing mode).")
    with open(QR_FILE, "r", encoding="utf-8") as f:
        qr_text = f.read()
    qr = parse_qr(qr_text)
    pubkey = load_der_public_key(base64.b64decode(qr["registration_key_b64"]))
    our_key = os.urandom(32)
    enc_key = pubkey.encrypt(our_key, padding.PKCS1v15())

    # Mirrors the real app exactly (re-checked against a real sniffed
    # registration): it sends RegisterRoot the INSTANT the EncryptedIO
    # progress counter ("02 04 00 <step>") reaches step=2 - signed with the
    # ORIGINAL challenge from connection-start (ENABLED notification), not
    # any later one. A connection whose step goes 01 -> 03 (never 02) is
    # dead - abandon it and retry on a fresh connection, no power-cycle
    # needed (confirmed: the real app's own first connection also sometimes
    # stalls at "03" and gets silently dropped in favour of a retry).
    ok = False
    for outer_attempt in range(5):
        print(f"\n--- registration connection attempt {outer_attempt + 1} ---")
        try:
            async with BleakClient(ADDR, services=[SERVICE_UUID], timeout=30.0) as client:
                await client.start_notify(NOTIFY_UUID, on_notify)
                reassembled = await collect_for(1.0)
                initial_challenge = current_challenge(reassembled, SIGNED_INNER_TYPE_ENABLED)
                if not initial_challenge:
                    print("  no initial challenge, retrying...")
                    continue
                print("  sending RSA registration blob...")

                reg_outer = bytes([2]) + struct.pack("<H", len(enc_key) + 3) + enc_key
                notif_chunks.clear()
                await write_chunks(client, reg_outer)

                print("  waiting for EncryptedIO progress step=2 (up to ~22s, the app itself warns this can take 20s)...")
                got_step2 = False
                for _ in range(110):  # up to ~22s, polled fast
                    await asyncio.sleep(0.2)
                    # Each EncryptedIO progress notification is its own 20-byte
                    # chunk: [2][04][00][step][padding...]. Check each one
                    # individually rather than the concatenated buffer's prefix.
                    for c in notif_chunks:
                        if len(c) >= 4 and c[0] == 2 and c[3] == 2:
                            got_step2 = True
                            break
                    if got_step2:
                        break
                if not got_step2:
                    print(f"  step=2 never arrived this connection, raw: {b''.join(notif_chunks).hex()}")
                    continue  # abandon this connection, try a fresh one - no power-cycle needed
                print("  got step=2, sending RegisterRoot immediately with the initial challenge...")

                notif_chunks.clear()
                challenge = initial_challenge
                frame = build_register_root_cmd(0, our_key, challenge)  # RootId=0 for this bootstrap frame only
                await write_chunks(client, frame)
                # A SECURITY_ERROR reply is a single 20-byte chunk we can
                # recognise immediately (inner type 0xFF04, i.e. bytes[11]==4
                # and bytes[12]==0xff) and bail out on early. A real success
                # is 3 chunks arriving ~0.1s apart (~60 bytes total) - keep
                # polling for it instead of stopping at the first chunk like
                # before (that bug is what lost us a real success earlier).
                reassembled = b""
                is_error = False
                for _ in range(30):  # up to 3s
                    await asyncio.sleep(0.1)
                    reassembled = b"".join(notif_chunks)
                    if len(reassembled) >= 13 and reassembled[11] == 4 and reassembled[12] == 0xFF:
                        is_error = True
                        break
                    if len(reassembled) >= 55:
                        break
                print(f"  RegisterRoot response: {len(reassembled)} bytes "
                      f"({'SECURITY_ERROR' if is_error else '...'}): {reassembled.hex()}")
                if len(reassembled) >= 55 and not is_error:
                    ok = True
                    break
        except Exception as e:
            print(f"  connection attempt failed: {e!r}")
        await asyncio.sleep(0.5)

    if not ok:
        raise RuntimeError("Registration failed after several fresh-connection retries.")

    # RootKeyNotification layout, inside the inner payload (after the 8-byte
    # challenge + 2-byte type + 2-byte discarded field SignedReader already
    # consumed): [2-byte RootId][32-byte key XORed against our_key].
    inner = reassembled[3:]
    assigned_root_id = inner[12] | (inner[13] << 8)
    scrambled = inner[14:14 + 32]
    final_key = bytes(a ^ b for a, b in zip(scrambled, our_key))

    with open(KEY_FILE, "wb") as f:
        f.write(assigned_root_id.to_bytes(2, "little") + final_key)
    print(f"New key registered and saved locally (assigned RootId={assigned_root_id}).")
    return assigned_root_id, final_key


async def main():
    root_id, key = await get_key()
    print(f"Using RootId={root_id}")

    for i in range(TOGGLES):
        print(f"\n--- Toggle {i + 1}/{TOGGLES} ---")
        try:
            async with BleakClient(ADDR, services=[SERVICE_UUID], timeout=30.0) as client:
                await client.start_notify(NOTIFY_UUID, on_notify)
                challenge = None
                for _ in range(5):
                    reassembled = await collect_for(0.6)
                    challenge = current_challenge(reassembled)
                    if challenge:
                        break
                if not challenge:
                    print("No challenge received, skipping this toggle.")
                    continue
                frame = build_switch_relais_cmd(root_id, CHANNEL_LIGHT, key, challenge)
                await write_chunks(client, frame)
                reassembled = await collect_for(1.0)
                print(f"Response: {len(reassembled)} bytes: {reassembled.hex()}")
        except Exception as e:
            print(f"Toggle {i + 1} failed: {e!r}")
        if i < TOGGLES - 1:
            await asyncio.sleep(PAUSE)

    print("\nDone.")


asyncio.run(main())
