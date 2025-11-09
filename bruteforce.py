from ecdsa import SECP256k1, SigningKey
from hashlib import sha256
from ecdsa.util import string_to_number
from binascii import hexlify
import hashlib
import bech32
import concurrent.futures

def pubkey_to_bech32(pubkey_bytes):
    h160 = hashlib.new('ripemd160', sha256(pubkey_bytes).digest()).digest()
    return bech32.encode("bc", 0, h160)

def verify_private_key(d, expected_pub_hex, expected_bech32):
    sk = SigningKey.from_secret_exponent(d, curve=SECP256k1)
    vk = sk.get_verifying_key()
    prefix = b'\x02' if vk.pubkey.point.y() % 2 == 0 else b'\x03'
    pubkey_compressed = prefix + vk.to_string()[:32]
    pub_hex = hexlify(pubkey_compressed).decode()
    addr = pubkey_to_bech32(pubkey_compressed)
    if pub_hex == expected_pub_hex and addr == expected_bech32:
        return pub_hex, addr
    return None

def recover_private_key(pair, pair_id=0, d_range=10000000000000):
    r1, s1, z1, r2, s2, z2, expected_pubkey, expected_address = pair
    n = SECP256k1.order
    print(f"[PAIR #{pair_id}] Start Δk brute-force w zakresie ±{d_range}...")

    for offset in range(0, d_range + 1):
        for sign in (-1, 1):
            dk = offset * sign
            try:
                delta_s = (s1 - s2) % n
                delta_z = (z1 - z2) % n
                if delta_s == 0:
                    continue
                delta_s_inv = pow(delta_s, -1, n)
                k1 = (dk * delta_s + delta_z) * delta_s_inv % n
                r_inv = pow(r1, -1, n)
                d_candidate = ((s1 * k1 - z1) * r_inv) % n

                log_fragment = hex(d_candidate)[2:10]
                print(f"[PAIR #{pair_id}] Δk = {dk:+7d} | d ~ {log_fragment}")

                result = verify_private_key(d_candidate, expected_pubkey, expected_address)
                if result:
                    print(f"\n✅ [PAIR #{pair_id}] ZNALEZIONO! Δk = {dk:+7d}")
                    print(f"🔑 Klucz prywatny: {hex(d_candidate)[2:].zfill(64)}")
                    print(f"📬 Public key: {result[0]}")
                    print(f"🏠 Adres: {result[1]}")
                    return True
            except Exception as e:
                print(f"[PAIR #{pair_id}] Błąd dla Δk = {dk}: {e}")
                continue
    return False

# === Dane podpisów ===
pairs = [
    (
        int("dd9efc22a9a163256888145daa5e83b5a0bef572287cc7e85be1b91a5015e954", 16),
        int("34cbcf3d4f8bfc6a7ac772fcd98f4178e93c69875af7694fda5a2b7edac0bf19", 16),
        int("5913507aba81d25a26f3bed68d06ebe8d2daa78955e0e03d048aa85d6094b61e", 16),
        int("dda3a316431216fa866afd664e67f80409c46af362935d6c2f425cb264ebb46a", 16),
        int("06da2c33804a13bb854d51eb36e86d3618a20fe27437332761d144069f085aeb", 16),
        int("7804bd0d534c09729a498fbde1d2d5ad9891f4b567360d9e7489b0ce98dfb5eb", 16),
        "0244587bb17c3d845ae477a2fb2511ef7233e7b3e8f3ec6f83bd154be74c39bf66",
        "bc1qnsupj8eqya02nm8v6tmk93zslu2e2z8chlmcej"
    ),
    (
        int("f8d4eec0ea6539879941608c34511678a2a7142140b02f4bc0ebbef8777af0d5", 16),
        int("58b9c1315ea7baea4f34d7e7097f1ae250b6410e72c9bda421ccd0ea13d0b767", 16),
        int("bbb678c16c67b6593e1782b8022857c27fcb24af53e14751726d08a4b06b030a", 16),
        int("f8df0f5926437ed775351e20950dbccf4053d4ce0a8d7d164bd896f08a56b8cc", 16),
        int("018707664c13d277b397e84b0c9ca2943a72ef45683bc206de23ac7f2a764da3", 16),
        int("bedb2509de0b8826960bace2021a6f93e58d8bf91c7549942359f6bae4849c66", 16),
        "0244587bb17c3d845ae477a2fb2511ef7233e7b3e8f3ec6f83bd154be74c39bf66",
        "bc1qnsupj8eqya02nm8v6tmk93zslu2e2z8chlmcej"
    ),
    (
        int("817820331f3589cef0936f0d3681edd33aa322672b4631d61bba5541d6f91af1", 16),
        int("1830757681a905bd9ff64fd58959aaacb1b9a85ac80bedda71e672a955cb3284", 16),
        int("13b59264e228c6624b3b491bfcede5701cc4fe3301de959e772ee7e36a2819f4", 16),
        int("816f0d391a281c265d20e1b3597d51316524e4e1d4cfa13b7e577728ec92d52b", 16),
        int("58b48e65293f731ee22e25e9bc82e75247ad0574c9fd094275aee681fd9d1801", 16),
        int("bce509cb76619d234068379e13713e84112f41d47291cbfa4e428abe66bbf8c6", 16),
        "0244587bb17c3d845ae477a2fb2511ef7233e7b3e8f3ec6f83bd154be74c39bf66",
        "bc1qnsupj8eqya02nm8v6tmk93zslu2e2z8chlmcej"
    )
]

# === Równoległe uruchomienie ===
if __name__ == "__main__":
    print("🔍 Start równoległego bruteforce... (pełne logi, Δk od środka)")
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(recover_private_key, pair, i) for i, pair in enumerate(pairs)]
        for f in concurrent.futures.as_completed(futures):
            if f.result():
                print("✅ Przerwano pozostałe zadania.")
                break
