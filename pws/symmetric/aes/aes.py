from typing import List


from pws.symmetric.aes.error import AESError
from pws.symmetric.aes.state import AESState

from pws.symmetric.aes.key_schedule import generate_round_keys


def _check_params(block: bytes, key: bytes) -> None:
    
    if len(block) != 16:
        raise AESError(f"Raw AES can only process a 128-bit (= 16-byte) block: got a {len(block) * 8}-bit block.")
    
    if len(key) not in (16, 24, 32):
        raise AESError(f"Raw AES can only use a 128-, 192-, or 256-bit (= 16-, 24-, or 32-byte) key: got a {len(key) * 8}-bit key.")

    

def encrypt_raw(block: bytes, key: bytes) -> bytes:
    

    _check_params(block, key)

    round_keys = generate_round_keys(key)
    
    state = AESState(block)
    
    state.add_round_key(round_keys.pop(0))
    n_rounds = {16: 9, 24: 11, 36: 13}[len(key)]

    for _ in range(n_rounds):

        state.sub_bytes()
        state.shift_rows()
        state.mix_columns()
        state.add_round_key(round_keys.pop(0))

    state.sub_bytes()
    state.shift_rows()
    state.add_round_key(round_keys.pop(0))
    
    return bytes(state.block)

def decrypt_raw(block: bytes, key: bytes) -> bytes:
    
    _check_params(block, key)

    round_keys = generate_round_keys(key)

    state = AESState(block)

    state.add_round_key(round_keys.pop(-1))
     
    n_rounds = {16: 9, 24: 11, 36: 13}[len(key)]

    for _ in range(n_rounds):

        state.inv_shift_rows()
        state.inv_sub_bytes()
        state.add_round_key(round_keys.pop(-1))
        state.inv_mix_columns()

    state.inv_shift_rows()
    state.inv_sub_bytes()
    state.add_round_key(round_keys.pop(-1))

    return bytes(state.block)
