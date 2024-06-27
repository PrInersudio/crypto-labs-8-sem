from math import gcd as math_gcd

def gcd(nums: list) -> int:
    while len(nums) > 1:
        nums = [math_gcd(nums[0], nums[1])] + nums[2:]
    return nums[0]

xor = lambda a,b: bytes(_a^_b for _a,_b in zip(a,b))

def check_last_bytes(byte_obj):
    last_two_bytes = byte_obj[-2:]
    if last_two_bytes == b'\x00\x00': return True
    try: last_two_bytes.decode()
    except Exception: return False
    return True

ct = open("task2_0", "rb").read()
""" #output = open("output.txt", "wb")
for i in range(len(ct)-2):
    example = ct[i:i+2]
    shifts = []
    for j in range(len(ct)-2):
        if ct[j:j+2] == example:
            shifts.append(j+2)
    block_len = gcd(shifts)
    if block_len == 1: continue
    gamma = b'\x00' * (block_len - 2) + ct[i:i+2]
    ct_blocks = [ct[k:k+block_len] for k in range(0,len(ct),block_len)]
    pt_blocks = []
    for block in ct_blocks:
        pt_blocks.append(xor(gamma, block))
    if all(check_last_bytes(block) for block in pt_blocks): print(block_len, i, pt_blocks) """

block_len = 47
i = 45
gamma_start = b"\x1c\x07N\xba\xc4\xadf\xe5\xa0r\xd6\x97\xddh\x1b\x02\xfd\xc3\xe2\x00" + bytes([98, 39, 21, 171, 39, 251, 27, 183, 34, 202, 140, 42, 97, 145, 0x14, 0x86, 240, 0xe1, 134, 212, 91, 136, 82]) + b'.\x82'
print(len(gamma_start))
gamma_end = b'\x88\x1e'
gamma = gamma_start + b'\x00' * (block_len - len(gamma_start) - len(gamma_end)) + gamma_end
ct_blocks = [ct[k:k+block_len] for k in range(0,len(ct),block_len)]
print(len(ct_blocks[0]))
print(gamma)
print(len(gamma))
for block in ct_blocks:
    print(xor(gamma, block))