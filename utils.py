def string2hexip(s):
    return ':'.join(['%02x' % c for c in s])


def hex2stringip(s):
    return ''.join([chr(int(c, 16)) for c in s.split(':')])


def get_i_from_raw_bytes(s, start_pos=0, end_pos=0, reverse_bytes=False):
    ans = 0
    if end_pos <= 0:
        end_pos = len(s) * 8 + end_pos
    if reverse_bytes:
        s = bytearray(s)
        s.reverse()
    for i in range(start_pos // 8, (end_pos + 7) // 8):
        ans <<= 8
        lbits = max(0, start_pos - i * 8)
        rbits = min(end_pos - i * 8, 8)
        bitcnt = rbits - lbits
        bitmask = ((1 << bitcnt) - 1) << (8 - rbits)
        ans += (s[i] & bitmask) >> (8 - rbits)
    return ans


def get_b_from_raw_bytes(s, pos):
    ind = pos // 8
    r = 7 - pos % 8
    return (s[ind] & (1 << r)) != 0