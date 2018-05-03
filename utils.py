import codecs

default_coding_list = ["ascii", "utf_8", "gb2312", "gbk", "gb18030", "big5", "big5hkscs", "utf_16", "utf_16_be",
                       "utf_16_le", "utf_7"]


# true default: ["ascii", "big5", "big5hkscs", "cp037", "cp424", "cp437", "cp500", "cp737", "cp775", "cp850", "cp852", "cp855", "cp856", "cp857", "cp860", "cp861", "cp862", "cp863", "cp864", "cp865", "cp866", "cp869", "cp874", "cp875", "cp932", "cp949", "cp950", "cp1006", "cp1026", "cp1140", "cp1250", "cp1251", "cp1252", "cp1253", "cp1254", "cp1255", "cp1256", "cp1257", "cp1258", "euc_jp", "euc_jis_2004", "euc_jisx0213", "euc_kr", "gb2312", "gbk", "gb18030", "hz", "iso2022_jp", "iso2022_jp_1", "iso2022_jp_2", "iso2022_jp_2004", "iso2022_jp_3", "iso2022_jp_ext", "iso2022_kr", "latin_1", "iso8859_2", "iso8859_3", "iso8859_4", "iso8859_5", "iso8859_6", "iso8859_7", "iso8859_8", "iso8859_9", "iso8859_10", "iso8859_13", "iso8859_14", "iso8859_15", "johab", "koi8_r", "koi8_u", "mac_cyrillic", "mac_greek", "mac_iceland", "mac_latin2", "mac_roman", "mac_turkish", "ptcp154", "shift_jis", "shift_jis_2004", "shift_jisx0213", "utf_16", "utf_16_be", "utf_16_le", "utf_7", "utf_8"]


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


def uni_decode(buff, preferred_coding_list=None):
    if preferred_coding_list is None:
        preferred_coding_list = []
    for coding_name in preferred_coding_list + default_coding_list:
        try:
            s = codecs.decode(buff, coding_name)
            return s
        except Exception as e:
            pass
    return codecs.encode(b"\xff", "hex_codec")


def get_enum_from_value(cls, v):
    try:
        enum_obj = cls(v)
    except ValueError:
        return v
    return enum_obj
