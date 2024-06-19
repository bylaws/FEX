%ifdef CONFIG
{
  "HostFeatures": ["AES256"],
  "RegData": {
    "XMM1": ["0x777B7B777B7B7777", "0x7B77777B77777B7B", "0x777b7b777b7b7777", "0x7b77777b77777b7b"],
    "XMM2": ["0x8884848884848888", "0x8488888488888484", "0x8884848884848888", "0x8488888488888484"],
    "XMM3": ["0x777B7B767B7B7776", "0x7B77777A77777B7A", "0x777b7b767b7b7776", "0x7b77777a77777b7a"],
    "XMM4": ["0x888484887B7B7777", "0x7B77777A88888484", "0x888484887b7b7777", "0x7b77777a88888484"]
  }
}
%endif

lea rdx, [rel .data]

vmovaps ymm0, [rdx + 32 * 4]

vaesenclast ymm1, ymm0, [rdx + 32 * 0]
vaesenclast ymm2, ymm0, [rdx + 32 * 1]
vaesenclast ymm3, ymm0, [rdx + 32 * 2]
vaesenclast ymm4, ymm0, [rdx + 32 * 3]

hlt

align 32
.data:
dq 0x0000000000000000
dq 0x0000000000000000
dq 0x0000000000000000
dq 0x0000000000000000

dq 0xFFFFFFFFFFFFFFFF
dq 0xFFFFFFFFFFFFFFFF
dq 0xFFFFFFFFFFFFFFFF
dq 0xFFFFFFFFFFFFFFFF

dq 0x0000000100000001
dq 0x0000000100000001
dq 0x0000000100000001
dq 0x0000000100000001

dq 0xFFFFFFFF00000000
dq 0x00000001FFFFFFFF
dq 0xFFFFFFFF00000000
dq 0x00000001FFFFFFFF

dq 0x0202020202020202
dq 0x0303030303030303
dq 0x0202020202020202
dq 0x0303030303030303
