/*
isolatebit:
        get the value bit-11 ~ bit-5 in AX and store the result in val1
        (zero-based bit index)
======
      val1 @ 0x600000-600001
      val2 @ 0x600001-600002
======
*/
;1111 1110 0000
and ax, 0b111111100000
shr ax, 5
mov [0x600000], al