Here's the immunity call stack for send in firefox...
```
0BADF00D   ws2_32.send
0BADF00D       buffer pointer: 008b7c08, size: 664.
0BADF00D       ascii: GET /rss/newsonline_world_edition/front_page/rss.xml HTTP/1.1..Host: newsrss.bbc.co.uk..User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (.NET CLR 3.5.30729)..Accept: text/html,application/xht
0BADF00D       hex:   0x47 0x45 0x54 0x20 0x2f 0x72 0x73 0x73 0x2f 0x6e 0x65 0x77 0x73 0x6f 0x6e 0x6c 0x69 0x6e 0x65 0x5f 0x77 0x6f 0x72 0x6c 0x64 0x5
0BADF00D   Address: 0132fcd4 - Stack: 004fa76a - Procedure: <JMP.&WSOCK32.#19> - frame: 00000000 - called from: 004fa765
0BADF00D   Address: 0132fcd8 - Stack: 00000404 - Procedure:   Socket = 404 - frame: 00000000 - called from: 004fa765
0BADF00D   Address: 0132fcdc - Stack: 008b7c08 - Procedure:   Data = 008B7C08 - frame: 00000000 - called from: 004fa765
0BADF00D   Address: 0132fce0 - Stack: 00000298 - Procedure:   DataSize = 298 (664.) - frame: 00000000 - called from: 004fa765
0BADF00D   Address: 0132fce4 - Stack: 00000000 - Procedure:   Flags = 0 - frame: 00000000 - called from: 004fa765
0BADF00D   Address: 0132fcfc - Stack: 004f44f3 - Procedure: nspr4.004FA730 - frame: 00000000 - called from: 004f44ee
0BADF00D   Address: 0132fd28 - Stack: 004f4558 - Procedure: nspr4.004F4450 - frame: 00000000 - called from: 004f4553
0BADF00D   Address: 0132fd40 - Stack: 10008b08 - Procedure: nspr4.PR_Write - frame: 00000000 - called from: 10008b02
```



By hand:
```
0x4FA765 is the call to send ...... 0x4FA7F5: ret
0x4F44F3: call 0x4FA730 ........... 0x4F453E: ret
0x4F4558: call 0x4F4450 ...........

```