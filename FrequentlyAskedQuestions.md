## Frequently Asked Questions ##


---


_How can I determine a convenient timeout to wait for ICP replies?_

**Increase the loglevel to 2 or higher, and check for a line in the modules logfile such as:**

`Recieved UDP datagram with 115 bytes from 192.168.0.1:0 after 224 microseconds`

**use a timeout which is slightly higher than the measured time.**


---