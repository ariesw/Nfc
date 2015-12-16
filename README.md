# Nfc
Example code and experiments on how to use Android NFC:
- Communicate with Mifare Desfire cards
- Work around Android resets when using a remote (slow) connection

---

WARNING: this code is only an example, does little to no error checking, and it is for information and educational purposes only.
The "remote" (i.e. slow coupler) example uses a raw java thread, "strong" references, fixed timeouts, no checks, etc... 
Thorbear's solution is much better, I would recommend to use something similar in production.

---

References:
- libfreefare and nfc-tools (https://github.com/nfc-tools) for inspiration/"documentation" on Mifare Desfire commands and parameters
- (Issue 58773)[https://code.google.com/p/android/issues/detail?id=58773]: NFC presence check function has incorrect implementation, fix for a correct behavior proposed
- Thorbears's own implementation, using a Lopper: https://gist.github.com/Thorbear/f7c48e90d3e71bde13cb
