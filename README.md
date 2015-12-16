# Nfc
Example code and experiments on how to use Android NFC:
- Communicate with Mifare Desfire cards
- Work around Android resets when using a remote (slow) connection

References:
- libfreefare and nfc-tools (https://github.com/nfc-tools) for inspiration/"documentation" on Mifare Desfire commands and parameters
- (Issue 58773)[https://code.google.com/p/android/issues/detail?id=58773]: NFC presence check function has incorrect implementation, fix for a correct behavior proposed
- Thorbears's own implementation, using a Lopper: https://gist.github.com/Thorbear/f7c48e90d3e71bde13cb
