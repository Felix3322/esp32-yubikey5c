"""Host-side test harness for the LibreFido emulator build.

The emulator (ENABLE_EMULATION=1 build of pico_fido2) exposes:
  * CTAPHID over TCP 127.0.0.1:35962 (server, 2 byte length framing),
  * CCID as a vpcd client connecting to 127.0.0.1:35963 (pcscd + vpcd),
  * an optional user-presence control socket on 127.0.0.1:35970
    (LF_EMU_UP=manual, commands "down"/"up").
"""
