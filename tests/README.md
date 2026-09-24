# Tests

See [docs/TESTING.md](../docs/TESTING.md): the emulator, the suites in this
directory (unit, storage, profiles, openpgp, isolation), the upstream FIDO
suite in `pico-fido/tests`, and the hardware test notes.

The suites need a user-mode PC/SC stack (pcscd with the vsmartcard vpcd
driver) described by these environment variables, read by
`harness/emulator.py`: `PCSC_DIR`, `PCSCD_BIN`, `VPCD_DRIVER` (or
`VPCD_DRIVER_1SLOT`), `PCSCLITE_CSOCK_NAME`, and the emulator binary in
`LF_EMU_BIN`. Tests that need something missing are skipped with the reason.
