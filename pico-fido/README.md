# Pico FIDO
This project transforms your Raspberry Pi Pico or ESP32 microcontroller into an integrated FIDO Passkey, functioning like a standard USB Passkey for authentication.

If you are looking for a OpenPGP + Fido, see: https://github.com/librekeys/pico-fido2.

This is a fork of the community edition of the project located at https://github.com/polhenarejos/pico-fido  
For licensing information, see the LICENSE file

## Features
Pico FIDO includes the following features:

- CTAP 2.1 / CTAP 1
- WebAuthn
- U2F
- HMAC-Secret extension
- CredProtect extension
- User presence enforcement through physical button
- User verification with PIN
- Discoverable credentials (resident keys)
- Credential management
- ECDSA and EDDSA authentication
- Support for SECP256R1, SECP384R1, SECP521R1, SECP256K1 and Ed25519 curves
- App registration and login
- Device selection
- Support for vendor configuration
- Backup with 24 words
- Secure lock to protect the device from flash dumps
- Permissions support (MC, GA, CM, ACFG, LBW)
- Authenticator configuration
- minPinLength extension
- Self attestation
- Enterprise attestation
- credBlobs extension
- largeBlobKey extension
- Large blobs support (2048 bytes max)
- OATH (based on YKOATH protocol specification)
- TOTP / HOTP
- Yubikey One Time Password
- Challenge-response generation
- Emulated keyboard interface
- Button press generates an OTP that is directly typed
- Yubico Authenticator app compatible
- Yubico YKMAN compatible
- Nitrokey nitropy and nitroapp compatible
- Secure Boot and Secure Lock in RP2350 and ESP32-S3 MCUs
- One Time Programming to store the master key that encrypts all resident keys and seeds.
- Rescue interface to allow recovery of the device if it becomes unresponsive or undetectable.
- LED customization with PicoKey App.

All features comply with the specifications. If you encounter unexpected behavior or deviations from the specifications, please open an issue.

## Security Considerations
Microcontrollers RP2350 and ESP32-S3 are designed to support secure environments when Secure Boot is enabled, and optionally, Secure Lock. These features allow a master key encryption key (MKEK) to be stored in a one-time programmable (OTP) memory region, which is inaccessible from outside secure code. This master key is then used to encrypt all private and secret keys on the device, protecting sensitive data from potential flash memory dumps.

**However**, the RP2040 microcontroller lacks this level of security hardware, meaning that it cannot provide the same protection. Data stored on its flash memory, including private or master keys, can be easily accessed or dumped, as encryption of the master key itself is not feasible. Consequently, if an RP2040 device is stolen, any stored private or secret keys may be exposed.

## Build for Raspberry Pico
Before building, ensure you have installed the toolchain for the Pico and that the Pico SDK is properly located on your drive.

```sh
git clone https://github.com/librekeys/pico-fido
git submodule update --init --recursive
cd pico-fido
mkdir build
cd build
PICO_SDK_PATH=/path/to/pico-sdk cmake .. -DPICO_BOARD=board_type -DUSB_VID=0x1D50 -DUSB_PID=0x619B
make
```
Note that `PICO_BOARD`, `USB_VID` and `USB_PID` are optional. If not provided, `pico` board and VID/PID `1D50:619B` will be used.


Additionally, you can pass the `VIDPID=value` parameter to build the firmware with a known VID/PID. The supported values are:

- `NitroHSM`
- `NitroFIDO2`
- `NitroStart`
- `NitroPro`
- `Nitro3`
- `Yubikey5`
- `YubikeyNeo`
- `YubiHSM`
- `Gnuk`
- `GnuPG`

You can use whatever VID/PID for your own personal use. **But remember that you are not authorized to distribute the binary with a VID/PID that you do not own.**
The VID/PID `1D50:619B` is provided to the project by [OpenMoko](https://wiki.openmoko.org/wiki/USB_Product_IDs). It can only be used for builds distributed under a free and open source license.

After running `make`, the binary file `pico_fido.uf2` will be generated. To load this onto your Pico board:

1. Put the Pico board into loading mode by holding the `BOOTSEL` button while plugging it in.
2. Copy the `pico_fido.uf2` file to the new USB mass storage device that appears.
3. Once the file is copied, the Pico mass storage device will automatically disconnect, and the Pico board will reset with the new firmware.
4. A blinking LED will indicate that the device is ready to work.

To configure your device you can use the [picoforge desktop application ](https://github.com/librekeys/picoforge).

## Led blink
Pico FIDO uses the led to indicate the current status. Four states are available:
### Press to confirm
The Led is almost on all the time. It goes off for 100 miliseconds every second.

![Press to confirm](https://user-images.githubusercontent.com/55573252/162008917-6a730eac-396c-44cc-890e-802294be30a3.gif)

### Idle mode
In idle mode, the Pico FIDO goes to sleep. It waits for a command and it is awaken by the driver. The Led is almost off all the time. It goes on for 500 milliseconds every second.

![Idle mode](https://user-images.githubusercontent.com/55573252/162008980-d5a5caad-072e-400c-98e3-2c606b4b2af9.gif)

### Active mode
In active mode, the Pico FIDO is awaken and ready to receive a command. It blinks four times in a second.

![Active](https://user-images.githubusercontent.com/55573252/162008997-1ea8cd7e-5384-4893-9dcb-b473153fc375.gif)

### Processing
While processing, the Pico FIDO is busy and cannot receive additional commands until the current is processed. In this state, the Led blinks 20 times in a second.

![Processing](https://user-images.githubusercontent.com/55573252/162009007-df45111e-2473-4a92-97c5-15c3cd19babd.gif)

## Driver

Pico FIDO uses the `HID` driver, which is present in all operating systems. It should be detected by all OS and browser/applications just like normal USB FIDO keys.

## Tests

Tests can be found in the `tests` folder. They are based on [FIDO2 tests](https://github.com/solokeys/fido2-tests "FIDO2 tests") from Solokeys but adapted to the [python-fido2](https://github.com/Yubico/python-fido2 "python-fido2") v1.0 package, which is a major refactor from the previous 0.8 version and includes the latest improvements from CTAP 2.1.

To run all tests, use:

```sh
pytest
```

To run a subset of tests, use the `-k <test>` flag:

```sh
pytest -k test_credprotect
```

## License

This project is released under the GNU Affero General Public License v3 (AGPLv3).
A copy of the AGPLv3 license is available in the `LICENSE` file.

## Credits
This project uses libraries and portion of code from other projects that are detailed in the `LICENSE` file.

