# OpenCore UEFI Secure Boot

An attempt to achieve OpenCore UEFI Secure Boot. This will allow OpenCore run in UEFI Secure Boot mode.

## Operating System

This script should be run on Linux.

## Modules needed

These modules collectively facilitate various operations such as file manipulation, HTTP requests, process management, and cryptographic operations necessary for the tasks performed by the script, including certificate generation, file downloading, directory management, and OpenCore package manipulation. Please install all module via "pip".

- **hashlib** - Provides secure hash and message digest algorithms.
- **json** - Encoding and decoding JSON data.
- **os** - Interacting with the operating system.
- **pathlib** - Represents filesystem paths with platform-independent semantics.
- **requests** - Sending HTTP requests.
- **shutil** - High-level file operations.
- **subprocess** - Spawning new processes and running shell commands.
- **urllib.parse** - Parsing URLs.
- **urllib.request** - Opening URLs.
- **zipfile** - Creating, reading, writing, and extracting ZIP files.

## Other requirement

These are requirement for signing all drivers / tools

- **efitools** - This dependency is used for handling EFI signatures and related operations, such as generating EFI Signature Lists (ESL) and signing EFI files. It's a critical component for UEFI Secure Boot support. However, its availability and installation process may vary depending on the operating system.
- **openssl** - Used for certificate generation and cryptographic operations. It's a widely-used library for secure communication and cryptographic functions.
- **curl** - Utility used for downloading files from URLs. It's a versatile command-line tool for transferring data with URLs. Similar to the other dependencies.
- **sbctl** - Tool that allows one to create keys for secure boot, securely enroll them and keep track of files to sign.

### How to run?

Step is quite simple. All will automaticaly generate random uuid, downloading latest OpenCore Package and signed all drivers / tools.

1. Launch on terminal:

   ```shell
   sh secureboot.sh
   ```

2. This notification will appear:

   ```shell
   Choose an option:
   1. Generate all keys, download and Signing OpenCore Package
   2. Signing Current systemd-boot
   3. Exit
   Enter your choice: 1
   ----------------------------------------------------------------------------
   OpenCore with UEFI Secureboot Support
   ----------------------------------------------------------------------------

       Warning:
       * This tool is intended for users with multiple operating systems who are using OpenCore as the chain loader.
       * The implementations of secure boot may vary on Windows, macOS, and Linux.
       * It is clear that you are aware of what you are supposed to do.
   ```

3. Choose `1` to generate required keys and Signing OpenCore Package.

   ```shell
   ----------------------------------------------------------------------------
   Generating OpenCore Secure Boot UUID
   ----------------------------------------------------------------------------
   Generated UUID: 8d2d972d-1553-4cdc-bf7d-a7fd38cb880a
   ----------------------------------------------------------------------------
   Generating Certifcates
   ----------------------------------------------------------------------------
   Press '1' for default certificate or '2' for custom certificate: 1
   Certificate details:
   Country: US
   State: California
   Locality: Cupertino
   Organization: Dortania
   Common Name: OpenCore
   Generating PK
   Generating PK successful.
   SHA1: 501a47ed1dcaa90533e10e0ebc14d767832f3b51, MD5: a7b0cc3c3e9b1563c1e05aa322abdf8a for file: keys/PK.auth
   SHA1: 8d91161a8673f5178b02a62c11093ff5c29fc63d, MD5: 32521227ee2b894ecd66348b3f49f17e for file: keys/PK.crt
   SHA1: 66e1b6bb888d0a7fc0fdff7eb4139ba8ddaf539a, MD5: ef05abe82c4c8adf009ca50cd5df7ca7 for file: keys/PK.esl
   SHA1: 25ab98ab986650f0bf59ce016e63365cef4399ff, MD5: e10a7b9056d7d6bde2adcf9b88825b53 for file: keys/PK.key
   Generating noPK
   Generating noPK successful.
   SHA1: 71fd122a89fce7c5c260f38b4b5f7486cfc7aa52, MD5: c12964cc03f8b3c7e5e431eabdb7127a for file: keys/noPK.auth
   Skipping keys/noPK.crt
   Skipping keys/noPK.esl
   Skipping keys/noPK.key
   Generating KEK
   Generating KEK successful.
   SHA1: 8528585fdc73420152ff1d053acbe9051e9f61c3, MD5: 92b93b20a009ed7821ed17f143ccbba4 for file: keys/KEK.auth
   SHA1: a533db4970ebecfcc5fac58140d9a73d06318b2f, MD5: 15dd2a246bda64bacfa2be8685499035 for file: keys/KEK.crt
   SHA1: 065a8db3c7d9894a500694bc38dec1d7b2c6425a, MD5: c584fa78f8c8320e2722922cea2d8a4a for file: keys/KEK.esl
   SHA1: 1af7a5225950798a8392c37083f899abb062f2d3, MD5: a41469b2ac9c8d0d9da4cc016805acf1 for file: keys/KEK.key
   Generating db
   Generating db successful.
   SHA1: 2a19c0e8d952acc70d8f78ad5e6669fe8cc8ff0c, MD5: cdebd3790503affc961c396e95a2a99c for file: keys/db.auth
   SHA1: 011f8e9b864762ef98c60e96a86f84218a09bb74, MD5: 28c932b4a487f30f6ae0e5be3e78da3c for file: keys/db.crt
   SHA1: 52b628d792e5be04d8ed386d74f4cee3ec6c11e1, MD5: 893cca039e31fb3f5246b78541ff4964 for file: keys/db.esl
   SHA1: 94ade7a606557b88867b5a028a19975b7858e1bc, MD5: 4590f1138f01992cadb58d51630a3a7b for file: keys/db.key
   ----------------------------------------------------------------------------
   Changing Key Permission
   ----------------------------------------------------------------------------
   Changing permission:
   .: db.auth, db.cer, db.crt, db.esl, db.key, KEK.auth, KEK.cer, KEK.crt, KEK.esl, KEK.key, noPK.auth, PK.auth, PK.cer, PK.crt, PK.esl, PK.key
   Permission changed
   ----------------------------------------------------------------------------
   Downloading MS Certificates
   ----------------------------------------------------------------------------
   Downloaded Microsoft Windows Production PCA 2011.crt - SHA1: 580a6f4cc4e4b669b9ebdc1b2b3e087b80d0678d
   Downloaded Windows UEFI CA 2023.crt - SHA1: 45a0fa32604773c82433c3b7d59e7466b3ac0c67
   Downloaded Microsoft Corporation UEFI CA 2011.crt - SHA1: 46def63b5ce61cf8ba0de2e6639c1019d0ed14f3
   Downloaded Microsoft UEFI CA 2023.crt - SHA1: b5eeb4a6706048073f0ed296e7f580a790b59eaa
   Downloaded Microsoft Corporation KEK CA 2011.crt - SHA1: 31590bfd89c9d74ed087dfac66334b3931254b30
   Downloaded Microsoft Corporation KEK 2K CA 2023.crt - SHA1: 459ab6fb5e284d272d5e3e6abc8ed663829d632b
   MS keys downloaded and saved successfully
   Files renamed and spaces replaced
   ----------------------------------------------------------------------------
   Creating EFI Signature Format
   ----------------------------------------------------------------------------
   MS Keys: 77fa9abd-0359-4d32-bd60-28f4e78f784b
   Microsoft db.esl generate success
   Microsoft Windows KEK.esl generate success
   Timestamp is 0-0-0 00:00:00
   Authentication Payload size 6173
   Signature of size 2205
   Signature at: 40
   Additional Microsoft db.auth generate success
   Timestamp is 0-0-0 00:00:00
   Authentication Payload size 3108
   Signature of size 2193
   Signature at: 40
   Additional Microsoft Windows KEK.auth generate success
   ----------------------------------------------------------------------------
   Checking and Downloading Latest OpenCore Package.
   ----------------------------------------------------------------------------
   Latest OpenCore release available: 0.9.8
   Do you want to download the latest release? (yes/no): yes
     % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                    Dload  Upload   Total   Spent    Left  Speed
     0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
   100 7923k  100 7923k    0     0  5033k      0  0:00:01  0:00:01 --:--:-- 40.4M
   OpenCore 0.9.8 downloaded, extracted, and zip file deleted.
   EFI dir moved successfully.
   Cleaning OpenCore dir
   HFSPlus.efi downloaded
   ----------------------------------------------------------------------------
   Signing OpenCore Package.
   ----------------------------------------------------------------------------
   Signing successful for XXXXX.efi in oc/EFI/OC
   SHA1: 2410b2705d937b6bb7007d7a5b5a0ea1b2cd69db, MD5: 9777362cb7eb1d0b3eebc0b396a5fbfe for XXXXX.efi
   Verification output:
   signature 1
   image signature issuers:
    - /C=US/ST=California/L=Cupertino/O=Dortania/CN=OpenCore Authorized Signature Database Key
   image signature certificates:
    - subject: /C=US/ST=California/L=Cupertino/O=Dortania/CN=OpenCore Authorized Signature Database Key
      issuer:  /C=US/ST=California/L=Cupertino/O=Dortania/CN=OpenCore Authorized Signature Database Key
   ```

### BIOS

Go to bios, find secureboot option, delete current keys and...

1. Enroll db.auth and Additional Microsoft db.auth for Authorized Signature Database option.
2. Enroll KEK.auth and Additional Microsoft Windows KEK.auth for Key Exchange Key option.
3. Enroll PK.auth for Platform Key.
4. Enable secureboot and restart.
   > Note: By enroll PK.auth will change secureboot mode from setup to user. As an alternative, use noPK.auth to clear all secure boot keys,

### Additional

Additionally, this tools allow user to sign systemd-boot. Please read properly the notification when launch option `2`.

## Credits

[Archlinux](https://archlinux.org/) | [Acidanthera](https://github.com/acidanthera)
