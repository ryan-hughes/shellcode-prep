Shellcodeprep is a handy Python script for converting shellcode .bin files to various formats, optionally applying an XOR encryption key, for easy copy/paste into shellcode loaders or stagers. Also handy for OSEP!

## Supported Output Formats
- vba
- cpp
- csharp
- ps
- base64
- bin

## Usage

    shellcode-prep % python3 shellcodeprep.py -h
        usage: shellcodeprep.py [-h] -i FILENAME -f STRING [-v STRING] [-x KEY] [-o FILENAME]

        -h, --help                          show this help message and exit
        -i FILENAME, --input FILENAME       File containing shellcode example: --input shellcode.bin
        -f STRING, --format STRING          Format, e.g. --format vba|cpp|csharp|ps|base64|bin
        -v STRING, --variable STRING        Name of the shellcode variable. Default: code
        -x KEY, --xor KEY                   XOR Key, e.g. --xor yourkeyhere
        -o FILENAME, --out FILENAME         File to output e.g. --out enc.txt

    shellcode-prep % python3 shellcodeprep.py --input /tmp/beacon.bin --format cpp --variable NotShellcode --xor myxorkey --out /tmp/beacon.txt
        Shellcode written to: /tmp/beacon.txt

    shellcode-prep % cat /tmp/beacon.txt
        unsigned char NotShellcode[] = {0xfd,0xe9,0xe8,0x22,0x28...