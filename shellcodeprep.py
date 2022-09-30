import sys
import argparse
import base64

parser = argparse.ArgumentParser(description="", epilog="", formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-i", "--input", metavar="FILENAME", required=True, help="File containing shellcode example: --input shellcode.bin")
parser.add_argument("-f", "--format", metavar="STRING", required=True, help="Format, e.g. --format vba|cpp|csharp|ps|base64|bin")
parser.add_argument("-v", "--variable", metavar="STRING", required=False, default="code", help="Name of the shellcode variable. Default: code")
parser.add_argument("-x", "--xor", metavar="KEY", required=False, help="XOR Key, e.g. --xor yourkeyhere")
parser.add_argument("-o", "--out", metavar="FILENAME", required=False, help="File to output e.g. --out enc.txt")

args = parser.parse_args()
_file = args.input
_format = args.format
_key = args.xor
_outfile = args.out
_variable = args.variable

def xor(data, key):    
    key = bytearray(key.encode())
    output_str = ""

    for i in range(len(data)):
        current = data[i]
        current_key = key[i % len(key)]
        output_str += chr(current ^ current_key)
    
    return output_str

def xor_bin(data, key):
    arr = bytearray()
    key = bytearray(key.encode())

    for i in range(len(bytearray(data))):
        current = data[i]
        current_key = key[i % len(key)]
        outbyte = current ^ current_key
        arr.append(outbyte)

    return arr

try:
    plaintext = open(_file, "rb").read()
except:
    print("ERROR: Issue reading shellcode file! Check your path.")
    sys.exit()

outputText = ""
cipherText = ""

if _key:
    if _format == "bin":
        ciphertext = xor_bin(plaintext, _key)
    else:
        ciphertext = xor(plaintext, _key)
else:
    ciphertext = plaintext

if _format == "cpp":
    outputText += "unsigned char " + _variable + "[] = "
    if _key:
        outputText += '{0x' + ',0x'.join(hex(ord(x))[2:] for x in ciphertext) + '};'
    else:
        outputText += '{0x' + ',0x'.join(hex(x)[2:] for x in ciphertext) + '};'
elif _format == "csharp":
    outputText += "byte[] " + _variable + " = new byte[" + str(len(ciphertext)) + "] "
    if _key:
        outputText += '{0x' + ',0x'.join(hex(ord(x))[2:] for x in ciphertext) + '};'
    else:
        outputText += '{0x' + ',0x'.join(hex(x)[2:] for x in ciphertext) + '};'
elif _format == "vba":
    outputText += _variable + " = Array("
    if _key:
        for x in ciphertext:
            outputText += str(ord(x)) + ","
        outputText = outputText.rstrip(outputText[-1])
    else:
        for x in ciphertext:
            outputText += str(x) + ","
        outputText = outputText.rstrip(outputText[-1])
    outputText += ")"
elif _format == "ps":
    outputText += "[Byte[]] $"+ _variable + " = "
    if _key:
        outputText += '0x' + ',0x'.join(hex(ord(x))[2:] for x in ciphertext)
    else:
        outputText += '0x' + ',0x'.join(hex(x)[2:] for x in ciphertext)
elif _format == "base64":
    if _key:
        outputText = base64.b64encode(ciphertext.encode())
    else:
        outputText = base64.b64encode(ciphertext)
    outputText = str(outputText)
    outputText = outputText.replace("b'","").replace("'", "").replace("\n", "")
elif _format == "bin":
    if _key:
        outputText = bytes(ciphertext)
    else:
        outputText = bytes(ciphertext)
else:
    print("ERROR: Format not recognized. Supported formats: vba, cpp, csharp, ps, base64, bin")
    sys.exit()

if _outfile:
    if _format == "bin":
        file = open(_outfile, "wb")
    else:
        file = open(_outfile, "w")
    file.write(outputText)
    file.close()
    print("Shellcode written to: " + _outfile)
else:
    print(outputText)