# Writeup of house(Detail)
## Inspiration
出题前刷了几个seccomp的pwn题，出题思路借鉴了我做的那个几个题。下面是刷的几个seccomp的题：
[2017 hitcon ctf 完美无瑕](https://ctf2017.hitcon.org/dashboard/) easy
[2015 32c3 ctf sandbox](https://github.com/ctfs/write-ups-2015/tree/master/32c3-ctf-2015/pwn/sandbox-300) medium-hard
[2016 33c3 ctf tea](https://github.com/ctfs/write-ups-2016/blob/master/33c3-ctf/pwn/tea-350/README.md) hard
[32C3 CTF ranger](https://kitctf.de/writeups/32c3ctf/ranger)
[2016 MMA CTF 2nd diary](https://github.com/ctfs/write-ups-2016/blob/master/mma-ctf-2nd-2016/pwn/diary-300/README.md) medium
[2017 BCTF boj](http://gcli.cn/2017/04/20/bctf2017boj/#step-1-escape-seccomp) hard

还有几个有助于分析seccomp的几个小工具，对做题很有帮助：
[seccomp-tools](https://github.com/david942j/seccomp-tools)
[libseccomp-scmp_bpf_disasm](https://github.com/seccomp/libseccomp/blob/master/tools/scmp_bpf_disasm.c)
在用seccomp-tools的过程中需要注意的是如果程序需要参数的话，可能就会分析失败。像下面这种情况：
```
seccomp-tools dump `./ranger 55555 127.0.0.1`
```
此时唯一的办法是在prctl函数设置断点，然后dump第三个指针参数相应长度的内存。
```
struct sock_filter {    /* Filter block */
       __u16    code;   /* Actual filter code */
       __u8     jt;     /* Jump true */
       __u8     jf;     /* Jump false */
       __u32    k;      /* Generic multiuse field */
};

struct sock_fprog {     /* Required for SO_ATTACH_FILTER. */
       unsigned short           len;    /* Number of filter blocks */
       struct sock_filter *filter;
};
```
需要dump的内存大小为：len * 8，可用gdb直接dump：
```
dump memory dumpfile filter filter+len*8 
```
然后用seccomp-tools反汇编即可：
```
seccomp-tools disasm dumpfile
```
例如：
```
dump memory dumpfile 0x00007fffffffe320 0x00007fffffffe320+8*8
root@w0lfzhang666:/home/w0lfzhang/Desktop/seccomp/chuti# seccomp-tools disasm dumpfile 
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x15 0x00 0x01 0x0000003b  if (A != execve) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x15 0x00 0x01 0x00000142  if (A != execveat) goto 0005
 0004: 0x06 0x00 0x00 0x00000000  return KILL
 0005: 0x15 0x00 0x01 0x00000039  if (A != fork) goto 0007
 0006: 0x06 0x00 0x00 0x00000000  return KILL
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```
这题用seccomp-tools只能dump父进程的bpf，子进程的bpf主要自己dump内存然后用seccomp-tools的disasm功能。

## Vulnerability
这个题的漏洞点在子进程函数中：
```
typedef struct file
{
	char filename[24];
	char *content;
}file;

puts("So man, what are you finding?");
count = read(0, file.filename, 40);
file.filename[count-1] = '\x0';
```
显而易见，读文件名的过程中可以溢出覆盖content指针，而函数又有往content内存写的功能：
```
puts("What do you want to give me?");
puts("content: ");
read(0, file.content, 0x200);
```
所以我们有了一个任意地址写的机会，但是往哪里写？
## Solution
写got表，但是程序的保护措施全开，got是只读的，放弃；写malloc_hook？但又能怎样，malloc函数只调用了一次，就算能控制返回地址使函数再一次执行，但是无法执行execve系统调用，放弃；所以此时唯一的办法是覆盖返回地址了，但是函数又是通过exit退出的，我们写谁的返回地址？而且前期是事先得泄露栈的地址。此时唯一的办法就是写read函数的返回地址：
```
read(0, file.content, 0x200);
```
此时我们可以rop了，但是子进程设置了系统调用白名单，我们无法获取shell。也许可以通过open->read->write系统调用来读flag，但是前期是你得知道flag文件名，而socket，recv，send等系统调用时不可用的。怎么办？
再来看看父进程的seccomp，父进程只是设置了一个黑名单，禁止了execve和fork系统调用。显然父进程的seccomp有漏洞：
```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x15 0x00 0x01 0x0000003b  if (A != execve) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x15 0x00 0x01 0x00000142  if (A != execveat) goto 0005
 0004: 0x06 0x00 0x00 0x00000000  return KILL
 0005: 0x15 0x00 0x01 0x00000039  if (A != fork) goto 0007
 0006: 0x06 0x00 0x00 0x00000000  return KILL
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```
父进程验证只是验证了系统调用号，此时我们可以通过x32abi来绕过seccomp。一般来说我们可以通过如下方法绕过64位seccomp黑名单的限制：
```
syscall(0x40000000 | sys_number, arg1, arg2, ...)
```
具体可参考x86_64的[系统调用表](http://elixir.free-electrons.com/linux/v3.19.8/source/arch/x86/syscalls/syscall_64.tbl)和linux的源码/usr/include/asm/unistd.h。但是execve的另一个64位系统调用号为520，可以不用上述方法直接与0x40000000位或。所以如果能执行520系统调用的话，我们也能拿到shell。(两种方法均可成功)
问题来了，我们可以通过子进程去覆盖父进程中waitpid函数的返回地址吗？因为此时父进程停在waitpid函数里，所以如果可以覆盖的话，一个rop就完事了。关键是怎么才能覆盖父进程中的返回地址。
如果我们可以直接修改父进程内存的话，那就可以通过rop打开/proc/ppid/mem文件，然后lseek到waitpid函数的返回地址那，然后再一次rop就行。一般来说子进程是无法修改父进程内存的，但是需要注意的是我用的是clone函数而不是fork函数，所以子进程和父进程是共享地址空间的。简单的来说，通过clone函数创建的实际上不是真正意义的进程，是界于线程和进程之间的轻量级进程。所以子进程对父进程地址空间的访问几乎没有限制。
现在整理下思路：
1. 通过/proc/self/status获取父进程的id。
2. 通过/proc/self/maps泄露父进程的栈地址，程序和libc的基地址，还有mmap地址。
3. 通过/proc/self/mem泄露子进程的栈地址，read和waitpid的返回地址。
4. 在子进程通过rop覆盖父进程中waitpid的返回地址。
5. 在父进程中rop获取shell。

获取shell有两种方式：
1. execute 520 system call or x32abi
2. switch the mode from 64bit to 32bit and execute 32bit shellcode 

第一种方法比较简单，第二种方法稍微麻烦一点，但是对64位seccomp黑名单的绕过更加通用。如果再把520号系统调用和x32abi的系统调用号过滤的话就只能用第二方法了。以下是用第二种方法绕过的试验结果：
```
w0lfzhang@w0lfzhang666:~/Desktop/seccomp/chuti$ python exp.py 
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/home/w0lfzhang/Desktop/seccomp/chuti/house'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process './house': pid 35909

[+] Got parent's pid:  35909
[+] Stage 1 finished!

[+] ELF adderss: 0x555555554000
[+] mmap address: 0x7fffe7a0d000
[+] Libc adderss: 0x7ffff7a0d000
[+] parent stack address: 0x7ffffffde000
[+] Stage 2 finished!

[+] Find child stack address.
[+] offset: 0x2f22a0
[+] child stack address: 0x7fffe7cff2a0
[+] ret_from_waitpid: 0x7fffffffdca8
[+] ret_from_read: 0x7fffe7cff208
[+] Stage 3 finished!

[.] Sending the first rop chain...

[.] Sending the second rop chain...

[.] Sending the first payload...

[.] Sending the second payload...

[*] Switching to interactive mode
$ echo *
1.py a.out combine.c core dumpfile exp.py fuck_sky_pwn_1.pptx house ld.so nsjail peda-session-a.out.txt peda-session-dash.txt peda-session-house.txt peda-session-tea.txt seccomp-bpf.h shell test.c this_is_flag
$ read -r line < this_is_flag
$ echo $line
flag{Bl4ck_4nd_Wh1te_5ecc0mp_4re_5tr0n9}
```
还有一点需要注意的是因为父进程ban了fork系统调用，所以cat等命令无法使用，只能通过shell的内置命令来读取flag。
```
echo *
read -r line < file
echo $line
```
这题没有过滤520及execve的x32abi的系统调用号，仅作为测试版。思前想后，最后我过滤掉了这两个系统调用，所以就只能用上述的方法来绕过了黑名单了~

## Links
[源码&exp]()
[Eigenstate : Seccomp Sandboxing](https://eigenstate.org/notes/seccomp)
[BPF(4)](https://www.freebsd.org/cgi/man.cgi?bpf(4))
[tea](https://github.com/ymgve/ctf-writeups/tree/master/33c3_ctf/pwn350-tea)


