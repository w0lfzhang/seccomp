/*
* building command: gcc -fpie -pie -Wl,-z,relro,-z,now -o house house.c
*/

#define _GNU_SOURCE 1
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include "seccomp-bpf.h"
#include <sys/syscall.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sched.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <signal.h>

#define errExit(msg) perror(msg); exit(EXIT_FAILURE);

/*set blacklist*/
static int install_parent_syscall_filter(void);
/*set whitelist*/
static int install_child_syscall_filter(void);
void initialize(void);
int my_room(void *arg);
int filter_filename(char *filename);
int menu(void);
void alarm_handle(void);

typedef struct file
{
	char filename[24];
	char *content;
}file;

int main(int argc, char *argv[])
{
	initialize();

	puts("Welcome to my house! Enjoy yourself!\n");

	void *stack;
	unsigned long offset;
	char choice;
	pid_t pid;
	int status;
	int fd;

	puts("Do you want to help me build my room? Y/n?");
	read(0, &choice, 4);
	if ( choice == 'y' || choice == 'Y')
	{
		fd = open("/dev/urandom", O_RDONLY);
		if (fd < 0)
		{
			errExit("open");
		}
		read(fd, (char *)&offset, 8);
		close(fd);
		offset &= 0xFFFFF0;
		stack = mmap(0, 0x10000000, PROT_READ | PROT_WRITE, 
					 MAP_ANONYMOUS | MAP_STACK | MAP_PRIVATE, -1, 0);
		if( stack == (void *)-1LL )
		{
			errExit("mmap");
		}
		/*
		we can use a random number here.
		*/
		//printf("[debug] child stack: %p\n", stack + offset);
		pid = clone(my_room, stack + offset, CLONE_VM, NULL);
		if ( pid == -1 )
		{
			errExit("clone");
		}
		waitpid(pid, &status, __WCLONE);
		//printf("%x\n", __WCLONE);

		if( WIFEXITED(status) )
		{
			puts("\nBuild finished! Thanks a lot!");
		}
		else
		{
			puts("\nMaybe something wrong? Build failed!");
		}
	}
	else
	{
		puts("You don't help me? OK, just get out of my hosue!");
		//my_room(NULL);
		exit(EXIT_SUCCESS);
	}
	
	exit(EXIT_SUCCESS);
}

void alarm_handle(void)
{
	puts("time out...");
	exit(EXIT_SUCCESS);
}

void initialize(void)
{
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	alarm(0x20);
	signal(SIGALRM, (void *)alarm_handle);
	
	if ( install_parent_syscall_filter() )
	{
		exit(EXIT_FAILURE);
	}
	
}

int filter_filename(char *filename)
{
	if ( strstr(filename, "flag") ||
		 strstr(filename, "*") )
	{
		return 1;
	}

	return 0;
}

int menu(void)
{
	char str[8];
	puts("\n1.Find something  2.Locate yourself  3.Get something  4.Give something  5.Exit");
	read(0, str, 2);
	return atoi(str);
}

int my_room(void *arg)
{
	puts("You get into my room. Just find something!\n");
	char *p = (char *)malloc(100000);
	if ( !p )
	{
		errExit("malloc");
	}

	
	if( install_child_syscall_filter() )
	{
		exit(EXIT_FAILURE);
	}

	char str[32];
	memset(str, 32, 0);
	
	file file;
	file.content = p;
	int fd, count;
	int choice;
	unsigned long long seek;

	/* first we must make a conditon to leak stack address */
	int read_times = 0;
	
	while ( read_times < 30 )
	{
		choice = menu();
		switch( choice )
		{
			case 1:
				puts("So man, what are you finding?");
				count = read(0, file.filename, 40);
				file.filename[count-1] = '\x0';
				if ( filter_filename(file.filename) )
				{
					puts("Man, don't do it! See you^.");
					exit(EXIT_FAILURE);
				}
				fd = open(file.filename, O_RDONLY);
				if ( fd < 0 )
				{
					errExit("open");
				}
				break;

			case 2:
				puts("So, Where are you?");
				read(0, str, 32);
				seek = strtoull(str, 0, 10);
				lseek(fd, seek, SEEK_SET);
				break;

			case 3:
				puts("How many things do you want to get?");
				read(0, str, 8);
				count = atoi(str);
				if( count > 100000 )
				{
					puts("You greedy man!");
					break;
				}
				if( (count = read(fd, file.content, count)) < 0 )
				{
					puts("error read");
					errExit("read");
				}
				puts("You get something:");
				write(1, file.content, count);
				break;

			case 4:
				puts("What do you want to give me?");
				puts("content: ");
				read(0, file.content, 0x200);
				break;

			case 5:
				exit(EXIT_SUCCESS);

			default:
				break;
		}
		
		read_times += 1;
	}
	
	puts("\nI guess you don't want to say Goodbye!");
	puts("But sadly, bye! Hope you come again!\n");
	exit(EXIT_SUCCESS);
}


static int install_parent_syscall_filter(void)
{
	struct sock_filter filter[] = 
	{
		/* Validate architecture. */
		//hard, remove this
		//VALIDATE_ARCHITECTURE,
		/* Grab the system call number. */
		EXAMINE_SYSCALL,
		/* block syscalls. */
		BLOCK_SYSCALL(execve),
		/*x32 abi forbidden*/
		BLOCK_X32_EXECVE1,
		BLOCK_X32_EXECVE2,
		BLOCK_SYSCALL(execveat),
		BLOCK_SYSCALL(fork),
		ALLOW_PROCESS,
	};

	struct sock_fprog prog = 
	{
		.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
		.filter = filter,
	};

	if ( prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ) 
	{
		perror("prctl(NO_NEW_PRIVS)");
		goto failed;
	}
	if ( prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) ) 
	{
		perror("prctl(SECCOMP)");
		goto failed;
	}
	return 0;

failed:
	if ( errno == EINVAL )
	{
		fprintf(stderr, "SECCOMP_FILTER is not available. :(\n");
	}

	return 1;
}

static int install_child_syscall_filter(void)
{
	struct sock_filter filter[] = 
	{
		/* Validate architecture. */
		VALIDATE_ARCHITECTURE,
		/* Grab the system call number. */
		EXAMINE_SYSCALL,
		/* List allowed syscalls. */
		ALLOW_SYSCALL(exit_group),
		ALLOW_SYSCALL(exit),
		ALLOW_SYSCALL(read),
		ALLOW_SYSCALL(write),
		ALLOW_SYSCALL(lseek),
		ALLOW_SYSCALL(open),
		ALLOW_SYSCALL(close),
		ALLOW_SYSCALL(brk),
		KILL_PROCESS,
	};

	struct sock_fprog prog = 
	{
		.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
		.filter = filter,
	};

	if ( prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ) 
	{
		perror("prctl(NO_NEW_PRIVS)");
		goto failed;
	}
	if ( prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) ) 
	{
		perror("prctl(SECCOMP)");
		goto failed;
	}
	return 0;

failed:
	if ( errno == EINVAL )
	{
		fprintf(stderr, "SECCOMP_FILTER is not available. :(\n");
	}

	return 1;
}
