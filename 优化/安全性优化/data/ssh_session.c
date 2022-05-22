//SSH/sshconnect.c/ssh_session

void specify_checks()
{
	check_null();
	check_buffer();
}










#include <stdlib.h>

#define FD_SET ignore
#define FD_ISSET ignore

#  define NI_MAXHOST      1025
#  define NI_MAXSERV      32
# define _PATH_BSHELL "/bin/sh"
#define SIZE_T_MAX 10000

#define SSH_VERSION	"OpenSSH_5.3"

#define RP_ECHO			0x0001
#define RP_ALLOW_STDIN		0x0002
#define RP_ALLOW_EOF		0x0004
#define RP_USE_ASKPASS		0x0008

typedef int MD5_CTX;

#define RDRW	0
#define RDONLY	1
#define ROQUIET	2

#define	EINVAL		22	/* Invalid argument */
#define	ENOTTY		25	/* Not a typewriter */

#define SSH_MSG_MIN				1
#define SSH_MSG_MAX				254
/* Message name */			/* msg code */	/* arguments */
#define SSH_MSG_NONE				0	/* no message */
#define SSH_MSG_DISCONNECT			1	/* cause (string) */
#define SSH_SMSG_PUBLIC_KEY			2	/* ck,msk,srvk,hostk */
#define SSH_CMSG_SESSION_KEY			3	/* key (BIGNUM) */
#define SSH_CMSG_USER				4	/* user (string) */
#define SSH_CMSG_AUTH_RHOSTS			5	/* user (string) */
#define SSH_CMSG_AUTH_RSA			6	/* modulus (BIGNUM) */
#define SSH_SMSG_AUTH_RSA_CHALLENGE		7	/* int (BIGNUM) */
#define SSH_CMSG_AUTH_RSA_RESPONSE		8	/* int (BIGNUM) */
#define SSH_CMSG_AUTH_PASSWORD			9	/* pass (string) */
#define SSH_CMSG_REQUEST_PTY			10	/* TERM, tty modes */
#define SSH_CMSG_WINDOW_SIZE			11	/* row,col,xpix,ypix */
#define SSH_CMSG_EXEC_SHELL			12	/* */
#define SSH_CMSG_EXEC_CMD			13	/* cmd (string) */
#define SSH_SMSG_SUCCESS			14	/* */
#define SSH_SMSG_FAILURE			15	/* */
#define SSH_CMSG_STDIN_DATA			16	/* data (string) */
#define SSH_SMSG_STDOUT_DATA			17	/* data (string) */
#define SSH_SMSG_STDERR_DATA			18	/* data (string) */
#define SSH_CMSG_EOF				19	/* */
#define SSH_SMSG_EXITSTATUS			20	/* status (int) */
#define SSH_MSG_CHANNEL_OPEN_CONFIRMATION	21	/* channel (int) */
#define SSH_MSG_CHANNEL_OPEN_FAILURE		22	/* channel (int) */
#define SSH_MSG_CHANNEL_DATA			23	/* ch,data (int,str) */
#define SSH_MSG_CHANNEL_CLOSE			24	/* channel (int) */
#define SSH_MSG_CHANNEL_CLOSE_CONFIRMATION	25	/* channel (int) */
/*      SSH_CMSG_X11_REQUEST_FORWARDING		26	   OBSOLETE */
#define SSH_SMSG_X11_OPEN			27	/* channel (int) */
#define SSH_CMSG_PORT_FORWARD_REQUEST		28	/* p,host,hp (i,s,i) */
#define SSH_MSG_PORT_OPEN			29	/* ch,h,p (i,s,i) */
#define SSH_CMSG_AGENT_REQUEST_FORWARDING	30	/* */
#define SSH_SMSG_AGENT_OPEN			31	/* port (int) */
#define SSH_MSG_IGNORE				32	/* string */
#define SSH_CMSG_EXIT_CONFIRMATION		33	/* */
#define SSH_CMSG_X11_REQUEST_FORWARDING		34	/* proto,data (s,s) */
#define SSH_CMSG_AUTH_RHOSTS_RSA		35	/* user,mod (s,mpi) */
#define SSH_MSG_DEBUG				36	/* string */
#define SSH_CMSG_REQUEST_COMPRESSION		37	/* level 1-9 (int) */
#define SSH_CMSG_MAX_PACKET_SIZE		38	/* size 4k-1024k (int) */
#define SSH_CMSG_AUTH_TIS			39	/* we use this for s/key */
#define SSH_SMSG_AUTH_TIS_CHALLENGE		40	/* challenge (string) */
#define SSH_CMSG_AUTH_TIS_RESPONSE		41	/* response (string) */
#define SSH_CMSG_AUTH_KERBEROS			42	/* (KTEXT) */
#define SSH_SMSG_AUTH_KERBEROS_RESPONSE		43	/* (KTEXT) */
#define SSH_CMSG_HAVE_KERBEROS_TGT		44	/* credentials (s) */
#define SSH_CMSG_HAVE_AFS_TOKEN			65	/* token (s) */

/*
 * Authentication methods.  New types can be added, but old types should not
 * be removed for compatibility.  The maximum allowed value is 31.
 */
#define SSH_AUTH_RHOSTS		1
#define SSH_AUTH_RSA		2
#define SSH_AUTH_PASSWORD	3
#define SSH_AUTH_RHOSTS_RSA	4
#define SSH_AUTH_TIS		5
#define SSH_AUTH_KERBEROS	6
#define SSH_PASS_KERBEROS_TGT	7
				/* 8 to 15 are reserved */
#define SSH_PASS_AFS_TOKEN	21

/* Unsigned.  */
typedef unsigned char		uint8_t;
typedef unsigned short int	uint16_t;
typedef unsigned int		uint32_t;
typedef unsigned long int	uint64_t;

#define SSH2_MSG_USERAUTH_REQUEST			50
#define SSH2_MSG_USERAUTH_FAILURE			51
#define SSH2_MSG_USERAUTH_SUCCESS			52
#define SSH2_MSG_USERAUTH_BANNER			53

#define SSH_CMSG_SESSION_KEY			3	/* key (BIGNUM) */
#define SSH_SMSG_SUCCESS			14	/* */

#define DNS_VERIFY_FOUND	0x00000001
#define DNS_VERIFY_MATCH	0x00000002
#define DNS_VERIFY_SECURE	0x00000004

/*
 * Cipher types for SSH-1.  New types can be added, but old types should not
 * be removed for compatibility.  The maximum allowed value is 31.
 */
#define SSH_CIPHER_SSH2		-3
#define SSH_CIPHER_INVALID	-2	/* No valid cipher selected. */
#define SSH_CIPHER_NOT_SET	-1	/* None selected (invalid number). */
#define SSH_CIPHER_NONE		0	/* no encryption */
#define SSH_CIPHER_IDEA		1	/* IDEA CFB */
#define SSH_CIPHER_DES		2	/* DES CBC */
#define SSH_CIPHER_3DES		3	/* 3DES CBC */
#define SSH_CIPHER_BROKEN_TSS	4	/* TRI's Simple Stream encryption CBC */
#define SSH_CIPHER_BROKEN_RC4	5	/* Alleged RC4 */
#define SSH_CIPHER_BLOWFISH	6
#define SSH_CIPHER_RESERVED	7
#define SSH_CIPHER_MAX		31

#define SSH_SMSG_PUBLIC_KEY			2	/* ck,msk,srvk,hostk */

/* Protocol flags.  These are bit masks. */
#define SSH_PROTOFLAG_SCREEN_NUMBER	1	/* X11 forwarding includes screen */
#define SSH_PROTOFLAG_HOST_IN_FWD_OPEN	2	/* forwarding opens contain host */

/*
 * Length of the session key in bytes.  (Specified as 256 bits in the
 * protocol.)
 */
#define SSH_SESSION_KEY_LENGTH		32

/*
 * Force host key length and server key length to differ by at least this
 * many bits.  This is to make double encryption with rsaref work.
 */
#define SSH_KEY_BITS_RESERVED		128


/*
 * Major protocol version.  Different version indicates major incompatibility
 * that prevents communication.
 *
 * Minor protocol version.  Different version indicates minor incompatibility
 * that does not prevent interoperation.
 */
#define PROTOCOL_MAJOR_1	1
#define PROTOCOL_MINOR_1	5

/* We support both SSH1 and SSH2 */
#define PROTOCOL_MAJOR_2	2
#define PROTOCOL_MINOR_2	0

#define	SSH_PROTO_UNKNOWN	0x00
#define	SSH_PROTO_1		0x01
#define	SSH_PROTO_1_PREFERRED	0x02
#define	SSH_PROTO_2		0x04

#define SSH_BUG_SIGBLOB		0x00000001
#define SSH_BUG_PKSERVICE	0x00000002
#define SSH_BUG_HMAC		0x00000004
#define SSH_BUG_X11FWD		0x00000008
#define SSH_OLD_SESSIONID	0x00000010
#define SSH_BUG_PKAUTH		0x00000020
#define SSH_BUG_DEBUG		0x00000040
#define SSH_BUG_BANNER		0x00000080
#define SSH_BUG_IGNOREMSG	0x00000100
#define SSH_BUG_PKOK		0x00000200
#define SSH_BUG_PASSWORDPAD	0x00000400
#define SSH_BUG_SCANNER		0x00000800
#define SSH_BUG_BIGENDIANAES	0x00001000
#define SSH_BUG_RSASIGMD5	0x00002000
#define SSH_OLD_DHGEX		0x00004000
#define SSH_BUG_NOREKEY		0x00008000
#define SSH_BUG_HBSERVICE	0x00010000
#define SSH_BUG_OPENFAILURE	0x00020000
#define SSH_BUG_DERIVEKEY	0x00040000
#define SSH_BUG_DUMMYCHAN	0x00100000
#define SSH_BUG_EXTEOF		0x00200000
#define SSH_BUG_PROBE		0x00400000
#define SSH_BUG_FIRSTKEX	0x00800000
#define SSH_OLD_FORWARD_ADDR	0x01000000
#define SSH_BUG_RFWD_ADDR	0x02000000
#define SSH_NEW_OPENSSH		0x04000000

#define SSH2_MSG_TRANSPORT_MIN				1
#define SSH2_MSG_TRANSPORT_MAX				49
#define SSH2_MSG_USERAUTH_MIN				50
#define SSH2_MSG_USERAUTH_MAX				79
#define SSH2_MSG_USERAUTH_PER_METHOD_MIN		60
#define SSH2_MSG_USERAUTH_PER_METHOD_MAX		SSH2_MSG_USERAUTH_MAX
#define SSH2_MSG_CONNECTION_MIN				80
#define SSH2_MSG_CONNECTION_MAX				127
#define SSH2_MSG_RESERVED_MIN				128
#define SSH2_MSG_RESERVED_MAX				191
#define SSH2_MSG_LOCAL_MIN				192
#define SSH2_MSG_LOCAL_MAX				255
#define SSH2_MSG_MIN					1
#define SSH2_MSG_MAX					255

#define DNS_RDATACLASS_IN	1
#define DNS_RDATATYPE_SSHFP	44

struct stat
  {
    __dev_t st_dev;		/* Device.  */
#if __WORDSIZE == 32
    unsigned short int __pad1;
#endif
#if __WORDSIZE == 64 || !defined __USE_FILE_OFFSET64
    __ino_t st_ino;		/* File serial number.	*/
#else
    __ino_t __st_ino;			/* 32bit file serial number.	*/
#endif
#if __WORDSIZE == 32
    __mode_t st_mode;			/* File mode.  */
    __nlink_t st_nlink;			/* Link count.  */
#else
    __nlink_t st_nlink;		/* Link count.  */
    __mode_t st_mode;		/* File mode.  */
#endif
    __uid_t st_uid;		/* User ID of the file's owner.	*/
    __gid_t st_gid;		/* Group ID of the file's group.*/
#if __WORDSIZE == 64
    int __pad0;
#endif
    __dev_t st_rdev;		/* Device number, if device.  */
#if __WORDSIZE == 32
    unsigned short int __pad2;
#endif
#if __WORDSIZE == 64 || !defined __USE_FILE_OFFSET64
    __off_t st_size;			/* Size of file, in bytes.  */
#else
    __off64_t st_size;			/* Size of file, in bytes.  */
#endif
    __blksize_t st_blksize;	/* Optimal block size for I/O.  */
#if __WORDSIZE == 64 || !defined __USE_FILE_OFFSET64
    __blkcnt_t st_blocks;		/* Number 512-byte blocks allocated. */
#else
    __blkcnt64_t st_blocks;		/* Number 512-byte blocks allocated. */
#endif
#ifdef __USE_MISC
    /* Nanosecond resolution timestamps are stored in a format
       equivalent to 'struct timespec'.  This is the type used
       whenever possible but the Unix namespace rules do not allow the
       identifier 'timespec' to appear in the <sys/stat.h> header.
       Therefore we have to handle the use of this header in strictly
       standard-compliant sources special.  */
    struct timespec st_atim;		/* Time of last access.  */
    struct timespec st_mtim;		/* Time of last modification.  */
    struct timespec st_ctim;		/* Time of last status change.  */
# define st_atime st_atim.tv_sec	/* Backward compatibility.  */
# define st_mtime st_mtim.tv_sec
# define st_ctime st_ctim.tv_sec
#else
    __time_t st_atime;			/* Time of last access.  */
    unsigned long int st_atimensec;	/* Nscecs of last access.  */
    __time_t st_mtime;			/* Time of last modification.  */
    unsigned long int st_mtimensec;	/* Nsecs of last modification.  */
    __time_t st_ctime;			/* Time of last status change.  */
    unsigned long int st_ctimensec;	/* Nsecs of last status change.  */
#endif
#if __WORDSIZE == 64
    long int __unused[3];
#else
# ifndef __USE_FILE_OFFSET64
    unsigned long int __unused4;
    unsigned long int __unused5;
# else
    __ino64_t st_ino;			/* File serial number.	*/
# endif
#endif
  };
  
  # define RRSET_VALIDATED	1



typedef unsigned char u_char;
typedef unsigned short int u_short;
typedef unsigned int u_int;
typedef unsigned long int u_long;
typedef int pid_t;
typedef unsigned int socklen_t;

/* Read NBYTES into BUF from FD.  Return the
   number read, -1 for errors or 0 for EOF.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern ssize_t read (int __fd, void *__buf, size_t __nbytes) __wur;

#define	EINPROGRESS	115	/* Operation now in progress */
#define	ETIMEDOUT	110	/* Connection timed out */
#define	EINTR		 4	/* Interrupted system call */

#define SOL_SOCKET	1
#define SO_ERROR	4
#define SO_KEEPALIVE	9

#define RPP_ECHO_OFF    0x00		/* Turn off echo (default). */
#define RPP_ECHO_ON     0x01		/* Leave echo on. */
#define RPP_REQUIRE_TTY 0x02		/* Fail if there is no tty. */
#define RPP_FORCELOWER  0x04		/* Force input to lower case. */
#define RPP_FORCEUPPER  0x08		/* Force input to upper case. */
#define RPP_SEVENBIT    0x10		/* Strip the high bit from input. */
#define RPP_STDIN       0x20		/* Read from stdin, not /dev/tty */

/* open/fcntl - O_SYNC is only implemented on blocks devices and on files
   located on an ext2 file system */
#define O_ACCMODE	   0003
#define O_RDONLY	     00
#define O_WRONLY	     01
#define O_RDWR		     02
#define O_CREAT		   0100	/* not fcntl */
#define O_EXCL		   0200	/* not fcntl */
#define O_NOCTTY	   0400	/* not fcntl */
#define O_TRUNC		  01000	/* not fcntl */
#define O_APPEND	  02000
#define O_NONBLOCK	  04000
#define O_NDELAY	O_NONBLOCK
#define O_SYNC		 010000
#define O_FSYNC		 O_SYNC
#define O_ASYNC		 020000

# define _PATH_TTY "/dev/tty"
#define _PATH_SSH_ASKPASS_DEFAULT	"/usr/X11R6/bin/ssh-askpass"

/* Standard file descriptors.  */
#define	STDIN_FILENO	0	/* Standard input.  */
#define	STDOUT_FILENO	1	/* Standard output.  */
#define	STDERR_FILENO	2	/* Standard error output.  */
/*
 * Maximum number of RSA authentication identity files that can be specified
 * in configuration files or on the command line.
 */
#define SSH_MAX_IDENTITY_FILES		100

/* Maximum number of TCP/IP ports forwarded per direction. */
#define SSH_MAX_FORWARDS_PER_DIRECTION	100

#define MAX_SEND_ENV	256

/* Highest reserved Internet port number.  */
# define IPPORT_RESERVED	1024

/* Possible values for `ai_flags' field in `addrinfo' structure.  */
# define AI_PASSIVE	0x0001	/* Socket address is intended for `bind'.  */
# define AI_CANONNAME	0x0002	/* Request for canonical name.  */
# define AI_NUMERICHOST	0x0004	/* Don't use name resolution.  */
# define AI_V4MAPPED	0x0008	/* IPv4 mapped addresses are acceptable.  */
# define AI_ALL		0x0010	/* Return IPv4 mapped and IPv6 addresses.  */
# define AI_ADDRCONFIG	0x0020	/* Use configuration of this host to choose
				   returned address type..  */
				   
#define AF_INET 2
#define AF_INET6 10

# define NI_NUMERICHOST	1	/* Don't try to look up hostname.  */
# define NI_NUMERICSERV 2	/* Don't convert port number to name.  */
# define NI_NOFQDN	4	/* Only return nodename portion.  */
# define NI_NAMEREQD	8	/* Don't return numeric addresses.  */
# define NI_DGRAM	16	/* Look up UDP service rather than TCP.  */

# define howmany(x, y)	(((x) + ((y) - 1)) / (y))

#define	EPIPE		32	/* Broken pipe */

/*
 * Environment variable for overwriting the default location of askpass
 */
#define SSH_ASKPASS_ENV		"SSH_ASKPASS"

/* readpass.c */

#define RP_ECHO			0x0001
#define RP_ALLOW_STDIN		0x0002
#define RP_ALLOW_EOF		0x0004
#define RP_USE_ASKPASS		0x0008

typedef enum {
	SYSLOG_LEVEL_QUIET,
	SYSLOG_LEVEL_FATAL,
	SYSLOG_LEVEL_ERROR,
	SYSLOG_LEVEL_INFO,
	SYSLOG_LEVEL_VERBOSE,
	SYSLOG_LEVEL_DEBUG1,
	SYSLOG_LEVEL_DEBUG2,
	SYSLOG_LEVEL_DEBUG3,
	SYSLOG_LEVEL_NOT_SET = -1
}       LogLevel;

/* Supported syslog facilities and levels. */
typedef enum {
	SYSLOG_FACILITY_DAEMON,
	SYSLOG_FACILITY_USER,
	SYSLOG_FACILITY_AUTH,
#ifdef LOG_AUTHPRIV
	SYSLOG_FACILITY_AUTHPRIV,
#endif
	SYSLOG_FACILITY_LOCAL0,
	SYSLOG_FACILITY_LOCAL1,
	SYSLOG_FACILITY_LOCAL2,
	SYSLOG_FACILITY_LOCAL3,
	SYSLOG_FACILITY_LOCAL4,
	SYSLOG_FACILITY_LOCAL5,
	SYSLOG_FACILITY_LOCAL6,
	SYSLOG_FACILITY_LOCAL7,
	SYSLOG_FACILITY_NOT_SET = -1
}       SyslogFacility;

typedef long int BIGNUM;

 struct _RSA
        {
        BIGNUM *n;              // public modulus
        BIGNUM *e;              // public exponent
        BIGNUM *d;              // private exponent
        BIGNUM *p;              // secret prime factor
        BIGNUM *q;              // secret prime factor
        BIGNUM *dmp1;           // d mod (p-1)
        BIGNUM *dmq1;           // d mod (q-1)
        BIGNUM *iqmp;           // q^-1 mod p
        };
        
  struct _DSA
        {
        BIGNUM *p;              // prime number (public)
        BIGNUM *q;              // 160-bit subprime, q | p-1 (public)
        BIGNUM *g;              // generator of subgroup (public)
        BIGNUM *priv_key;       // private key x
        BIGNUM *pub_key;        // public key y = g^x
        };
typedef struct _RSA RSA;
typedef struct _DSA DSA;

typedef struct Key Key;
enum types {
	KEY_RSA1,
	KEY_RSA,
	KEY_DSA,
	KEY_UNSPEC
};
enum fp_type {
	SSH_FP_SHA1,
	SSH_FP_MD5
};
enum fp_rep {
	SSH_FP_HEX,
	SSH_FP_BUBBLEBABBLE,
	SSH_FP_RANDOMART
};

/* key is stored in external hardware */
#define KEY_FLAG_EXT		0x0001

struct Key {
	int	 type;
	int	 flags;
	RSA	*rsa;
	DSA	*dsa;
};
#define SSH2_MSG_DISCONNECT				1
#define SSH2_MSG_IGNORE					2
#define SSH2_MSG_UNIMPLEMENTED				3
#define SSH2_MSG_DEBUG					4
#define SSH2_MSG_SERVICE_REQUEST			5
#define SSH2_MSG_SERVICE_ACCEPT				6


/* Data structure for representing a forwarding request. */

typedef struct {
	char	 *listen_host;		/* Host (address) to listen on. */
	int	  listen_port;		/* Port to forward. */
	char	 *connect_host;		/* Host to connect. */
	int	  connect_port;		/* Port to connect on connect_host. */
}       Forward;

typedef struct {
	int     forward_agent;	/* Forward authentication agent. */
	int     forward_x11;	/* Forward X11 display. */
	int     forward_x11_trusted;	/* Trust Forward X11 display. */
	int     exit_on_forward_failure;	/* Exit if bind(2) fails for
-L/-R */
	char   *xauth_location;	/* Location for xauth program */
	int     gateway_ports;	/* Allow remote connects to forwarded ports. */
	int     use_privileged_port;	/* Don't use privileged port if false.
*/
	int     rhosts_rsa_authentication;	/* Try rhosts with RSA
						 * authentication. */
	int     rsa_authentication;	/* Try RSA authentication. */
	int     pubkey_authentication;	/* Try ssh2 pubkey authentication. */
	int     hostbased_authentication;	/* ssh2's rhosts_rsa */
	int     challenge_response_authentication;
					/* Try S/Key or TIS, authentication. */
	int     gss_authentication;	/* Try GSS authentication */
	int     gss_deleg_creds;	/* Delegate GSS credentials */
	int     password_authentication;	/* Try password
						 * authentication. */
	int     kbd_interactive_authentication; /* Try keyboard-interactive
auth. */
	char	*kbd_interactive_devices; /* Keyboard-interactive auth devices.
*/
	int     zero_knowledge_password_authentication;	/* Try jpake */
	int     batch_mode;	/* Batch mode: do not ask for passwords. */
	int     check_host_ip;	/* Also keep track of keys for IP address */
	int     strict_host_key_checking;	/* Strict host key checking. */
	int     compression;	/* Compress packets in both directions. */
	int     compression_level;	/* Compression level 1 (fast) to 9
					 * (best). */
	int     tcp_keep_alive;	/* Set SO_KEEPALIVE. */
	LogLevel log_level;	/* Level for logging. */

	int     port;		/* Port to connect. */
	int     address_family;
	int     connection_attempts;	/* Max attempts (seconds) before
					 * giving up */
	int     connection_timeout;	/* Max time (seconds) before
					 * aborting connection attempt */
	int     number_of_password_prompts;	/* Max number of password
						 * prompts. */
	int     cipher;		/* Cipher to use. */
	char   *ciphers;	/* SSH2 ciphers in order of preference. */
	char   *macs;		/* SSH2 macs in order of preference. */
	char   *hostkeyalgorithms;	/* SSH2 server key types in order of
preference. */
	int	protocol;	/* Protocol in order of preference. */
	char   *hostname;	/* Real host to connect. */
	char   *host_key_alias;	/* hostname alias for .ssh/known_hosts */
	char   *proxy_command;	/* Proxy command for connecting the host. */
	char   *user;		/* User to log in as. */
	int     escape_char;	/* Escape character; -2 = none */

	char   *system_hostfile;/* Path for /etc/ssh/ssh_known_hosts. */
	char   *user_hostfile;	/* Path for $HOME/.ssh/known_hosts. */
	char   *system_hostfile2;
	char   *user_hostfile2;
	char   *preferred_authentications;
	char   *bind_address;	/* local socket address for connection to sshd
*/
	char   *smartcard_device; /* Smartcard reader device */
	int	verify_host_key_dns;	/* Verify host key using DNS */

	int     num_identity_files;	/* Number of files for RSA/DSA
identities. */
	char   *identity_files[SSH_MAX_IDENTITY_FILES];
	Key    *identity_keys[SSH_MAX_IDENTITY_FILES];

	/* Local TCP/IP forward requests. */
	int     num_local_forwards;
	Forward local_forwards[SSH_MAX_FORWARDS_PER_DIRECTION];

	/* Remote TCP/IP forward requests. */
	int     num_remote_forwards;
	Forward remote_forwards[SSH_MAX_FORWARDS_PER_DIRECTION];
	int	clear_forwardings;

	int	enable_ssh_keysign;
	int64_t rekey_limit;
	int	no_host_authentication_for_localhost;
	int	identities_only;
	int	server_alive_interval;
	int	server_alive_count_max;

	int     num_send_env;
	char   *send_env[MAX_SEND_ENV];

	char	*control_path;
	int	control_master;

	int	hash_known_hosts;

	int	tun_open;	/* tun(4) */
	int     tun_local;	/* force tun device (optional) */
	int     tun_remote;	/* force tun device (optional) */

	char	*local_command;
	int	permit_local_command;
	int	visual_host_key;

	int	use_roaming;

}       Options;

struct addrinfo {
	int	ai_flags;	/* AI_PASSIVE, AI_CANONNAME */
	int	ai_family;	/* PF_xxx */
	int	ai_socktype;	/* SOCK_xxx */
	int	ai_protocol;	/* 0 or IPPROTO_xxx for IPv4 and IPv6 */
	size_t	ai_addrlen;	/* length of ai_addr */
	char	*ai_canonname;	/* canonical name for hostname */
	struct sockaddr *ai_addr;	/* binary address */
	//struct addrinfo *ai_next;	/* next structure in linked list */
};

/* Types of sockets.  */
enum __socket_type
{
  SOCK_STREAM = 1,		/* Sequenced, reliable, connection-based
				   byte streams.  */
#define SOCK_STREAM SOCK_STREAM
  SOCK_DGRAM = 2,		/* Connectionless, unreliable datagrams
				   of fixed maximum length.  */
#define SOCK_DGRAM SOCK_DGRAM
  SOCK_RAW = 3,			/* Raw protocol interface.  */
#define SOCK_RAW SOCK_RAW
  SOCK_RDM = 4,			/* Reliably-delivered messages.  */
#define SOCK_RDM SOCK_RDM
  SOCK_SEQPACKET = 5,		/* Sequenced, reliable, connection-based,
				   datagrams of fixed maximum length.  */
#define SOCK_SEQPACKET SOCK_SEQPACKET
  SOCK_DCCP = 6,		/* Datagram Congestion Control Protocol.  */
#define SOCK_DCCP SOCK_DCCP
  SOCK_PACKET = 10,		/* Linux specific way of getting packets
				   at the dev level.  For writing rarp and
				   other similar things on the user level. */
#define SOCK_PACKET SOCK_PACKET

  /* Flags to be ORed into the type parameter of socket and socketpair and
     used for the flags parameter of paccept.  */

  SOCK_CLOEXEC = 02000000,	/* Atomically set close-on-exec flag for the
				   new descriptor(s).  */
#define SOCK_CLOEXEC SOCK_CLOEXEC
  SOCK_NONBLOCK = 04000		/* Atomically mark descriptor(s) as
				   non-blocking.  */
#define SOCK_NONBLOCK SOCK_NONBLOCK
};
#define ECHO	0000010
#define ECHOE	0000020
#define ECHOK	0000040
#define ECHONL	0000100
#define NOFLSH	0000200
#define TOSTOP	0000400
# define ECHOCTL 0001000
# define ECHOPRT 0002000
# define ECHOKE	 0004000
# define FLUSHO	 0010000
# define PENDIN	 0040000

/* tcsetattr uses these */
#define	TCSANOW		0
#define	TCSADRAIN	1
#define	TCSAFLUSH	2

# define _T_FLUSH	(TCSAFLUSH)

/* Signals.  */
#define	SIGHUP		1	/* Hangup (POSIX).  */
#define	SIGINT		2	/* Interrupt (ANSI).  */
#define	SIGQUIT		3	/* Quit (POSIX).  */
#define	SIGILL		4	/* Illegal instruction (ANSI).  */
#define	SIGTRAP		5	/* Trace trap (POSIX).  */
#define	SIGABRT		6	/* Abort (ANSI).  */
#define	SIGIOT		6	/* IOT trap (4.2 BSD).  */
#define	SIGBUS		7	/* BUS error (4.2 BSD).  */
#define	SIGFPE		8	/* Floating-point exception (ANSI).  */
#define	SIGKILL		9	/* Kill, unblockable (POSIX).  */
#define	SIGUSR1		10	/* User-defined signal 1 (POSIX).  */
#define	SIGSEGV		11	/* Segmentation violation (ANSI).  */
#define	SIGUSR2		12	/* User-defined signal 2 (POSIX).  */
#define	SIGPIPE		13	/* Broken pipe (POSIX).  */
#define	SIGALRM		14	/* Alarm clock (POSIX).  */
#define	SIGTERM		15	/* Termination (ANSI).  */
#define	SIGSTKFLT	16	/* Stack fault.  */
#define	SIGCLD		SIGCHLD	/* Same as SIGCHLD (System V).  */
#define	SIGCHLD		17	/* Child status has changed (POSIX).  */
#define	SIGCONT		18	/* Continue (POSIX).  */
#define	SIGSTOP		19	/* Stop, unblockable (POSIX).  */
#define	SIGTSTP		20	/* Keyboard stop (POSIX).  */
#define	SIGTTIN		21	/* Background read from tty (POSIX).  */
#define	SIGTTOU		22	/* Background write to tty (POSIX).  */
#define	SIGURG		23	/* Urgent condition on socket (4.2 BSD).  */
#define	SIGXCPU		24	/* CPU limit exceeded (4.2 BSD).  */
#define	SIGXFSZ		25	/* File size limit exceeded (4.2 BSD).  */
#define	SIGVTALRM	26	/* Virtual alarm clock (4.2 BSD).  */
#define	SIGPROF		27	/* Profiling alarm clock (4.2 BSD).  */
#define	SIGWINCH	28	/* Window size change (4.3 BSD, Sun).  */
#define	SIGPOLL		SIGIO	/* Pollable event occurred (System V).  */
#define	SIGIO		29	/* I/O now possible (4.2 BSD).  */
#define	SIGPWR		30	/* Power failure restart (System V).  */
#define SIGSYS		31	/* Bad system call.  */
#define SIGUNUSED	31



//----------------------------------------

/* Fatal messages.  This function never returns. */

void
fatal(const char *fmt,...)
{
	exit(1);
}

void *
xmalloc(size_t size)
{
	void *ptr;

	if (size == 0)
		fatal("xmalloc: zero size");
	ptr = malloc(size);
	if (ptr == NULL)
		fatal("xmalloc: out of memory (allocating %lu bytes)", (u_long) size);
	return ptr;
}

char *
xstrdup (s)
  const char *s;
{
  register size_t len = strlen (s) + 1;
  register char *ret = xmalloc (len);
  memcpy (ret, s, len);
  return ret;
}



RSA* RSA_new();
BIGNUM* BN_new();
DSA* DSA_new();
/*
void * _memset(void *s, int c, size_t n)
{
size_t i;
char * ptr = s;

for (i = 0; i < n; i++, ptr++)
{
	*ptr = c;
}
return s;
}

void * memset(void *s, int c, size_t n)
{
size_t i;
char * ptr = s;

for (i = 0; i < n; i++, ptr++)
{
	*ptr = c;
}
return s;
}


int _getaddrinfo(const char * a, const char *b, 
    const struct addrinfo * c, struct addrinfo ** ai)
{
	*ai = malloc(sizeof(struct addrinfo));
	if(*ai == NULL) return -1;
	return 0;   	
}
*/

// ---------------Callees-------------


int errno;
/* import */
extern Options options;
extern char *__progname;
extern uid_t original_real_uid;
extern uid_t original_effective_uid;
extern pid_t proxy_command_pid;
/*
 * General data structure for command line options and options configurable
 * in configuration files.  See readconf.h.
 */
Options options;

#define getaddrinfo(a,b,c,d)	(ssh_getaddrinfo(a,b,c,d))

/*
 * Macros to raise/lower permissions.
 */
#define PRIV_START do {					\
	int save_errno = errno;				\
	if (seteuid(original_effective_uid) != 0)	\
		fatal("PRIV_START: seteuid: %s",	\
		    strerror(errno));			\
	errno = save_errno;				\
} while (0)

#define PRIV_END do {					\
	int save_errno = errno;				\
	if (seteuid(original_real_uid) != 0)		\
		fatal("PRIV_END: seteuid: %s",		\
		    strerror(errno));			\
	errno = save_errno;				\
} while (0)


void *
xcalloc(size_t nmemb, size_t size)
{
	void *ptr;

	if (size == 0 || nmemb == 0)
		fatal("xcalloc: zero size");
	if (SIZE_T_MAX / nmemb < size)
		fatal("xcalloc: nmemb * size > SIZE_T_MAX");
	ptr = calloc(nmemb, size);
	if (ptr == NULL)
		fatal("xcalloc: out of memory (allocating %lu bytes)",
		    (u_long)(size * nmemb));
	return ptr;
}

void
xfree(void *ptr)
{
	if (_SYN___1)
		fatal("xfree: NULL pointer given as argument");
	free(ptr);
}

static volatile int signo;

/* Type of a signal handler.  */
typedef void (*__sighandler_t) (int);

/* Structure describing the action to be taken when a signal arrives.  */
struct sigaction
  {
  	/* Used if SA_SIGINFO is not set.  */
	__sighandler_t sa_handler;
  
      /* Additional set of signals to be blocked.  */
    __sigset_t sa_mask;

    /* Special flags.  */
    int sa_flags;

    /* Restore handler.  */
    void (*sa_restorer) (void);
  };

typedef unsigned char	cc_t;
typedef unsigned int	speed_t;
typedef unsigned int	tcflag_t;

typedef struct {
	int family;		/* for example FamilyInternet */
	int length;		/* length of address, in bytes */
	char *address;		/* pointer to where to find the bytes */
} XHostAddress;

#define NCCS 32
struct termios
  {
    tcflag_t c_iflag;		/* input mode flags */
    tcflag_t c_oflag;		/* output mode flags */
    tcflag_t c_cflag;		/* control mode flags */
    tcflag_t c_lflag;		/* local mode flags */
    cc_t c_line;			/* line discipline */
    cc_t c_cc[NCCS];		/* control characters */
    speed_t c_ispeed;		/* input speed */
    speed_t c_ospeed;		/* output speed */
#define _HAVE_STRUCT_TERMIOS_C_ISPEED 1
#define _HAVE_STRUCT_TERMIOS_C_OSPEED 1
  };
  
  typedef enum {
	HOST_OK, HOST_NEW, HOST_CHANGED, HOST_FOUND
}       HostStatus;

/* POSIX.1g specifies this type name for the `sa_family' member.  */
typedef unsigned short int sa_family_t;

/* Type to represent a port.  */
typedef unsigned short int in_port_t;

#define	__SOCKADDR_COMMON(sa_prefix) \
  sa_family_t sa_prefix##family

/* Structure describing a generic socket address.  */
struct sockaddr
  {
    __SOCKADDR_COMMON (sa_);	/* Common data: address family and length.  */
    char sa_data[14];		/* Address data.  */
  };
  
  /* Internet address.  */
typedef unsigned int in_addr_t;
struct in_addr
  {
    in_addr_t s_addr;
  };
  #define __SOCKADDR_COMMON_SIZE	(sizeof (unsigned short int))
  
  /* Structure describing an Internet socket address.  */
struct sockaddr_in
  {
    __SOCKADDR_COMMON (sin_);
    in_port_t sin_port;			/* Port number.  */
    struct in_addr sin_addr;		/* Internet address.  */

    /* Pad to size of `struct sockaddr'.  */
    unsigned char sin_zero[sizeof (struct sockaddr) -
			   __SOCKADDR_COMMON_SIZE -
			   sizeof (in_port_t) -
			   sizeof (struct in_addr)];
  };

/* Network number for local host loopback.  */
#define	IN_LOOPBACKNET		127



/* IPv6 address */
struct in6_addr
  {
    union
      {
	uint8_t	__u6_addr8[16];
#if defined __USE_MISC || defined __USE_GNU
	uint16_t __u6_addr16[8];
	uint32_t __u6_addr32[4];
#endif
      } __in6_u;
#define s6_addr			__in6_u.__u6_addr8
#if defined __USE_MISC || defined __USE_GNU
# define s6_addr16		__in6_u.__u6_addr16
# define s6_addr32		__in6_u.__u6_addr32
#endif
  };
  
  /* Ditto, for IPv6.  */
struct sockaddr_in6
  {
    __SOCKADDR_COMMON (sin6_);
    in_port_t sin6_port;	/* Transport layer port # */
    uint32_t sin6_flowinfo;	/* IPv6 flow information */
    struct in6_addr sin6_addr;	/* IPv6 address */
    uint32_t sin6_scope_id;	/* IPv6 scope-id */
  };

# define	_SS_MAXSIZE	128	/* Implementation specific max size */
# define       _SS_PADSIZE     (_SS_MAXSIZE - sizeof (struct sockaddr))

struct sockaddr_storage {
	struct sockaddr	ss_sa;
	char		__ss_pad2[_SS_PADSIZE];
};

/* Old OpenSSL doesn't support what we need for DHGEX-sha256 */
#if OPENSSL_VERSION_NUMBER < 0x00907000L
# define KEX_DEFAULT_KEX		\
	"diffie-hellman-group-exchange-sha1," \
	"diffie-hellman-group14-sha1," \
	"diffie-hellman-group1-sha1"
#else
# define KEX_DEFAULT_KEX		\
	"diffie-hellman-group-exchange-sha256," \
	"diffie-hellman-group-exchange-sha1," \
	"diffie-hellman-group14-sha1," \
	"diffie-hellman-group1-sha1"
#endif

#define	KEX_DEFAULT_PK_ALG	"ssh-rsa,ssh-dss"

#define	KEX_DEFAULT_ENCRYPT \
	"aes128-ctr,aes192-ctr,aes256-ctr," \
	"arcfour256,arcfour128," \
	"aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc," \
	"aes192-cbc,aes256-cbc,arcfour,rijndael-cbc@lysator.liu.se"
#define	KEX_DEFAULT_MAC \
	"hmac-md5,hmac-sha1,umac-64@openssh.com,hmac-ripemd160," \
	"hmac-ripemd160@openssh.com," \
	"hmac-sha1-96,hmac-md5-96"
#define	KEX_DEFAULT_COMP	"none,zlib@openssh.com,zlib"
#define	KEX_DEFAULT_LANG	""

enum kex_init_proposals {
	PROPOSAL_KEX_ALGS,
	PROPOSAL_SERVER_HOST_KEY_ALGS,
	PROPOSAL_ENC_ALGS_CTOS,
	PROPOSAL_ENC_ALGS_STOC,
	PROPOSAL_MAC_ALGS_CTOS,
	PROPOSAL_MAC_ALGS_STOC,
	PROPOSAL_COMP_ALGS_CTOS,
	PROPOSAL_COMP_ALGS_STOC,
	PROPOSAL_LANG_CTOS,
	PROPOSAL_LANG_STOC,
	PROPOSAL_MAX
};

static char *myproposal[PROPOSAL_MAX] = {
	KEX_DEFAULT_KEX,
	KEX_DEFAULT_PK_ALG,
	KEX_DEFAULT_ENCRYPT,
	KEX_DEFAULT_ENCRYPT,
	KEX_DEFAULT_MAC,
	KEX_DEFAULT_MAC,
	KEX_DEFAULT_COMP,
	KEX_DEFAULT_COMP,
	KEX_DEFAULT_LANG,
	KEX_DEFAULT_LANG
};





/* Common definitions for ssh tunnel device forwarding */
#define SSH_TUNMODE_NO		0x00
#define SSH_TUNMODE_POINTOPOINT	0x01
#define SSH_TUNMODE_ETHERNET	0x02
#define SSH_TUNMODE_DEFAULT	SSH_TUNMODE_POINTOPOINT
#define SSH_TUNMODE_YES		(SSH_TUNMODE_POINTOPOINT|SSH_TUNMODE_ETHERNET)

#define SSH_TUNID_ANY		0x7fffffff
#define SSH_TUNID_ERR		(SSH_TUNID_ANY - 1)
#define SSH_TUNID_MAX		(SSH_TUNID_ANY - 2)



char *forced_command;

typedef struct Sensitive Sensitive;
struct Sensitive {
	Key	**keys;
	int	nkeys;
	int	external_keysign;
};

/* The passwd structure.  */
struct passwd
{
  char *pw_name;		/* Username.  */
  char *pw_passwd;		/* Password.  */
  __uid_t pw_uid;		/* User ID.  */
  __gid_t pw_gid;		/* Group ID.  */
  char *pw_gecos;		/* Real name.  */
  char *pw_dir;			/* Home directory.  */
  char *pw_shell;		/* Shell program.  */
};

enum kex_modes {
	MODE_IN,
	MODE_OUT,
	MODE_MAX
};

typedef struct {
	u_char	*buf;		/* Buffer for data. */
	u_int	 alloc;		/* Number of bytes allocated for data. */
	u_int	 offset;	/* Offset of first byte containing data. */
	u_int	 end;		/* Offset of last byte containing data. */
}       Buffer;

typedef int sig_atomic_t;

/*
 * Every authentication method has to handle authentication requests for
 * non-existing users, or for users that are not allowed to login. In this
 * case 'valid' is set to 0, but 'user' points to the username requested by
 * the client.
 */

struct Authmethod {
	char	*name;
	int	(*userauth)(int *authctxt);
	int	*enabled;
};
typedef struct Authmethod Authmethod;



struct Authctxt {
	const char *server_user;
	const char *local_user;
	const char *host;
	const char *service;
	Authmethod *method;
	int success;
	char *authlist;
	/* pubkey */
	//Idlist keys;
	struct AuthenticationConnection *agent;
	/* hostbased */
	Sensitive *sensitive;
	/* kbd-interactive */
	int info_req_seen;
	/* generic */
	void *methoddata;
};
typedef struct Authctxt Authctxt;

typedef int EVP_CIPHER;
typedef int EVP_MD;
typedef int HMAC_CTX;
struct Cipher {
	char	*name;
	int	number;		/* for ssh1 only */
	u_int	block_size;
	u_int	key_len;
	u_int	discard_len;
	u_int	cbc_mode;
	const EVP_CIPHER	*(*evptype)(void);
};

typedef struct Cipher Cipher;

struct Enc {
	char	*name;
	Cipher	*cipher;
	int	enabled;
	u_int	key_len;
	u_int	block_size;
	u_char	*key;
	u_char	*iv;
};
typedef struct Enc Enc;
struct Mac {
	char	*name;
	int	enabled;
	u_int	mac_len;
	u_char	*key;
	u_int	key_len;
	int	type;
	const EVP_MD	*evp_md;
	HMAC_CTX	evp_ctx;
	struct umac_ctx *umac_ctx;
};
typedef struct Mac Mac;
struct Comp {
	int	type;
	int	enabled;
	char	*name;
};
typedef struct Comp Comp;

struct Newkeys {
	Enc	enc;
	Mac	mac;
	Comp	comp;
};
typedef struct Newkeys Newkeys;



enum kex_exchange {
	KEX_DH_GRP1_SHA1,
	KEX_DH_GRP14_SHA1,
	KEX_DH_GEX_SHA1,
	KEX_DH_GEX_SHA256,
	KEX_MAX
};



struct Kex;
struct Kex {
	u_char	*session_id;
	u_int	session_id_len;
	Newkeys	*newkeys[MODE_MAX];
	u_int	we_need;
	int	server;
	char	*name;
	int	hostkey_type;
	int	kex_type;
	Buffer	my;
	Buffer	peer;
	sig_atomic_t done;
	int	flags;
	const EVP_MD *evp_md;
	char	*client_version_string;
	char	*server_version_string;
	int	(*verify_host_key)(Key *);
	Key	*(*load_host_key)(int);
	int	(*host_key_index)(Key *);
	void	(*k[KEX_MAX])(int *);
};
typedef struct Kex Kex;

typedef struct {
	int	fd;
	Buffer	identities;
	int	howmany;
}	AuthenticationConnection;





/* Write N bytes of BUF to FD.  Return the number written, or -1.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern ssize_t write (int __fd, __const void *__buf, size_t __n) __wur;
#define vwrite (ssize_t (*)(int, void *, size_t))write

int resume_in_progress;
static u_int64_t write_bytes;
static u_int64_t read_bytes;

size_t
roaming_atomicio(ssize_t(*f)(int, void*, size_t), int fd, void *buf,
    size_t count)
{
	size_t ret = atomicio(f, fd, buf, count);

	if (f == vwrite && ret > 0 && !resume_in_progress) {
		write_bytes += ret;
	} else if (f == read && ret > 0 && !resume_in_progress) {
		read_bytes += ret;
	}
	return ret;
}



int compat20;
char *server_version_string;
char *client_version_string;

char *xxx_host;
struct sockaddr *xxx_hostaddr;

void	 kexdh_client(Kex *);
void	 kexdh_server(Kex *);
void	 kexgex_client(Kex *);
void	 kexgex_server(Kex *);

static int verify_host_key_callback(Key *hostkey);




static int matching_host_key_dns;
struct rdatainfo {
	unsigned int		rdi_length;	/* length of data */
	unsigned char		*rdi_data;	/* record data */
};

struct rrsetinfo {
	unsigned int		rri_flags;	/* RRSET_VALIDATED ... */
	unsigned int		rri_rdclass;	/* class number */
	unsigned int		rri_rdtype;	/* RR type number */
	unsigned int		rri_ttl;	/* time to live */
	unsigned int		rri_nrdatas;	/* size of rdatas array */
	unsigned int		rri_nsigs;	/* size of sigs array */
	char			*rri_name;	/* canonical name */
	struct rdatainfo	*rri_rdatas;	/* individual records */
	struct rdatainfo	*rri_sigs;	/* individual signatures */
};

#define ANSWER_BUFFER_SIZE 0xffff

# define ERRSET_SUCCESS		0
# define ERRSET_NOMEMORY	1
# define ERRSET_FAIL		2
# define ERRSET_INVAL		3
# define ERRSET_NONAME		4
# define ERRSET_NODATA		5

/*
 * Resolver options (keep these in synch with res_debug.c, please)
 */
#define RES_INIT	0x00000001	/* address initialized */
#define RES_DEBUG	0x00000002	/* print debug messages */
#define RES_AAONLY	0x00000004	/* authoritative answers only (!IMPL)*/
#define RES_USEVC	0x00000008	/* use virtual circuit */
#define RES_PRIMARY	0x00000010	/* query primary server only (!IMPL) */
#define RES_IGNTC	0x00000020	/* ignore trucation errors */
#define RES_RECURSE	0x00000040	/* recursion desired */
#define RES_DEFNAMES	0x00000080	/* use default domain name */
#define RES_STAYOPEN	0x00000100	/* Keep TCP socket open */
#define RES_DNSRCH	0x00000200	/* search up local domain tree */
#define	RES_INSECURE1	0x00000400	/* type 1 security disabled */
#define	RES_INSECURE2	0x00000800	/* type 2 security disabled */
#define	RES_NOALIASES	0x00001000	/* shuts off HOSTALIASES feature */
#define	RES_USE_INET6	0x00002000	/* use/map IPv6 in gethostbyname() */
#define RES_ROTATE	0x00004000	/* rotate ns list after each query */
#define	RES_NOCHECKNAME	0x00008000	/* do not check names for sanity. */
#define	RES_KEEPTSIG	0x00010000	/* do not strip TSIG records */
#define	RES_BLAST	0x00020000	/* blast all recursive servers */
#define RES_USEBSTRING	0x00040000	/* IPv6 reverse lookup with byte
					   strings */
#define RES_NOIP6DOTINT	0x00080000	/* Do not use .ip6.int in IPv6
					   reverse lookup */
#define RES_USE_EDNS0	0x00100000	/* Use EDNS0.  */
#define RES_SNGLKUP	0x00200000	/* one outstanding request at a time */
#define RES_SNGLKUPREOP	0x00400000	/* -"-, but open new socket for each
					   request */
					   
struct dns_query {
	char			*name;
	u_int16_t		type;
	u_int16_t		class;
	struct dns_query	*next;
};

struct dns_rr {
	char			*name;
	u_int16_t		type;
	u_int16_t		class;
	u_int16_t		ttl;
	u_int16_t		size;
	void			*rdata;
	struct dns_rr		*next;
};

struct dns_response {
	int		header;
	struct dns_query	*query;
	struct dns_rr		*answer;
	struct dns_rr		*authority;
	struct dns_rr		*additional;
};

int h_errno;

/* Possible values left in `h_errno'.  */
#define	HOST_NOT_FOUND	1	/* Authoritative Answer Host not found.  */
#define	TRY_AGAIN	2	/* Non-Authoritative Host not found,
				   or SERVERFAIL.  */
#define	NO_RECOVERY	3	/* Non recoverable errors, FORMERR, REFUSED,
				   NOTIMP.  */
#define	NO_DATA		4	/* Valid name, no data record of requested
				   type.  */
# define NETDB_INTERNAL	-1	/* See errno.  */
# define NETDB_SUCCESS	0	/* No problem.  */
# define NO_ADDRESS	NO_DATA	/* No address, look for MX record.  */

#define T_RRSIG 46

/* Cipher used for encrypting authentication files. */
#define SSH_AUTHFILE_CIPHER	SSH_CIPHER_3DES

/* Default port number. */
#define SSH_DEFAULT_PORT	22

/* Maximum number of TCP/IP ports forwarded per direction. */
#define SSH_MAX_FORWARDS_PER_DIRECTION	100

/*
 * Maximum number of RSA authentication identity files that can be specified
 * in configuration files or on the command line.
 */
#define SSH_MAX_IDENTITY_FILES		100

/*
 * Maximum length of lines in authorized_keys file.
 * Current value permits 16kbit RSA and RSA1 keys and 8kbit DSA keys, with
 * some room for options and comments.
 */
#define SSH_MAX_PUBKEY_BYTES		8192

#define SSHCTL_MASTER_NO	0
#define SSHCTL_MASTER_YES	1
#define SSHCTL_MASTER_AUTO	2
#define SSHCTL_MASTER_ASK	3
#define SSHCTL_MASTER_AUTO_ASK	4

#define SSH2_MSG_GLOBAL_REQUEST				80
#define SSH2_MSG_REQUEST_SUCCESS			81
#define SSH2_MSG_REQUEST_FAILURE			82

/* Used to identify ``EscapeChar none'' */
#define SSH_ESCAPECHAR_NONE		-2

# define _PATH_DEVNULL "/dev/null"

/* default window/packet sizes for tcp/x11-fwd-channel */
#define CHAN_SES_PACKET_DEFAULT	(32*1024)
#define CHAN_SES_WINDOW_DEFAULT	(64*CHAN_SES_PACKET_DEFAULT)
#define CHAN_TCP_PACKET_DEFAULT	(32*1024)
#define CHAN_TCP_WINDOW_DEFAULT	(64*CHAN_TCP_PACKET_DEFAULT)
#define CHAN_X11_PACKET_DEFAULT	(16*1024)
#define CHAN_X11_WINDOW_DEFAULT	(4*CHAN_X11_PACKET_DEFAULT)

/* Definitions for channel types. */
#define SSH_CHANNEL_X11_LISTENER	1	/* Listening for inet X11 conn. */
#define SSH_CHANNEL_PORT_LISTENER	2	/* Listening on a port. */
#define SSH_CHANNEL_OPENING		3	/* waiting for confirmation */
#define SSH_CHANNEL_OPEN		4	/* normal open two-way channel */
#define SSH_CHANNEL_CLOSED		5	/* waiting for close confirmation */
#define SSH_CHANNEL_AUTH_SOCKET		6	/* authentication socket */
#define SSH_CHANNEL_X11_OPEN		7	/* reading first X11 packet */
#define SSH_CHANNEL_INPUT_DRAINING	8	/* sending remaining data to conn */
#define SSH_CHANNEL_OUTPUT_DRAINING	9	/* sending remaining data to app */
#define SSH_CHANNEL_LARVAL		10	/* larval session */
#define SSH_CHANNEL_RPORT_LISTENER	11	/* Listening to a R-style port  */
#define SSH_CHANNEL_CONNECTING		12
#define SSH_CHANNEL_DYNAMIC		13
#define SSH_CHANNEL_ZOMBIE		14	/* Almost dead. */
#define SSH_CHANNEL_MAX_TYPE		15

#define CHAN_EXTENDED_IGNORE		0
#define CHAN_EXTENDED_READ		1
#define CHAN_EXTENDED_WRITE		2


struct Channel;

typedef void channel_callback_fn(int, void *);
typedef int channel_infilter_fn(struct Channel *, char *, int);
typedef void channel_filter_cleanup_fn(int, void *);
typedef u_char *channel_outfilter_fn(struct Channel *, u_char **, u_int *);

/* Channel success/failure callbacks */
typedef void channel_confirm_cb(int, struct Channel *, void *);
typedef void channel_confirm_abandon_cb(struct Channel *, void *);
static void ssh_session2_setup(int id, void *arg);


/* Context for non-blocking connects */
struct channel_connect {
	char *host;
	int port;
	struct addrinfo *ai, *aitop;
};

struct Channel {
	int     type;		/* channel type/state */
	int     self;		/* my own channel identifier */
	int     remote_id;	/* channel identifier for remote peer */
	u_int   istate;		/* input from channel (state of receive half) */
	u_int   ostate;		/* output to channel  (state of transmit half) */
	int     flags;		/* close sent/rcvd */
	int     rfd;		/* read fd */
	int     wfd;		/* write fd */
	int     efd;		/* extended fd */
	int     sock;		/* sock fd */
	int     ctl_fd;		/* control fd (client sharing) */
	int     isatty;		/* rfd is a tty */
	int     wfd_isatty;	/* wfd is a tty */
	int	client_tty;	/* (client) TTY has been requested */
	int     force_drain;	/* force close on iEOF */
	int     delayed;		/* fdset hack */
	Buffer  input;		/* data read from socket, to be sent over
				 * encrypted connection */
	Buffer  output;		/* data received over encrypted connection for
				 * send on socket */
	Buffer  extended;
	char    *path;
		/* path for unix domain sockets, or host name for forwards */
	int     listening_port;	/* port being listened for forwards */
	int     host_port;	/* remote port to connect for forwards */
	char   *remote_name;	/* remote hostname */

	u_int	remote_window;
	u_int	remote_maxpacket;
	u_int	local_window;
	u_int	local_window_max;
	u_int	local_consumed;
	u_int	local_maxpacket;
	int     extended_usage;
	int	single_connection;

	char   *ctype;		/* type */

	/* callback */
	channel_callback_fn	*open_confirm;
	void			*open_confirm_ctx;
	channel_callback_fn	*detach_user;
	int			detach_close;
	int	status_confirms;

	/* filter */
	channel_infilter_fn	*input_filter;
	channel_outfilter_fn	*output_filter;
	void			*filter_ctx;
	channel_filter_cleanup_fn *filter_cleanup;

	/* keep boundaries */
	int     		datagram;

	/* non-blocking connect */
	struct channel_connect	connect_ctx;
};
typedef struct Channel Channel;

/* possible output states */
#define CHAN_OUTPUT_OPEN		0
#define CHAN_OUTPUT_WAIT_DRAIN		1
#define CHAN_OUTPUT_WAIT_IEOF		2
#define CHAN_OUTPUT_CLOSED		3

/* possible input states */
#define CHAN_INPUT_OPEN			0
#define CHAN_INPUT_WAIT_DRAIN		1
#define CHAN_INPUT_WAIT_OCLOSE		2
#define CHAN_INPUT_CLOSED		3

/* channel related messages */

#define SSH2_MSG_CHANNEL_OPEN				90
#define SSH2_MSG_CHANNEL_OPEN_CONFIRMATION		91
#define SSH2_MSG_CHANNEL_OPEN_FAILURE			92
#define SSH2_MSG_CHANNEL_WINDOW_ADJUST			93
#define SSH2_MSG_CHANNEL_DATA				94
#define SSH2_MSG_CHANNEL_EXTENDED_DATA			95
#define SSH2_MSG_CHANNEL_EOF				96
#define SSH2_MSG_CHANNEL_CLOSE				97
#define SSH2_MSG_CHANNEL_REQUEST			98
#define SSH2_MSG_CHANNEL_SUCCESS			99
#define SSH2_MSG_CHANNEL_FAILURE			100

/* Fake signal functions.  */
#define SIG_ERR	((__sighandler_t) -1)		/* Error return.  */
#define SIG_DFL	((__sighandler_t) 0)		/* Default action.  */
#define SIG_IGN	((__sighandler_t) 1)		/* Ignore signal.  */

/* disconnect reason code */

#define SSH2_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT	1
#define SSH2_DISCONNECT_PROTOCOL_ERROR			2
#define SSH2_DISCONNECT_KEY_EXCHANGE_FAILED		3
#define SSH2_DISCONNECT_HOST_AUTHENTICATION_FAILED	4
#define SSH2_DISCONNECT_RESERVED			4
#define SSH2_DISCONNECT_MAC_ERROR			5
#define SSH2_DISCONNECT_COMPRESSION_ERROR		6
#define SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE		7
#define SSH2_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED	8
#define SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE		9
#define SSH2_DISCONNECT_CONNECTION_LOST			10
#define SSH2_DISCONNECT_BY_APPLICATION			11
#define SSH2_DISCONNECT_TOO_MANY_CONNECTIONS		12
#define SSH2_DISCONNECT_AUTH_CANCELLED_BY_USER		13
#define SSH2_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE	14
#define SSH2_DISCONNECT_ILLEGAL_USER_NAME		15

/* 0x54 is just a magic number to make these relatively unique ('T') */

#define TCGETS		0x5401
#define TCSETS		0x5402 /* Clashes with SNDCTL_TMR_START sound ioctl */
#define TCSETSW		0x5403
#define TCSETSF		0x5404
#define TCGETA		0x5405
#define TCSETA		0x5406
#define TCSETAW		0x5407
#define TCSETAF		0x5408
#define TCSBRK		0x5409
#define TCXONC		0x540A
#define TCFLSH		0x540B
#define TIOCEXCL	0x540C
#define TIOCNXCL	0x540D
#define TIOCSCTTY	0x540E
#define TIOCGPGRP	0x540F
#define TIOCSPGRP	0x5410
#define TIOCOUTQ	0x5411
#define TIOCSTI		0x5412
#define TIOCGWINSZ	0x5413
#define TIOCSWINSZ	0x5414
#define TIOCMGET	0x5415
#define TIOCMBIS	0x5416
#define TIOCMBIC	0x5417
#define TIOCMSET	0x5418
#define TIOCGSOFTCAR	0x5419
#define TIOCSSOFTCAR	0x541A
#define FIONREAD	0x541B
#define TIOCINQ		FIONREAD
#define TIOCLINUX	0x541C
#define TIOCCONS	0x541D
#define TIOCGSERIAL	0x541E
#define TIOCSSERIAL	0x541F
#define TIOCPKT		0x5420
#define FIONBIO		0x5421
#define TIOCNOTTY	0x5422
#define TIOCSETD	0x5423
#define TIOCGETD	0x5424
#define TCSBRKP		0x5425	/* Needed for POSIX tcsendbreak() */
/* #define TIOCTTYGSTRUCT 0x5426 - Former debugging-only ioctl */
#define TIOCSBRK	0x5427  /* BSD compatibility */
#define TIOCCBRK	0x5428  /* BSD compatibility */
#define TIOCGSID	0x5429  /* Return the session ID of FD */
#define TCGETS2		_IOR('T', 0x2A, struct termios2)
#define TCSETS2		_IOW('T', 0x2B, struct termios2)
#define TCSETSW2	_IOW('T', 0x2C, struct termios2)
#define TCSETSF2	_IOW('T', 0x2D, struct termios2)
#define TIOCGRS485	0x542E
#define TIOCSRS485	0x542F
#define TIOCGPTN	_IOR('T', 0x30, unsigned int)
				/* Get Pty Number (of pty-mux device) */
#define TIOCSPTLCK	_IOW('T', 0x31, int)  /* Lock/unlock Pty */
#define TCGETX		0x5432 /* SYS5 TCGETX compatibility */
#define TCSETX		0x5433
#define TCSETXF		0x5434
#define TCSETXW		0x5435


struct winsize
  {
    unsigned short int ws_row;
    unsigned short int ws_col;
    unsigned short int ws_xpixel;
    unsigned short int ws_ypixel;
  };

/* Common data for the client loop code. */
static volatile sig_atomic_t quit_pending; /* Set non-zero to quit the loop. */
static int escape_char1;	/* Escape character. (proto1 only) */
static int escape_pending1;	/* Last character was an escape (proto1 only) */
static int last_was_cr;		/* Last character was a newline. */
static int exit_status;		/* Used to store the command exit status. */
static int stdin_eof;		/* EOF has been encountered on stderr. */
static Buffer stdin_buffer;	/* Buffer for stdin data. */
static Buffer stdout_buffer;	/* Buffer for stdout data. */
static Buffer stderr_buffer;	/* Buffer for stderr data. */
static u_int buffer_high;/* Soft max buffer size. */
static int connection_in;	/* Connection to server (input). */
static int connection_out;	/* Connection to server (output). */
static int need_rekeying;	/* Set to non-zero if rekeying is requested. */
static int session_closed;	/* In SSH2: login session closed. */

/*
 * Flag to indicate that we have received a window change signal which has
 * not yet been processed.  This will cause a message indicating the new
 * window size to be sent to the server a little later.  This is volatile
 * because this is updated in a signal handler.
 */
static volatile sig_atomic_t received_window_change_signal;
static volatile sig_atomic_t received_signal;

/*
 * Signal handler for signals that cause the program to terminate.  These
 * signals must be trapped to restore terminal modes.
 */
/*ARGSUSED */
static void signal_handler(int sig);
/*
 * Signal handler for the window change signal (SIGWINCH).  This just sets a
 * flag indicating that the window has changed.
 */
/*ARGSUSED */
static void window_change_handler(int sig);


/* fd to control socket */
int muxserver_sock;

int no_shell_flag;
int datafellows;
int fork_after_authentication_flag;
int tty_flag;
int stdin_null_flag;
int stdin;
int stdout;
int stderr;


/*
 * Size of the channel array.  All slots of the array must always be
 * initialized (at least the type field); unused slots set to NULL
 */
static u_int channels_alloc;

/*
 * Pointer to an array containing all allocated channels.  The array is
 * dynamically extended as needed.
 */
static Channel **channels;

/*
 * Name of the host we are connecting to.  This is the name given on the
 * command line, or the HostName specified for the user-supplied name in a
 * configuration file.
 */
char *host;

/* Callback for remote forward global requests */
static void
ssh_confirm_remote_forward(int type, u_int32_t seq, void *ctxt);
int client_simple_escape_filter(Channel *c, char *buf, int len);
/* Free the escape filter context on channel free */
void client_filter_cleanup(int cid, void *ctx);
static void
client_channel_closed(int id, void *arg);

int	session_ident;
Kex *xxx_kex;


void *
xrealloc(void *ptr, size_t size)
{
	void *new_ptr;

	new_ptr = malloc(size);
	if(new_ptr == NULL) 
		fatal("xrealloc: out of memory (new_size %lu bytes)", (u_long) size);
	return new_ptr;

}


static void
ssh_init_forwarding(void)
{
	int success = 0;
	int i;
	
	


	/* Initiate local TCP/IP port forwardings. */
	for (i = 0; _SYN___2 ;i++) { 
		debug("Local connections to %.200s:%d forwarded to remote "
		    "address %.200s:%d",
		    (options.local_forwards[i].listen_host == NULL) ?
		    (options.gateway_ports ? "*" : "LOCALHOST") :
		    options.local_forwards[i].listen_host,
		    options.local_forwards[i].listen_port,
		    options.local_forwards[i].connect_host,
		    options.local_forwards[i].connect_port);
		success += channel_setup_local_fwd_listener(
		    options.local_forwards[i].listen_host,
		    options.local_forwards[i].listen_port,
		    options.local_forwards[i].connect_host,
		    options.local_forwards[i].connect_port,
		    options.gateway_ports);
	}
	if (i > 0 && success != i && options.exit_on_forward_failure)
		fatal("Could not request local forwarding.");
	if (i > 0 && success == 0)
		error("Could not request local forwarding.");

	/* Initiate remote TCP/IP port forwardings. */
	for (i = 0; _SYN___3; i++) { 
		debug("Remote connections from %.200s:%d forwarded to "
		    "local address %.200s:%d",
		    (options.remote_forwards[i].listen_host == NULL) ?
		    "LOCALHOST" : options.remote_forwards[i].listen_host,
		    options.remote_forwards[i].listen_port,
		    options.remote_forwards[i].connect_host,
		    options.remote_forwards[i].connect_port);
		if (channel_request_remote_forwarding(
		    options.remote_forwards[i].listen_host,
		    options.remote_forwards[i].listen_port,
		    options.remote_forwards[i].connect_host,
		    options.remote_forwards[i].connect_port) < 0) {
			if (options.exit_on_forward_failure)
				fatal("Could not request remote forwarding.");
			else
				logit("Warning: Could not request remote "
				    "forwarding.");
		}
		client_register_global_confirm(ssh_confirm_remote_forward,
		    &options.remote_forwards[i]);
	}

	/* Initiate tunnel forwarding. */
	if (options.tun_open != SSH_TUNMODE_NO) {
		if (client_request_tun_fwd(options.tun_open,
		    options.tun_local, options.tun_remote) == -1) {
			if (options.exit_on_forward_failure)
				fatal("Could not request tunnel forwarding.");
			else
				error("Could not request tunnel forwarding.");
		}
	}			
}

/*
 * Implements the interactive session with the server.  This is called after
 * the user has been authenticated, and a command has been started on the
 * remote host.  If escape_char != SSH_ESCAPECHAR_NONE, it is the character
 * used as an escape character for terminating or suspending the session.
 */

int
client_loop(int have_pty, int escape_char_arg, int ssh2_chan_id)
{
	fd_set *readset = NULL, *writeset = NULL;
	double start_time, total_time;
	int max_fd = 0, max_fd2 = 0, len, rekeying = 0;
	u_int64_t ibytes, obytes;
	u_int nalloc = 0;
	char buf[100];

	debug("Entering interactive session.");

	start_time = get_current_time();

	/* Initialize variables. */
	escape_pending1 = 0;
	last_was_cr = 1;
	exit_status = -1;
	stdin_eof = 0;
	buffer_high = 64 * 1024;
	connection_in = packet_get_connection_in();
	connection_out = packet_get_connection_out();
	max_fd = MAX(connection_in, connection_out);
	if (muxserver_sock != -1)
		max_fd = MAX(max_fd, muxserver_sock);

	if (!compat20) {
		/* enable nonblocking unless tty */
		if (!isatty(fileno(stdin)))
			set_nonblock(fileno(stdin));
		if (!isatty(fileno(stdout)))
			set_nonblock(fileno(stdout));
		if (!isatty(fileno(stderr)))
			set_nonblock(fileno(stderr));
		max_fd = MAX(max_fd, fileno(stdin));
		max_fd = MAX(max_fd, fileno(stdout));
		max_fd = MAX(max_fd, fileno(stderr));
	}
	quit_pending = 0;
	escape_char1 = escape_char_arg;

	/* Initialize buffers. */
	buffer_init(&stdin_buffer);
	buffer_init(&stdout_buffer);
	buffer_init(&stderr_buffer);

	client_init_dispatch();

	/*
	 * Set signal handlers, (e.g. to restore non-blocking mode)
	 * but don't overwrite SIG_IGN, matches behaviour from rsh(1)
	 */
	if (signal(SIGHUP, SIG_IGN) != SIG_IGN)
		signal(SIGHUP, signal_handler);
	if (signal(SIGINT, SIG_IGN) != SIG_IGN)
		signal(SIGINT, signal_handler);
	if (signal(SIGQUIT, SIG_IGN) != SIG_IGN)
		signal(SIGQUIT, signal_handler);
	if (signal(SIGTERM, SIG_IGN) != SIG_IGN)
		signal(SIGTERM, signal_handler);
	signal(SIGWINCH, window_change_handler);

	if (have_pty)
		enter_raw_mode();

	if (compat20) {
		session_ident = ssh2_chan_id;
		if (escape_char_arg != SSH_ESCAPECHAR_NONE)
			channel_register_filter(session_ident,
			    client_simple_escape_filter, NULL,
			    client_filter_cleanup,
			    client_new_escape_filter_ctx(escape_char_arg));
		if (session_ident != -1)
			channel_register_cleanup(session_ident,
			    client_channel_closed, 0);
	} else {
		/* Check if we should immediately send eof on stdin. */
		client_check_initial_eof_on_stdin();
	}

	/* Main loop of the client for the interactive session mode. */
	while (!quit_pending) {

		/* Process buffered packets sent by the server. */
		client_process_buffered_input_packets();

		if (compat20 && session_closed && !channel_still_open())
			break;

		rekeying = (xxx_kex != NULL && !xxx_kex->done);

		if (rekeying) {
			debug("rekeying in progress");
		} else {
			/*
			 * Make packets of buffered stdin data, and buffer
			 * them for sending to the server.
			 */
			if (!compat20)
				client_make_packets_from_stdin_data();

			/*
			 * Make packets from buffered channel data, and
			 * enqueue them for sending to the server.
			 */
			if (packet_not_very_much_data_to_write())
				channel_output_poll();

			/*
			 * Check if the window size has changed, and buffer a
			 * message about it to the server if so.
			 */
			client_check_window_change();

			if (quit_pending)
				break;
		}
		/*
		 * Wait until we have something to do (something becomes
		 * available on one of the descriptors).
		 */
		max_fd2 = max_fd;
		client_wait_until_can_do_something(&readset, &writeset,
		    &max_fd2, &nalloc, rekeying);

		if (quit_pending)
			break;

		/* Do channel operations unless rekeying in progress. */
		if (!rekeying) {
			channel_after_select(readset, writeset);
			if (need_rekeying || packet_need_rekeying()) {
				debug("need rekeying");
				if(_SYN___4){ 
				  xxx_kex->done = 0;
				  kex_send_kexinit(xxx_kex);
				}
				need_rekeying = 0;
			}
		}

		/* Buffer input from the connection.  */
		client_process_net_input(readset);

		/* Accept control connections.  */
		if (muxserver_sock != -1 &&FD_ISSET(muxserver_sock, readset)) {
			if (muxserver_accept_control())
				quit_pending = 1;
		}

		if (quit_pending)
			break;

		if (!compat20) {
			/* Buffer data from stdin */
			client_process_input(readset);
			/*
			 * Process output to stdout and stderr.  Output to
			 * the connection is processed elsewhere (above).
			 */
			client_process_output(writeset);
		}

		/*
		 * Send as much buffered packet data as possible to the
		 * sender.
		 */
		if (FD_ISSET(connection_out, writeset))
			packet_write_poll();
	}
	if (readset)
		xfree(readset);
	if (writeset)
		xfree(writeset);

	/* Terminate the session. */

	/* Stop watching for window change. */
	signal(SIGWINCH, SIG_DFL);

	if (compat20) {
		packet_start(SSH2_MSG_DISCONNECT);
		packet_put_int(SSH2_DISCONNECT_BY_APPLICATION);
		packet_put_cstring("disconnected by user");
		packet_send();
		packet_write_wait();
	}

	channel_free_all();

	if (have_pty)
		leave_raw_mode();

	/* restore blocking io */
	if (!isatty(fileno(stdin)))
		unset_nonblock(fileno(stdin));
	if (!isatty(fileno(stdout)))
		unset_nonblock(fileno(stdout));
	if (!isatty(fileno(stderr)))
		unset_nonblock(fileno(stderr));

	/*
	 * If there was no shell or command requested, there will be no remote
	 * exit status to be returned.  In that case, clear error code if the
	 * connection was deliberately terminated at this end.
	 */
	if (no_shell_flag && received_signal == SIGTERM) {
		received_signal = 0;
		exit_status = 0;
	}

	if (received_signal)
		fatal("Killed by signal %d.", (int) received_signal);

	/*
	 * In interactive mode (with pseudo tty) display a message indicating
	 * that the connection has been closed.
	 */
	if (have_pty && options.log_level != SYSLOG_LEVEL_QUIET) {
		snprintf(buf, sizeof buf,
		    "Connection to %.64s closed.\r\n", host);
		buffer_append(&stderr_buffer, buf, strlen(buf));
	}

	/* Output any buffered data for stdout. */
	while (buffer_len(&stdout_buffer) > 0) {
		len = write(fileno(stdout), buffer_ptr(&stdout_buffer),
		    buffer_len(&stdout_buffer));
		if (len <= 0) {
			error("Write failed flushing stdout buffer.");
			break;
		}
		buffer_consume(&stdout_buffer, len);
	}

	/* Output any buffered data for stderr. */
	while (buffer_len(&stderr_buffer) > 0) {
		len = write(fileno(stderr), buffer_ptr(&stderr_buffer),
		    buffer_len(&stderr_buffer));
		if (len <= 0) {
			error("Write failed flushing stderr buffer.");
			break;
		}
		buffer_consume(&stderr_buffer, len);
	}

	/* Clear and free any buffers. */
	memset(buf, 0, sizeof(buf));
	buffer_free(&stdin_buffer);
	buffer_free(&stdout_buffer);
	buffer_free(&stderr_buffer);

	/* Report bytes transferred, and transfer rates. */
	total_time = get_current_time() - start_time;
	packet_get_state(MODE_IN, NULL, NULL, NULL, &ibytes);
	packet_get_state(MODE_OUT, NULL, NULL, NULL, &obytes);
	verbose("Transferred: sent %llu, received %llu bytes, in %.1f seconds",
	    obytes, ibytes, total_time);
	if (total_time > 0)
		verbose("Bytes per second: sent %.1f, received %.1f",
		    obytes / total_time, ibytes / total_time);
	/* Return the exit status of the program. */
	debug("Exit status %d", exit_status);
	return exit_status;
}

static void
check_agent_present(void)
{
	if (options.forward_agent) {
		/* Clear agent forwarding if we don't have an agent. */
		if (!ssh_agent_present())
			options.forward_agent = 0;
	}
}

/*
 * Execute a local command
 */
int
ssh_local_cmd(const char *args)
{
	char *shell;
	pid_t pid;
	int status;

	if (!options.permit_local_command ||
	     _SYN___5) 
		return (1);

	if ((shell = getenv("SHELL")) == NULL)
		shell = _PATH_BSHELL;

	pid = fork();
	if (pid == 0) {
		debug3("Executing %s -c \"%s\"", shell, args);
		execl(shell, shell, "-c", args, (char *)NULL);
		error("Couldn't execute %s -c \"%s\": %s",
		    shell, args, strerror(errno));
		_exit(1);
	} else if (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	while (waitpid(pid, &status, 0) == -1)
		if (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));

	if (!WIFEXITED(status))
		return (1);

	return (WEXITSTATUS(status));
}

/* command to be executed */
Buffer command;
static int
ssh_session(void)
{
	int type;
	int interactive = 0;
	int have_tty = 0;
	struct winsize ws;
	char *cp;
	const char *display;

	/* Enable compression if requested. */
	if (options.compression) {
		debug("Requesting compression at level %d.",
		    options.compression_level);

		if (options.compression_level < 1 ||
		    options.compression_level > 9)
			fatal("Compression level must be from 1 (fast) to "
			    "9 (slow, best).");

		/* Send the request. */
		packet_start(SSH_CMSG_REQUEST_COMPRESSION);
		packet_put_int(options.compression_level);
		packet_send();
		packet_write_wait();
		type = packet_read();
		if (type == SSH_SMSG_SUCCESS)
			packet_start_compression(options.compression_level);
		else if (type == SSH_SMSG_FAILURE)
			logit("Warning: Remote host refused compression.");
		else
			packet_disconnect("Protocol error waiting for "
			    "compression response.");
	}
	/* Allocate a pseudo tty if appropriate. */
	if (tty_flag) {
		debug("Requesting pty.");

		/* Start the packet. */
		packet_start(SSH_CMSG_REQUEST_PTY);

		/* Store TERM in the packet.  There is no limit on the
		   length of the string. */
		cp = getenv("TERM");
		if (!cp)
			cp = "";
		packet_put_cstring(cp);

		/* Store window size in the packet. */
		if (ioctl(fileno(stdin), TIOCGWINSZ, &ws) < 0)
			memset(&ws, 0, sizeof(ws));
		packet_put_int((u_int)ws.ws_row);
		packet_put_int((u_int)ws.ws_col);
		packet_put_int((u_int)ws.ws_xpixel);
		packet_put_int((u_int)ws.ws_ypixel);

		/* Store tty modes in the packet. */
		tty_make_modes(fileno(stdin), NULL);

		/* Send the packet, and wait for it to leave. */
		packet_send();
		packet_write_wait();

		/* Read response from the server. */
		type = packet_read();
		if (type == SSH_SMSG_SUCCESS) {
			interactive = 1;
			have_tty = 1;
		} else if (type == SSH_SMSG_FAILURE)
			logit("Warning: Remote host failed or refused to "
			    "allocate a pseudo tty.");
		else
			packet_disconnect("Protocol error waiting for pty "
			    "request response.");
	}
	/* Request X11 forwarding if enabled and DISPLAY is set. */
	display = getenv("DISPLAY");
	if (options.forward_x11 && display != NULL) {
		char *proto, *data;
		/* Get reasonable local authentication information. */
		client_x11_get_proto(display, options.xauth_location,
		    options.forward_x11_trusted, &proto, &data);
		/* Request forwarding with authentication spoofing. */
		debug("Requesting X11 forwarding with authentication "
		    "spoofing.");
		x11_request_forwarding_with_spoofing(0, display, proto, data);

		/* Read response from the server. */
		type = packet_read();
		if (type == SSH_SMSG_SUCCESS) {
			interactive = 1;
		} else if (type == SSH_SMSG_FAILURE) {
			logit("Warning: Remote host denied X11 forwarding.");
		} else {
			packet_disconnect("Protocol error waiting for X11 "
			    "forwarding");
		}
	}
	/* Tell the packet module whether this is an interactive session. */
	packet_set_interactive(interactive);

	/* Request authentication agent forwarding if appropriate. */
	check_agent_present();

	if (options.forward_agent) {
		debug("Requesting authentication agent forwarding.");
		auth_request_forwarding();

		/* Read response from the server. */
		type = packet_read();
		packet_check_eom();
		if (type != SSH_SMSG_SUCCESS)
			logit("Warning: Remote host denied authentication agent forwarding.");
	}

	/* Initiate port forwardings. */
	ssh_init_forwarding();

	/* Execute a local command */
	if (options.local_command != NULL &&
	    options.permit_local_command)
		ssh_local_cmd(options.local_command);

	/*
	 * If requested and we are not interested in replies to remote
	 * forwarding requests, then let ssh continue in the background.
	 */
	if (fork_after_authentication_flag &&
	    (!options.exit_on_forward_failure ||
	    options.num_remote_forwards == 0)) {
		fork_after_authentication_flag = 0;
		if (daemon(1, 1) < 0)
			fatal("daemon() failed: %.200s", strerror(errno));
	}

	/*
	 * If a command was specified on the command line, execute the
	 * command now. Otherwise request the server to start a shell.
	 */
	if (buffer_len(&command) > 0) {
		int len = buffer_len(&command);
		if (len > 900)
			len = 900;
		debug("Sending command: %.*s", len,
		    (u_char *)buffer_ptr(&command));
		packet_start(SSH_CMSG_EXEC_CMD);
		packet_put_string(buffer_ptr(&command), buffer_len(&command));
		packet_send();
		packet_write_wait();
	} else {
		debug("Requesting shell.");
		packet_start(SSH_CMSG_EXEC_SHELL);
		packet_send();
		packet_write_wait();
	}
	

	/* Enter the interactive session. */
	return client_loop(have_tty, tty_flag ?
	    options.escape_char : SSH_ESCAPECHAR_NONE, 0);
}