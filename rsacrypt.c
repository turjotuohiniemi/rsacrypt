/*
 * rsacrypt
 * data encryption/decryption using the Rivest-Shamir-Adleman algorithm
 *
 * This program is free software;
 * No Rights Reserved
 *
 * Purpose:
 * Use this program to encrypt or decrypt files with the RSA algorithm;
 * supports also generating RSA key pairs. This is a 32-bit implementation
 * so don't take it too seriously.
 *
 * Authors:
 * Turjo Tuohiniemi
 *
 * History:
 * 22-Feb-1999 turjo	First version (encryption only)
 * 17-Mar-2000 turjo	Added support for decryption
 *
 * Notes:
 * On Linux, compile by using the following command:
 * gcc -o rsacrypt -Wall -O2 rsacrypt.c -lm
 *
 * This program uses the non-standard long long data type, so it might not
 * compile with all C compilers.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

/*****************************************************************************
 archbits
 determine how many bits are needed to represent an int in this architechture

 Program exits if this funcion fails.
 
 returns:	the number of bits needed for an int minus one;
 		31 = return value for 32-bit systems
 *****************************************************************************/
unsigned archbits(void)
{
    if (sizeof(unsigned) == 4)
	return 31;
    puts("Program improperly compiled; number of architechture bits is undefined");
    exit(EXIT_FAILURE);
}

/*****************************************************************************
 bitsize
 determine how many bits are needed to represent the given integer
 
 returns:	the number of bits needed for representation
 
 number		number whose representation-bitcount should be determined
 *****************************************************************************/
unsigned bitsize(unsigned number)
{
    unsigned i;
    for (i = archbits(); i != 0; i--) {
	if (number >> i)
	    return i + 1;
    }
    return 0;
}

/*****************************************************************************
 ab_mod_n
 compute a^b mod n
 
 returns:	the result of the calculation
 
 a		the value of a
 b		the value of b (the exponent)
 n		the value of n (the modulo)
 *****************************************************************************/
unsigned ab_mod_n(unsigned a, unsigned b, unsigned n)
{
    unsigned long long C, D, A = a, B = b, N = n;
    unsigned i;
    C = 0;
    D = 1;

    for (i = archbits(); 1; i--) {
	C *= 2;
	D = (D * D) % N;
	if (B & (1 << i)) {
	    C++;
	    D = (D * A) % N;
	}
	if (i == 0)
	    break;
    }
    return (unsigned) D;
}

/*****************************************************************************
 is_prime
 determine if the given number is a prime

 Slow algorithm, which tries dividing the number with all integers up to
 the square root of the number.
 
 returns:	0 = given number is not a prime
 		1 = given number is a prime
 
 p		integer whose primeness should be checked
 *****************************************************************************/
unsigned is_prime(unsigned p)
{
    unsigned i, maxdiv;

    maxdiv = ceil((unsigned) sqrt(p));
    for (i = 2; i <= maxdiv; i++) {
	if ((p % i) == 0) {
	    return 0;
	}
    }
    return 1;
}

/*****************************************************************************
 find_inverse
 find multiplicative inverse for integer d, using a slow algorithm

 returns:	0 = there was another common divisor than 1
 		otherwise the multiplicative inverse of d

 d		the integer for which the iverse will be calculated
 f		the second integer, contains the modulo for the inverse
 *****************************************************************************/
unsigned find_inverse(unsigned d, unsigned f)
{
    unsigned i;
    for (i = 1; i < f; i++) {
	if ((i * d) % f == 1)
	    return i;
    }
    return 0;
}

/*****************************************************************************
 check_gcd
 find greatest common divisor and determine multiplicative inverse of d
 
 This function checks that the greatest common divisor of given integers d and
 f is 1, and if so, finds the multiplicative inverse of d.
 
 returns:	0 = there was another common divisor than 1
 		otherwise the multiplicative inverse of d

 d		the first integer (for which d^-1 will be calculated, too)
 f		the second integer
 *****************************************************************************/
unsigned check_gcd(unsigned d, unsigned f)
{
    int x1, x2, x3, y1, y2, y3, q, t1, t2, t3;

    x1 = 1;
    x2 = 0;
    x3 = f;
    y1 = 0;
    y2 = 1;
    y3 = d;
    while (y3 != 0) {
	if (y3 == 1) {
	    if (y2 < 0) {
#if 0
		puts("Internal check_gcd() consistency check, please wait...");
		if (find_inverse(d, f) != f + y2) {
		    printf("Consistency check failed:\n");
		    printf
			("cannot calculate multiplicative inverse for integer %d.\n",
			 d);
		    exit(EXIT_FAILURE);
		}
#endif
		return f + y2;
	    }
	    return y2;
	}
	q = x3 / y3;
	t1 = x1 - (q * y1);
	t2 = x2 - (q * y2);
	t3 = x3 - (q * y3);
	x1 = y1;
	x2 = y2;
	x3 = y3;
	y1 = t1;
	y2 = t2;
	y3 = t3;
    }
    /* gcd is in x3, but there's no inverse */
    return 0;
}

/*****************************************************************************
 generate_keys
 generate and print two key pairs from primes p and q, then exit
 
 p		first prime used in key generation
 q		second prime used in key generation
 *****************************************************************************/
void generate_keys(unsigned p, unsigned q)
{
    unsigned e, f, n, d = 0;
    n = p * q;
    if (bitsize(p) + bitsize(q) > 32) {
	puts("Error: the multiplication of p and q yields an integer too big.");
	puts("Try again with smaller values.");
	exit(EXIT_FAILURE);
    }
    f = (p - 1) * (q - 1);
    for (e = 2; e < f; e++) {
	if ((d = check_gcd(e, f)) != 0)
	    break;
    }
    if (e == f) {
	puts("Error: cannot calculate multiplicative reverse integer.");
	exit(EXIT_FAILURE);
    }
    printf("Public key:  e = %u, n = %u\n", e, n);
    printf("Private key: d = %u\n", d);
    exit(EXIT_SUCCESS);
}

/*****************************************************************************
 read_file
 read a file in memory
 
 returns:	-2 = one or more of the arguments were NULL
 		-1 = an error occured, error printed
 		0 = the file has been read

 name		filename
 buf		return value: pointer to file data buffer; 2*sizeof(int) extra
 		bytes are available at the end of the buffer
 len		return value: length of the file
 *****************************************************************************/
int read_file(char *name, char **buf, off_t * len)
{
    struct stat statbuf;
    off_t remaining;
    size_t bytcount;
    char *c;
    int fd, result;

    if (name == NULL || buf == NULL || len == NULL)
	return -2;

    /* open the file */
    if ((fd = open(name, O_RDONLY)) == -1) {
	perror(name);
	return -1;
    }
    /* get file length */
    if (fstat(fd, &statbuf) == -1) {
	perror("fstat");
	close(fd);
	return -1;
    }
    if ((*len = statbuf.st_size) == 0) {
	close(fd);
	return 0;
    }
    remaining = statbuf.st_size;

    /* allocate buffer for the file */
    if ((*buf = malloc(statbuf.st_size + 2 * sizeof(int))) == NULL) {
	puts("Out of memory");
	close(fd);
	return -1;
    }

    /* read the file */
    c = *buf;
    while (remaining > 0) {
	if ((bytcount = remaining) > 2048)
	    bytcount = 2048;
	if ((result = read(fd, c, bytcount)) <= 0) {
	    puts("File read error");
	    close(fd);
	    free(*buf);
	    return -1;
	}
	remaining -= result;
	c += result;
    }
    /* we're done */
    close(fd);
    return 0;
}

/*****************************************************************************
 write_file
 write a memory block to file
 
 returns:	-1 = an error occured, error printed
 		0 = the file has been written

 name		filename, if NULL then file descriptor custfd is used
 buf		pointer to file data buffer
 len		length of the buffer
 custfd		file descriptor to which the block is written, ignored
 		if the name argument is not NULL
 *****************************************************************************/
int write_file(char *name, unsigned char *buf, off_t len, int custfd)
{
    size_t result, bytcount;
    off_t remaining;
    unsigned char *c;
    int fd;

    /* open file */
    if (name) {
	if ((fd = open(name, O_WRONLY | O_TRUNC)) == -1) {
	    perror(name);
	    return -1;
	}
	custfd = 0;
    } else
	fd = custfd;
    /* write data to it */
    remaining = len;
    c = buf;
    while (remaining > 0) {
	if ((bytcount = remaining) > 2048)
	    bytcount = 2048;
	if ((result = write(fd, c, bytcount)) == (size_t) - 1) {
	    perror(name);
	    if (!custfd)
		close(fd);
	    return -1;
	}
	if (result == 0) {
	    puts("File write error");
	    if (!custfd)
		close(fd);
	    return -1;
	}
	remaining -= result;
	c += result;
    }
    /* we're done */
    if (!custfd)
	close(fd);
    return 0;
}

/*****************************************************************************
 readbits
 read n bits from the given pointer
 
 returns:	read bits
 
 buf		pointer to buffer from which read bits, updated after read
 bitpos		next bit to read from the start of buf, 0 = start from the
 		beginning, updated after read
 n		number of bits to read
 *****************************************************************************/
unsigned readbits(unsigned char **buf, unsigned *bitpos, unsigned n)
{
    unsigned result, counter;

    result = 0;
    counter = 0;
    while (n != 0) {
	result |= ((**buf >> *bitpos) & 1) << counter;
	if (++(*bitpos) >= 8) {
	    *bitpos = 0;
	    (*buf)++;
	}
	n--;
	counter++;
    }
    return result;
}

/*****************************************************************************
 writebits
 write n bits to the given pointer
 
 buf		buffer to which write the bits, updated after write
 bitpos		next bit in buffer to which write a bit, 0 = beginning,
 		updated after write
 n		how many bits should be written
 value		value to write
 *****************************************************************************/
void writebits(unsigned char **buf, unsigned *bitpos, unsigned n,
	       unsigned value)
{
    unsigned counter;

    counter = 0;
    while (n != 0) {
	(**buf) |= ((value >> counter) & 1) << *bitpos;
	if (++(*bitpos) >= 8) {
	    *bitpos = 0;
	    (*buf)++;
	}
	n--;
	counter++;
    }
}

/*****************************************************************************
 encrypt_file
 encrypt a file and exit
 
 name		filename
 e		the public key (integer e)
 n		the modulo (integer n)
 *****************************************************************************/
void encrypt_file(char *name, unsigned e, unsigned n)
{
    unsigned int srcbits, destbits, dest_textbit, textbit, extraspace;
    off_t buflen;
    unsigned char *buf, *destbuf, *dest_text, *text;
    int fd;

    /* read file into memory (the buffer will have some extra bytes) */
    if (read_file(name, (char **) &buf, &buflen) != 0) {
	exit(EXIT_FAILURE);
    }
    /* allocate buffer for encrypted data (will need one bit extra space per */
    /* source word, plus two ints for padding) */
    destbits = bitsize(n);
    srcbits = destbits - 1;
    extraspace = 2 * sizeof(int) + buflen / srcbits;
    if ((dest_text = destbuf = malloc(buflen + extraspace)) == NULL) {
	puts("Not enough memory");
	exit(EXIT_FAILURE);
    }
    /* encrypt the data */
    text = buf;
    dest_textbit = textbit = 0;
    while (text < buf + buflen) {
	writebits(&dest_text, &dest_textbit, destbits,
		  ab_mod_n(readbits(&text, &textbit, srcbits), e, n));
    }
    /* open the file for rewriting */
    if ((fd = open(name, O_WRONLY | O_TRUNC)) == -1) {
	perror(name);
	exit(EXIT_FAILURE);
    }
    /* write original length of the file */
    if (write(fd, &buflen, sizeof(buflen)) != sizeof(buflen)) {
	puts("File write error");
	close(fd);
	exit(EXIT_FAILURE);
    }
    /* write actual file data */
    if (write_file(NULL, destbuf, dest_text - destbuf + 1, fd) != 0) {
	close(fd);
	exit(EXIT_FAILURE);
    }
    close(fd);
    exit(EXIT_SUCCESS);
}

/*****************************************************************************
 decrypt_file
 decrypt a file and exit
 
 name		filename
 d		the secret key (integer d)
 n		the modulo (integer n)
 *****************************************************************************/
void decrypt_file(char *name, unsigned d, unsigned n)
{
    unsigned int srcbits, dstbits, bitpos_src, bitpos_dst;
    int lendiff, maxdiff;
    off_t buflen, origfilelen;
    unsigned char *buf, *decrpt_buf, *decrpt_src, *decrpt_dst, *endmark;

    /* read file into memory (the buffer will have a few extra bytes) */
    if (read_file(name, (char **) &buf, &buflen) != 0) {
	exit(EXIT_FAILURE);
    }
    /* determine length of original file and check that it makes sense */
    srcbits = bitsize(n);
    dstbits = srcbits - 1;
    origfilelen = *(off_t *) buf;
    buf += sizeof(off_t);
    lendiff = origfilelen - (buflen - sizeof(off_t));
    maxdiff = origfilelen / dstbits + 1 + 2 * sizeof(int);
    if (origfilelen < 0 || lendiff < -maxdiff || lendiff > maxdiff) {
	puts("File is corrupted, cannot decrypt");
	exit(EXIT_FAILURE);
    }
    /* allocate buffer for decrypted data */
    if ((decrpt_dst = decrpt_buf =
	 malloc(origfilelen + 2 * sizeof(int))) == NULL) {
	puts("Not enough memory");
	exit(EXIT_FAILURE);
    }
    /* decrypt the data */
    decrpt_src = buf;
    bitpos_src = bitpos_dst = 0;
    endmark = decrpt_dst + origfilelen;
    while (decrpt_dst <= endmark) {
	writebits(&decrpt_dst, &bitpos_dst, dstbits,
		  ab_mod_n(readbits(&decrpt_src, &bitpos_src, srcbits), d,
			   n));
    }
    /* save decrypted data */
    if (write_file(name, decrpt_buf, origfilelen, -1) == -1)
	exit(EXIT_FAILURE);
    else
	exit(EXIT_SUCCESS);
}

/*****************************************************************************
 find_next_prime
 find a prime number, print it and exit
 
 n		number from which start testing for a prime
 *****************************************************************************/
void find_next_prime(unsigned n)
{
    if ((n & 1) == 0)
	n |= 1;
    while (n + 1 != 0) {
	printf("Testing %u... ", n);
	fflush(stdout);
	if (is_prime(n)) {
	    printf("is a prime\n");
	    exit(EXIT_SUCCESS);
	}
	printf("not prime\n");
	n += 2;
    }
    puts("Could not find a prime");
    exit(EXIT_FAILURE);
}

/*****************************************************************************
 usage
 print usage and exit
 *****************************************************************************/
void usage(void)
{
    puts("Usage: rsa -p n           (find a prime number, starting from n)");
    puts("       rsa -g p q         (generates keys from primes p and q)");
    puts("       rsa -e e n file    (encrypts file with public key pair e and n)");
    puts("       rsa -d d n file    (decrypts file with private key pair d and n)");
    exit(EXIT_SUCCESS);
}

/*****************************************************************************
 a2ui
 convert a string into an unsigned integer
 
 returns:	0 = the string did not represent a valid unsigned integer
 		otherwise unsigned integer represented by the string

 str		string to be converted
 *****************************************************************************/
unsigned int a2ui(const char *str)
{
    unsigned long int val;
    char *terminatr;
    val = strtoul(str, &terminatr, 10);
    if (*terminatr != 0)
	return 0;
    return val;
}

int main(int argc, char **argv)
{
    /* serve our customer... */
    if (argc == 3) {
	if (!strcmp(argv[1], "-p"))
	    find_next_prime(a2ui(argv[2]));
    }
    if (argc < 4 || argc > 5)
	usage();
    if (!strcmp(argv[1], "-g"))
	generate_keys(a2ui(argv[2]), a2ui(argv[3]));
    if (!strcmp(argv[1], "-e"))
	encrypt_file(argv[4], a2ui(argv[2]), a2ui(argv[3]));
    if (!strcmp(argv[1], "-d"))
	decrypt_file(argv[4], a2ui(argv[2]), a2ui(argv[3]));

    /* we don't know what he or she wants */
    printf("%s: unknown option\n", argv[1]);
    return EXIT_SUCCESS;
}
