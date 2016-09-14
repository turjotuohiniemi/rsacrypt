# History

I wrote this program to better understand how the RSA algorithm works.
Therefore, it only supports the number of bits that were conveniently
available to me at the time.

# Compile

Sorry, there's no Makefile for this one, but running
`gcc -o rsacrypt -Wall -O2 rsacrypt.c -lm`
on the command line should do the trick.

# How to use it

1. Find two prime numbers that are relatively close to each other.
For example:

```
	./rsacrypt -p 1500
	Testing 1501... not prime
	Testing 1503... not prime
	Testing 1505... not prime
	Testing 1507... not prime
	Testing 1509... not prime
	Testing 1511... is a prime

	./rsacrypt -p 1700
	Testing 1701... not prime
	Testing 1703... not prime
	Testing 1705... not prime
	Testing 1707... not prime
	Testing 1709... is a prime
```

2. Generate your public and private keys. Using the primes found above,
this would be:
```
	./rsacrypt -g 1511 1709
	Public key:  e = 3, n = 2582299
	Private key: d = 1719387
```

3. Encrypt the file you want using the public key. For example:

```
	./rsacrypt -e 3 2582299 README.md
```

4. Notice how the file looks like rubbish.

```
	od -Ax -tc README.md | head
```

5. Decrypt it

```
	./rsacrypt -d 1719387 2582299 README.md
```
