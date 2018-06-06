/*
 * EML RSA - Alternative RSA implementation.
 * 
 * Authors:
 * Eduardo Garcia Misiuk <eduardogmisiuk@gmail.com>
 * Mauricio Caetano Silva <mauriciocaetanosilva@gmail.com>
 * Lucas Yudi Sugi <lucas.sugi@usp.br>
 */

/*
 	This file is part of EML RSA.

	EML RSA is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	EML RSA is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with EML RSA. If not, see <http://www.gnu.org/licenses/>.
*/

#include <iostream>
#include <fstream>
#include <cstdlib>
#include <string>
#include <vector>
#include <gmpxx.h>

#include "eml-rsa.h"

#define KEY_LENGTH_BITS 256
#define REPEAT_MILLER_RABIN 50

// Function used to generate random numbers
gmp_randclass rnd(gmp_randinit_default);

void decrypt (std::string &key_fn, std::string &message_fn, std::string &encrypted_message_fn) {
	mpz_class n, d, n1, res, character;
	std::vector <mpz_class> encrypted_message;

	std::string message = "";

	// Key and encrypted message files
	std::ifstream key_f, encrypted_message_f;
	// Decrypted message file
	std::ofstream message_f;

	// Reading the key from key_fn
	key_f.open(key_fn, std::ios::in);
	key_f >> n;
	key_f >> d;
	key_f >> n1;
	key_f.close();

	// Reading the message from message_fn
	encrypted_message_f.open(encrypted_message_fn, std::ios::in | std::ios::binary);
	do {
		encrypted_message_f >> character;
		encrypted_message.push_back(character);
	} while (!encrypted_message_f.eof());
	// The last character at 'message' will be EOF, so we need to get rid of him
	encrypted_message_f.close();

	// Since our message is separated by spaces, we can get
	// the characters directly from the file
	for (mpz_class &c : encrypted_message) {
		// Applying Caesar's Cypher with the second generated key
		c -= n1;

		// mpz_powm() doesn't prevent timing attacks, but mpz_powm_sec() does
		// res = character**d mod n
		mpz_powm_sec(res.get_mpz_t(), c.get_mpz_t(), d.get_mpz_t(), n.get_mpz_t());

		c = 0;

		// We can't convert from mpz_t to char directly,
		// so we convert to signed long int and then to char
		// We can convert to char because now it's an ASCII character
		// Since we treated the value as unsigned at the encryption,
		// we need to treat it as a signed char again to recover the original
		// character
		message += (signed char) mpz_get_si(res.get_mpz_t());
	}

	// Writes the message in the message file
	message_f.open(message_fn, std::ios::out);
	message_f << message;
	message_f.close();

	// Removing the values from the memory for security
	n = 0;
	d = 0;
	n1 = 0;
	res = 0;
}

void encrypt (std::string &key_fn, std::string &message_fn, std::string &encrypted_message_fn) {
	mpz_class n, n1, e, res, character;

	std::string message = "";
	std::string encrypted_message = "";
	std::string temp = "";

	// Key and message files
	std::ifstream key_f, message_f;
	std::ofstream encrypted_message_f;

	// Reading the key from key_fn
	key_f.open(key_fn, std::ios::in);
	key_f >> n;
	key_f >> e;
	key_f >> n1;
	key_f.close();

	// Reading the message from message_fn
	message_f.open(message_fn, std::ios::in);
	do {
		message += message_f.get();
	} while (!message_f.eof());
	// The last character at 'message' will be EOF, so we need to get rid of him
	message.pop_back();
	message_f.close();

	for (char &c : message) {
		// We read the character as a unsigned char because the RSA needs the message to
		// be within 1 < character < n-1
		// Treating it as positive, we can encrypt any kind of file, since some
		// characters can be negative in images, for example
		character = (unsigned char) c;
		// Replacing the message characters to improve security
		c = '0';
		// mpz_powm() doesn't prevent timing attacks, but mpz_powm_sec() does
		mpz_powm_sec(res.get_mpz_t(), character.get_mpz_t(), e.get_mpz_t(), n.get_mpz_t());

		// Applying Caesar's Cypher with the second generated key
		res += n1;

		encrypted_message += res.get_str() + " ";
		character = 0;
	}

	encrypted_message.pop_back();

	encrypted_message_f.open(encrypted_message_fn, std::ios::out | std::ios::binary);
	encrypted_message_f << encrypted_message;
	encrypted_message_f.close();

	// Removing the values from the memory for security
	n = 0;
	e = 0;
	n1 = 0;
	res = 0;
}

mpz_class generate_rand_number(const unsigned int size, bool specific_bits_length){
	// Inferior limit (bits number)
	mpz_class min;
	mpz_ui_pow_ui(min.get_mpz_t(), 2, size-1);

	// Superior limit(numero de bits)
	mpz_class max;
	mpz_ui_pow_ui(max.get_mpz_t(), 2, size);
	
	mpz_class randnumber = rnd.get_z_range(max-min);

	//Se o modo for 2, o intervalo de sorteio eh: (0 - 2^size)
	if(!specific_bits_length) min = 0;
	
	return (min+randnumber);
}

mpz_class generate_rand_number(const unsigned int size, unsigned long int seed, bool specific_bits_length){
	// Inferior limit (bits number)
	mpz_class min;
	mpz_ui_pow_ui(min.get_mpz_t(), 2, size-1);

	// Superior limit(numero de bits)
	mpz_class max;
	mpz_ui_pow_ui(max.get_mpz_t(), 2, size);
	
	mpz_class randnumber = rnd.get_z_range(max-min);

	// Verify if the generated number must have specific bit size
	if(!specific_bits_length) min = 0;
	
	return (min+randnumber);
}

mpz_class generate_rand_prime(const unsigned int size, unsigned long int seed){
	mpz_class candidate;
	mpz_class nx_prime;
	bool specific_bits_length = true;

	// Generates a random candidate number with specific size
	candidate = generate_rand_number(size, seed, specific_bits_length);

	// Check the primality of the candidate number with "Miller-Rabin" algorithm
	if(mpz_probab_prime_p(candidate.get_mpz_t(), REPEAT_MILLER_RABIN) == 0){	

		// If candidate isn't a prime, then select the next prime number greater than candidate 
		mpz_nextprime(nx_prime.get_mpz_t(), candidate.get_mpz_t());

		// Remove previous value of candidate for secury
		candidate = 0;
		return nx_prime;
	}

	return candidate;
}

mpz_class select_e(mpz_class tot){
	mpz_class e;
	mpz_class coprimes;
	bool specific_bits_length = false;
	
	// Select an integer "e" in the range of 1 < e < tot, "e" and tot are coprimes
	do{
		// "KEY_LENGTH_BITS - 1" ensures that "e" will have a smaller value than the totient "tot" 
		// because of its smaller size in bits
		e = generate_rand_number(KEY_LENGTH_BITS-1, specific_bits_length);

		// Verifies if "e" and "tot" are coprimes 
		mpz_gcd(coprimes.get_mpz_t(), e.get_mpz_t(), tot.get_mpz_t());
	}while(mpz_cmp_ui(coprimes.get_mpz_t(),1) != 0);

	coprimes = 0;	
	return e;
}

mpz_class modular_minverse(mpz_class e, mpz_class tot){
	mpz_class d;
	
	// Calculus of "d" as modular multiplicative inverse of e(modulo(tot))
	mpz_invert(d.get_mpz_t(), e.get_mpz_t(), tot.get_mpz_t());
	
	return d;
}

void generate_keys(unsigned long int seed, std::string &key_fn){
	rnd.seed(seed);

	// "p" and "q" are two prime numbers with the size "KEY_LENGTH_BITS"
	mpz_class p = generate_rand_prime(KEY_LENGTH_BITS, seed);
	mpz_class q = generate_rand_prime(KEY_LENGTH_BITS, seed);
	// Generating the second key
	mpz_class n1 = generate_rand_prime((KEY_LENGTH_BITS/2), seed);

	// "n" saves the value of p*q
	mpz_class n = p * q;

	// "Tot" contains the totient value lcm[(p-1)*(q-1)]
	mpz_class tot;
	mpz_class aux1 = p-1;
	mpz_class aux2 = q-1;

	mpz_lcm(tot.get_mpz_t(), aux1.get_mpz_t(), aux2.get_mpz_t());

	// Select an integer "e" in the range of 1 < e < tot, "e" and tot are coprimes
	mpz_class e = select_e(tot);

	// Calculus of "d" as modular multiplicative inverse of e(modulo(tot))
	mpz_class d = modular_minverse(e, tot);

	// Create file with the public key
	std::string key_pub_fn = key_fn;
	key_pub_fn += ".pub";

	std::ofstream key_pub_f;
	key_pub_f.open(key_pub_fn, std::ios::out);
	key_pub_f << n;
	key_pub_f << "\n";
	key_pub_f << e;
	key_pub_f << "\n";
	key_pub_f << n1;
	key_pub_f.close();

	// Create file with the private key
	std::string key_prv_fn = key_fn;
	key_prv_fn += ".prv";

	std::ofstream key_prv_f;
	key_prv_f.open(key_prv_fn, std::ios::out);
	key_prv_f << n;
	key_prv_f << "\n";
	key_prv_f << d;
	key_prv_f << "\n";
	key_prv_f << n1;
	key_prv_f.close();

	// Removing the values from the memory for security
	p = 0;
	q = 0;
	n = 0;
	n1 = 0;
 	tot = 0;
	e = 0;
	d = 0;
	aux1 = 0;
	aux2 = 0;
}
