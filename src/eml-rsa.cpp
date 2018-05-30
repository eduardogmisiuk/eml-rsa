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
#include <cmath>
#include <gmpxx.h>

#include "eml-rsa.h"

// TODO: generate_keys(*)
// TODO: unicode 

void decrypt (std::string &key_fn, std::string &message_fn, std::string &encrypted_message_fn) {
	mpz_class n, d, res, character;

	std::string message = "", encrypted_message = "";

	// Key and encrypted message files
	std::ifstream key_f, encrypted_message_f;
	// Decrypted message file
	std::ofstream message_f;

	// Reading the key from key_fn
	key_f.open(key_fn, std::ios::in);
	key_f >> n;
	key_f >> d;
	key_f.close();

	encrypted_message_f.open(encrypted_message_fn, std::ios::in);
	// Since our message is separated by spaces, we can get
	// the characters directly from the file
	do {
		encrypted_message_f >> character;

		// res = character**d mod n
		mpz_powm(res.get_mpz_t(), character.get_mpz_t(), d.get_mpz_t(), n.get_mpz_t());

		// We can't convert from mpz_t to char directly,
		// so we convert to signaled long int and then to char
		// We can convert to char because now it's an ASCII character
		message += (char) mpz_get_si(res.get_mpz_t());

	} while (!encrypted_message_f.eof());
	encrypted_message_f.close();

	// Writes the message in the message file
	message_f.open(message_fn, std::ios::out);
	message_f << message;
	message_f.close();

	// Removing the values from the memory for security
	n = 0;
	d = 0;
	res = 0;
}

void encrypt (std::string &key_fn, std::string &message_fn, std::string &encrypted_message_fn) {
	mpz_class n, e, res, character;

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
	key_f.close();

	// Reading the message from message_fn
	message_f.open(message_fn, std::ios::in);
	// 'message_f >> temp' reads until certain symbols, so we need to certify that
	// it will go until the end
	do {
		message += message_f.get();
	} while (!message_f.eof());
	// The last character at 'message' will be EOF, so we need to get rid of him
	message.pop_back();
	std::cout << message << std::endl;
	message_f.close();

	// Modular exponentiation: character**e mod n
	for (char &c : message) {
		character = c;
		mpz_powm(res.get_mpz_t(), character.get_mpz_t(), e.get_mpz_t(), n.get_mpz_t());
		// Replacing the message characters to improve security
		c = '0';
		encrypted_message += res.get_str() + " ";
		character = 0;
	}

	encrypted_message.pop_back();
	std::cout << "Encrypted: " << encrypted_message << std::endl;

	encrypted_message_f.open(encrypted_message_fn, std::ios::out);
	encrypted_message_f << encrypted_message;
	encrypted_message_f.close();

	// Removing the values from the memory for security
	n = 0;
	e = 0;
	res = 0;
}

void generate_keys (std::string seed){
	// TODO
}
