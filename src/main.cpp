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

#include <cstdlib>
#include <iostream>
#include <fstream>
#include <string>
#include <gmpxx.h>

#include "eml-rsa.h"

int main (int argc, char *argv[]) {
	std::string key_fn = argv[3];
	std::string message_fn;
	std::string encrypted_message_fn;
	std::string seed;
	char option = argv[2][0];

	switch (option) {
		case 'D':
			message_fn = argv[4];
			encrypted_message_fn = argv[5];

			decrypt(key_fn, message_fn, encrypted_message_fn);
			break;

		case 'E':
			encrypted_message_fn = argv[4];
			message_fn = argv[5];

			encrypt(key_fn, message_fn, encrypted_message_fn);
			break;

		case 'K':
			seed = argv[4];

			generate_keys(seed);
			break;
	}

	return EXIT_SUCCESS;
}
