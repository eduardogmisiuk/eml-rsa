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

#ifndef _EML_RSA_H_
#define _EML_RSA_H_

#include <string>

void decrypt (std::string &key_fn, std::string &message_fn, std::string &encrypted_message_fn);
void encrypt (std::string &key_fn, std::string &message_fn, std::string &encrypted_message_fn);

void generate_keys (std::string seed);

#endif // _EML_RSA_H_
