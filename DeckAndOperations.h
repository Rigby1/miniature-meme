/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   DeckAndOperatios.h
 * Author: Deniz
 *
 * Created on April 23, 2018, 9:30 PM
 */

#ifndef DECKANDOPERATIONS_H
#define DECKANDOPERATIONS_H

#include <gmpxx.h>
#include <vector>
#include <random>
#include <cstdint>
#include <iostream>
#include "CardClass.h"
#include <map>
#include <iterator>
#include <boost/asio.hpp>


typedef struct {
	mpz_class p;
	mpz_class g;
} Public_Key;

extern mpz_class Secret_Key;

using namespace std;

class CipherText : mpz_class {
public :
	mpz_class c_1, c_2;

	CipherText() {
	}
	CipherText(const mpz_class &msg) : c_1(1), c_2(msg) {
	}
	CipherText(const mpz_class &c_1, const mpz_class &c_2) : c_1(c_1), c_2(c_2) {
	}
	CipherText(const CipherText &ct) : c_1(ct.c_1), c_2(ct.c_2) {
	}

	std::vector<uint8_t> toBinary() {
		std::vector<uint8_t> r((this->bits() +7) / 8, 0);
		mpz_export(r.data(), nullptr, -1, sizeof(uint8_t), 0, 0, this->get_mpz_t());
		return r;
	}

	/**
	 * Return this number modulo power of 2.
	 * @param exp The exponent
	 * @return this number modulo power of 2
	 */

	size_t bits() {
		return mpz_sizeinbase(this->get_mpz_t(), 2);
	}
	size_t bytes() {
		return (this->bits() + 7) / 8;
	}

};

class PermutationClass {
private:
	size_t randomNumber(size_t min, size_t max){
		std::mt19937_64 gen(rdev());
		if(min<max){
			std::uniform_int_distribution<> dis(min, max-1);
			return dis(gen);
		}
		else
			return 0;
	}
public:
	std::random_device rdev;
	std::vector<size_t> map, rmap;


	PermutationClass() {

	}

	PermutationClass(size_t size) {
		for(size_t i = 0; i < size ; i++) {
			map.push_back(i);
			rmap.push_back(i);
		}
		randomize();
		updateRmap();
	}

	PermutationClass(size_t size, bool isRandom) {
		if(isRandom){
			for(size_t i = 0; i < size ; i++) {
				map.push_back(i);
				rmap.push_back(i);
			}
			randomize();
			updateRmap();
		}
		else{
			for(size_t i = 0; i < size ; i++) {
				map.push_back(i);
				rmap.push_back(i);
			}
			updateRmap();
		}
	}


	void randomize() {
		for (size_t i=0; i<map.size()-1; i++) {
			size_t j = randomNumber(i, map.size());
			iter_swap(map.begin() + i, map.begin() + j);
		}
		updateRmap();
	}

	void updateRmap() {
		for(size_t i=0; i<map.size(); i++) {
			rmap[map[i]] = i;
		}
	}


	size_t getElementFromMap(size_t i) {
		return map[i];
	}

	size_t getElementFromRMap(size_t i) {
		return rmap[i];
	}
};


inline std::ostream & operator<< (std::ostream &i, const CipherText &ct) {
	return i << "CipherText(" << ct.c_1 << ", " << ct.c_2 << ")";
}


class DeckAndOperations {
public:
	DeckAndOperations();
	void generateCardsAndPutIntoDeck();
	void shuffleDeck();
	void generatePublicKey(Public_Key *pk);
	void generateSecretKey(Public_Key *pk);
	mpz_class getEncryptedSecret();
	//    std::vector<uint8_t> getEncryptedSecretInBinary();
	mpz_class generateP (const mpz_class&);
	mpz_class findGforP (const mpz_class&);
	mpz_class secretRandomR (const mpz_class&);
	mpz_class contributeToSharedSecret(mpz_class inp);
	template <class T>
	void permutationShuffle(vector<T> &vectorToBePermutated, vector<size_t> mapToBeApplied){
		vector<T> newDeckVectorClass;

		for(size_t i = 0; i< mapToBeApplied.size(); i++){
			newDeckVectorClass.push_back(vectorToBePermutated.at(mapToBeApplied.at(i)));
		}
		vectorToBePermutated = newDeckVectorClass;

	}


	vector<mpz_class> generateSecretRandomRVector(const mpz_class &p, int size);

	CipherText mask_elGamal(const Public_Key &pk, const CipherText &ct, mpz_class *rp);
	vector<CipherText> re_mask_elGamal_deck(const Public_Key &pk, vector<CipherText> &vectorToRemasked, vector<mpz_class> &rp);
	CipherText unmask_elGamal(const Public_Key &pk, const CipherText &ct);
	vector<CipherText> mask_elGamal_deck();
//	vector<CipherText> mask_elGamal_masked_deck();
	CipherText finalize_unmask_elGamal(const Public_Key &pk, const CipherText &ct);
//	void reversePermutationShuffle(PermutationClass *pClass);
//	void reversePermutationShuffleForEncryptedVector(PermutationClass *pClass);
//	void permutationShuffleForEncryptedVector(PermutationClass *pClass);
	void transformCardClassVectorToMpzVector();
	Public_Key pk;
	vector<CipherText> deckVector;
	PermutationClass * permutationClass;

	mpz_class Shared_Public_Key;
	vector<CipherText> getDeck();
	DeckAndOperations(const DeckAndOperations& orig);
	DeckAndOperations(mpz_class p, mpz_class g);
	virtual ~DeckAndOperations();

private:
	size_t randomNumber(size_t, size_t);
	//    std::vector<uint8_t> toBinary(mpz_class input);
	//    size_t bits(mpz_class input);
	//    size_t bytes(mpz_class input);
	mpz_t cardsMultiplied; // not necessary at the moment , for the future; in order to keep track of number of cards
	int totalCardCount; // not necessary at the moment , for the future; in order to keep track of multiplication of the cards




};

#endif /* DECKANDOPERATIOS_H */

