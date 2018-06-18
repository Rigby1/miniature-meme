/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   DeckAndOperatios.h
 * Author: rigo
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
    void permutationShuffle(vector<int> *pMap);
    CipherText mask_elGamal(const Public_Key &pk, const CipherText &ct, mpz_class *r);
    CipherText unmask_elGamal(const Public_Key &pk, const CipherText &ct);
    void reversePermutationShuffle(vector<int> pVector);
    Public_Key pk;
    mpz_class Shared_Secret_Key;
    vector<CardClass*> getDeck();
    DeckAndOperations(const DeckAndOperations& orig);
    DeckAndOperations(mpz_class p, mpz_class g);
    virtual ~DeckAndOperations();

private:
    int randomNumber(int,int);
//    std::vector<uint8_t> toBinary(mpz_class input);
//    size_t bits(mpz_class input);
//    size_t bytes(mpz_class input);
    mpz_t cardsMultiplied;
    int totalCardCount;
    vector<CardClass*> deckVector;

};

#endif /* DECKANDOPERATIOS_H */

