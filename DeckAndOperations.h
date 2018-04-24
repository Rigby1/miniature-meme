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

#include <gmp.h>
#include <vector>
#include <random>
#include <iostream>
#include "CardClass.h"


using namespace std;

class DeckAndOperations {
public:
    DeckAndOperations();
    void generateCardsAndPutIntoDeck();
    void shuffleDeck();
    void encrypt_elGamal(mpz_t,mpz_t,mpz_t,mpz_t,mpz_t);
    void decrypt_elGamal(mpz_t,mpz_t,mpz_t,mpz_t,mpz_t,mpz_t);
    vector<CardClass*> getDeck();
    DeckAndOperations(const DeckAndOperations& orig);
    virtual ~DeckAndOperations();
private:
    int randomNumber(int,int);
    mpz_t cardsMultiplied;
    int totalCardCount;
    vector<CardClass*> deckVector;
};

#endif /* DECKANDOPERATIOS_H */

