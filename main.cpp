/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   main.cpp
 * Author: rigo
 *
 * Created on April 23, 2018, 9:22 PM
 */

#include <cstdlib>
#include <iostream>
#include <vector>
#include <string>
#include <gmp.h>

#include "CardClass.h"
#include "DeckAndOperations.h"


using namespace std;

/*
 * 
 */
int main(int argc, char** argv) {
    
    DeckAndOperations * deck  = new DeckAndOperations;
    deck->generateCardsAndPutIntoDeck();
    vector<CardClass*> deckVector = deck->getDeck();
//    for(auto i = deckVector.begin(); i != deckVector.end(); i++){
//        //gmp_printf ("%s is %Zd\n", "Id", (*i)->id);
//        cout  << (*i)->representation << "\n";
//    }
   
    mpz_t p;
    mpz_t q;
    mpz_t r;
    mpz_t x;
    mpz_t m;

    mpz_init(p);
    mpz_init(q);
    mpz_init(r);
    mpz_init(x);
    mpz_init(m);
    mpz_set_si(p,241);
    mpz_set_si(q,13);
    mpz_set_si(r,2);
    mpz_set_si(x,3);
    mpz_set_si(m,5);
    
    //deck->shuffleDeck();
    //deck->encode (p,q,r,x,m);
    //m = 5 and m = 199 is encrypted as 57
    for(auto i = deckVector.begin(); i != deckVector.end(); i++){
        gmp_printf ("%s is %Zd\n", "id", (*i)->id);
        deck->encrypt_elGamal(p,q,r,x,(*i)->id);
        //deck->decode(p,q,r,x,(*i)->id);
    }
// // inverse and powm works   
//  mpz_t inverse;  
//  mpz_init(inverse);
//  mpz_invert(inverse,x,p);
//  mpz_powm(inverse,m,r,p);
//  gmp_printf ("%s is %Zd\n", "inverse", inverse);

    return 0;
}

