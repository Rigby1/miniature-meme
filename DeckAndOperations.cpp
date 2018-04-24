/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   DeckAndOperatios.cpp
 * Author: rigo
 * 
 * Created on April 23, 2018, 9:30 PM
 */

#include "DeckAndOperations.h"

using namespace std;

DeckAndOperations::DeckAndOperations() {
    mpz_init(cardsMultiplied);
    mpz_set_si(cardsMultiplied,1);
    totalCardCount = 0;
}

DeckAndOperations::DeckAndOperations(const DeckAndOperations& orig) {
}

DeckAndOperations::~DeckAndOperations() {
}

void DeckAndOperations::generateCardsAndPutIntoDeck(){
    mpz_t aPrime;
    mpz_init(aPrime);
    mpz_set_si(aPrime,1);
    int type;
    int number;
    string representation;
    for(int i=0; i<52 ; i++){
        type = i / 13;
        if(i % 13 == 0)
            number = 13;
        else
            number = i%13;
        if (type == 0)
            representation = "clubs " + to_string(number);
	else if (type == 1) 
            representation = "diamonds " + to_string(number);
	else if (type == 2) 
            representation = "hearts " + to_string(number);
	else if (type == 3) 
            representation = "spades " + to_string(number);
        
        
        mpz_nextprime(aPrime, aPrime);
        CardClass* card = new CardClass(aPrime, type, number, representation);
        representation = "";

        totalCardCount++;
        mpz_mul(cardsMultiplied,cardsMultiplied,aPrime);
        deckVector.push_back(card);
        //gmp_printf ("%s is an mpz %Zd\n", "here", aPrime);
    }
}

vector<CardClass*> DeckAndOperations::getDeck(){
    return deckVector;
}

void DeckAndOperations::shuffleDeck(){
//    mpz_t rand_Num;
//    mpz_init(rand_Num);
    vector<CardClass*> newDeck;


    //for(int i=0 ; i<52;i++){

    
    int generatedRandomValue = randomNumber(0,deckVector.size());
//    newDeck.push_back(deckVector.at(generatedRandomValue));
//    deckVector.erase(deckVector.begin()+generatedRandomValue);
//    cout<<deckVector.size();
    //}
   // cout<< "Deck size:"<<deckVector.size() << "\n";
    while(deckVector.size() > 0){
        //gmp_printf ("%s is %Zd\n", "Id", (*i)->id);
        //cout<< "GeneratedRandomValue" << generatedRandomValue << "\n";
        newDeck.push_back(deckVector.at(generatedRandomValue));
        deckVector.erase(deckVector.begin()+generatedRandomValue);
        generatedRandomValue = randomNumber(0,deckVector.size());
    }

    deckVector = newDeck;

   
//    mpz_t vectorSize;
//    mpz_init(vectorSize);
//    mpz_set_ui(vectorSize,deckVector.size());
//    
//    gmp_randstate_t r_state;
//    gmp_randinit_mt(r_state);
//    mpz_urandomm(rand_Num,r_state,vectorSize);
//    gmp_printf ("%s is %Zd\n", "Random Number", rand_Num);

}

int DeckAndOperations::randomNumber(int min, int max){
    if(min<max){
        std::random_device rdev;
        std::mt19937 gen(rdev());
        std::uniform_int_distribution<> dis(min, max-1);
        return dis(gen);
    }
    else 
        return 0;
}

void DeckAndOperations::encrypt_elGamal(mpz_t p, mpz_t g, mpz_t r_a, mpz_t x_a, mpz_t m){
  mpz_t c_1;
  mpz_t c_2;
  mpz_t g_to_x_to_r;
  mpz_init(g_to_x_to_r);
  mpz_init(c_1);
  mpz_init(c_2);
  
  mpz_powm(c_1,g,r_a,p);
  mpz_powm(g_to_x_to_r,g,x_a,p);
  mpz_powm(g_to_x_to_r,g_to_x_to_r,r_a,p);
//  mpz_mod(c_1,c_1,p);
    
  
//  mpz_mul(r_times_x,r_a,x_a);
//  mpz_powm(c_2,g,r_times_x,p);
  mpz_mul(c_2,g_to_x_to_r,m);
  mpz_mod(c_2,c_2,p);
  
    gmp_printf ("%s is %Zd\n", "c_1", c_1);
    gmp_printf ("%s is %Zd\n", "c_2", c_2);
  decrypt_elGamal(c_1,c_2,r_a,x_a,p,g);

}


void DeckAndOperations::decrypt_elGamal(mpz_t c_1, mpz_t c_2, mpz_t r_a, mpz_t x_a, mpz_t p, mpz_t q){

  mpz_t g_to_x_to_r;
  mpz_init(g_to_x_to_r);
    
  mpz_t c_to_x_inverse;
  mpz_init(c_to_x_inverse);
//  
  mpz_powm(c_to_x_inverse,c_1,x_a,p);
  mpz_invert(c_to_x_inverse,c_to_x_inverse,p);

  
  mpz_t message;
  mpz_init(message);
 
  
  mpz_mul(message,c_2,c_to_x_inverse);
  mpz_mod(message,message,p);
  gmp_printf ("%s is %Zd\n", "message", message);
    cout << "\n";


//  
//  mpz_mul(r_times_x,r_a,x_a);
//  mpz_powm(c_2,g,r_times_x,p);
//  mpz_mul(c_2,c_2,m);
//  mpz_mod(c_2,c_2,p);
  
//  gmp_printf ("%s is %Zd\n", "c_1", c_1);
  //gmp_printf ("%s is %Zd\n", "c_2", c_2);


}
