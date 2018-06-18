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

std::random_device rdev;
std::mt19937_64 gen(rdev());

mpz_class Secret_Key;


DeckAndOperations::DeckAndOperations() {
    mpz_init(cardsMultiplied);
    mpz_set_si(cardsMultiplied,1);
    totalCardCount = 0;
    generatePublicKey(&pk);
}


DeckAndOperations::DeckAndOperations(mpz_class p, mpz_class g) {
    mpz_init(cardsMultiplied);
    mpz_set_si(cardsMultiplied,1);
    totalCardCount = 0;
    pk.p = p;
    pk.g = g;
    generateSecretKey(&pk);
}

DeckAndOperations::DeckAndOperations(const DeckAndOperations& orig) {
}

DeckAndOperations::~DeckAndOperations() {
}


void DeckAndOperations::generateCardsAndPutIntoDeck(){
    mpz_class aPrime;
    aPrime = 1;
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
        
        
        mpz_nextprime(aPrime.get_mpz_t(), aPrime.get_mpz_t());
        CardClass* card = new CardClass(aPrime, type, number, representation);
        representation = "";

        totalCardCount++;
        mpz_mul(cardsMultiplied,cardsMultiplied,aPrime.get_mpz_t());
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

    
//    newDeck.push_back(deckVector.at(generatedRandomValue));
//    deckVector.erase(deckVector.begin()+generatedRandomValue);
//    cout<<deckVector.size();
    //}
   // cout<< "Deck size:"<<deckVector.size() << "\n";
    while(deckVector.size() > 0){
        int generatedRandomValue = randomNumber(0,deckVector.size());
        //gmp_printf ("%s is %Zd\n", "Id", (*i)->id);
        //cout<< "GeneratedRandomValue" << generatedRandomValue << "\n";
        newDeck.push_back(deckVector.at(generatedRandomValue));
        deckVector.erase(deckVector.begin()+generatedRandomValue);
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

void DeckAndOperations::permutationShuffle(vector<int> *pVector){
	vector<int> permutationVector;

    for(int i = 0; i<5000 ; i ++){
        int generatedRandomValueOne = randomNumber(0,deckVector.size());
        permutationVector.push_back(generatedRandomValueOne);
        iter_swap(deckVector.begin(), deckVector.begin() + generatedRandomValueOne);
    }

	if(pVector != NULL){
		*pVector = permutationVector;
	}

}

void DeckAndOperations::reversePermutationShuffle(vector<int> pVector){
	  for (auto rit = pVector.crbegin(); rit != pVector.crend(); ++rit){
	        iter_swap(deckVector.begin()  + *rit, deckVector.begin());
	  }

}

int DeckAndOperations::randomNumber(int min, int max){
    if(min<max){

        std::uniform_int_distribution<> dis(min, max-1);
        return dis(gen);
    }
    else 
        return 0;
}

//void DeckAndOperations::encrypt_elGamal(Public_Key *pk, mpz_class m){
//	  mpz_class c_1;
//	  mpz_class c_2;
//	  mpz_class g_to_x_to_r;
//
//	  mpz_powm(c_1.get_mpz_t(),pk->g.get_mpz_t(),secretRandomR(pk->p).get_mpz_t(),pk->p.get_mpz_t());
//	  mpz_powm(g_to_x_to_r.get_mpz_t(),pk->g.get_mpz_t(),Secret_Key.get_mpz_t(),pk->p.get_mpz_t());
//	  mpz_powm(g_to_x_to_r.get_mpz_t(),g_to_x_to_r.get_mpz_t(),secretRandomR(pk->p).get_mpz_t(),pk->p.get_mpz_t());
//	//  mpz_mod(c_1,c_1,p);
//
//
//	//  mpz_mul(r_times_x,r_a,x_a);
//	//  mpz_powm(c_2,g,r_times_x,p);
//	  c_2 = (g_to_x_to_r * m) % pk->p;
//
//	  cout << "c1 : " << c_1 << "\n";
//	  cout << "c2 : " << c_2 << "\n";
//
//}

CipherText DeckAndOperations::mask_elGamal(const Public_Key &pk, const CipherText &ct, mpz_class *rp) {
	mpz_class r = secretRandomR(pk.p);


	if (rp != NULL) {
		*rp = r;
	}

	mpz_class g_to_r;
	mpz_class y_to_r;


	mpz_class y;
	mpz_powm((y).get_mpz_t(),(pk.g).get_mpz_t(),Secret_Key.get_mpz_t(),(pk.p).get_mpz_t());



	mpz_powm(g_to_r.get_mpz_t(),pk.g.get_mpz_t(),r.get_mpz_t(),pk.p.get_mpz_t());
	mpz_powm(y_to_r.get_mpz_t(),y.get_mpz_t(),r.get_mpz_t(),pk.p.get_mpz_t());


	return CipherText(ct.c_1 * g_to_r % pk.p, ct.c_2 * y_to_r % pk.p);
}

CipherText DeckAndOperations::unmask_elGamal(const Public_Key &pk, const CipherText &ct){

	mpz_class unmasked;
	mpz_powm(unmasked.get_mpz_t(),ct.c_1.get_mpz_t(),Secret_Key.get_mpz_t(),pk.p.get_mpz_t());
	mpz_invert(unmasked.get_mpz_t(),unmasked.get_mpz_t(),pk.p.get_mpz_t());
	return CipherText(unmasked * ct.c_2 % pk.p);
}



//void DeckAndOperations::decrypt_elGamal(mpz_t c_1, mpz_t c_2, mpz_t r_a, mpz_t x_a, mpz_t p, mpz_t q){
//
//  mpz_t g_to_x_to_r;
//  mpz_init(g_to_x_to_r);
//
//  mpz_t c_to_x_inverse;
//  mpz_init(c_to_x_inverse);
////
//  mpz_powm(c_to_x_inverse,c_1,x_a,p);
//  mpz_invert(c_to_x_inverse,c_to_x_inverse,p);
//
//
//  mpz_t message;
//  mpz_init(message);
//
//  
//  mpz_mul(message,c_2,c_to_x_inverse);
//  mpz_mod(message,message,p);
//  gmp_printf ("%s is %Zd\n", "message", message);
//    cout << "\n";
//
//
////
////  mpz_mul(r_times_x,r_a,x_a);
////  mpz_powm(c_2,g,r_times_x,p);
////  mpz_mul(c_2,c_2,m);
////  mpz_mod(c_2,c_2,p);
//  
////  gmp_printf ("%s is %Zd\n", "c_1", c_1);
//  //gmp_printf ("%s is %Zd\n", "c_2", c_2);
//
//
//}


void DeckAndOperations::generatePublicKey(Public_Key *pk){
	pk->p = generateP(50);
	pk->g = findGforP(pk->p);
	generateSecretKey(pk);
}

void DeckAndOperations::generateSecretKey(Public_Key *pk){
	Secret_Key = secretRandomR(pk->p);
}

mpz_class DeckAndOperations::getEncryptedSecret() {
	mpz_class encryptedSecret;
	mpz_powm(encryptedSecret.get_mpz_t(),pk.g.get_mpz_t(),Secret_Key.get_mpz_t(),pk.p.get_mpz_t());
	return encryptedSecret;
}

mpz_class DeckAndOperations::contributeToSharedSecret(mpz_class inp) {
	mpz_class contributed;
	mpz_powm(contributed.get_mpz_t(),inp.get_mpz_t(), Secret_Key.get_mpz_t() ,pk.p.get_mpz_t());
	return contributed;
}

//std::vector<uint8_t> DeckAndOperations::getEncryptedSecretInBinary() {
//	mpz_class encryptedSecret = getEncryptedSecret();
//	return toBinary(encryptedSecret);
//}
//
//std::vector<uint8_t> DeckAndOperations::toBinary(mpz_class input) {
//    std::vector<uint8_t> r((bits(input) +7) / 8, 0);
//    mpz_export(r.data(), nullptr, -1, sizeof(uint8_t), 0, 0, input.get_mpz_t());
//    return r;
//}
//
//size_t bits(mpz_class input) {
//    return mpz_sizeinbase(input.get_mpz_t(), 2);
//}
//size_t bytes(mpz_class input) {
//    return (bits(input) + 7) / 8;
//}

mpz_class DeckAndOperations::generateP(const mpz_class &nbits) {

	return mpz_class("beb7ff0625cb71c1939bba00527bdf77de8b1d38a16edf5527a8d967eec39c4d77c21551362e915fb1ab6ae3b3075ae456f58bd31794e1bd1b4e99bdf12fb7c9", 16);
}

mpz_class DeckAndOperations::findGforP(const mpz_class &p){
	return mpz_class(7);
}


mpz_class DeckAndOperations::secretRandomR(const mpz_class &p) {
	size_t bits = mpz_sizeinbase(p.get_mpz_t(), 2);
	mpz_class r;

	do {
		r = 0;
		std::uniform_int_distribution<uint64_t> dis(0, 0xFFFFFFFFFFFFFFFF);
		for (size_t i=0; i<bits; i+=64) {
			uint64_t tmp = dis(gen);
			r |= mpz_class(tmp) << i;
		}
		r &= (mpz_class(1) << (bits+1)) - 1;
	} while (r <= 0 || r >= p);

	return r;
}
