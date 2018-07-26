/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   DeckAndOperatios.cpp
 * Author: Deniz
 * 
 * Created on April 23, 2018, 9:30 PM
 */

#include "DeckAndOperations.h"
#define NUMBEROFCARDS 8
using namespace std;

mpz_class Secret_Key;

std::random_device rdev;
std::mt19937_64 gen(rdev());


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



DeckAndOperations::~DeckAndOperations() {
}


void DeckAndOperations::generateCardsAndPutIntoDeck(){
	mpz_class aPrime(1);
	for(int i=0; i< NUMBEROFCARDS ; i++){

		mpz_nextprime(aPrime.get_mpz_t(), aPrime.get_mpz_t());
		CipherText ct(aPrime);

		totalCardCount++;
		mpz_mul(cardsMultiplied,cardsMultiplied,aPrime.get_mpz_t());
		deckVector.push_back(ct);
	}
}

vector<CipherText> DeckAndOperations::getDeck(){
	return deckVector;
}


size_t DeckAndOperations::randomNumber(size_t min, size_t max){
	if(min<max){

		std::uniform_int_distribution<> dis(min, max-1);
		return dis(gen);
	}
	else
		return 0;
}



CipherText DeckAndOperations::mask_elGamal(const Public_Key &pk, const CipherText &ct, mpz_class *rp) {

	mpz_class g_to_r;
	mpz_class y_to_r;

	//	we don't need those lines anymore because y is shared public key
	mpz_class y(Shared_Public_Key);
	if(Shared_Public_Key == 0 || Shared_Public_Key == NULL) { // This is for single player runs
		Shared_Public_Key = secretRandomR(pk.p);
		y = Shared_Public_Key;
	}
	//mpz_powm((y).get_mpz_t(),(pk.g).get_mpz_t(),Secret_Key.get_mpz_t(),(pk.p).get_mpz_t());



	if (rp == NULL) {
		mpz_class r = secretRandomR(pk.p);
		mpz_powm(g_to_r.get_mpz_t(),pk.g.get_mpz_t(),r.get_mpz_t(),pk.p.get_mpz_t());
		mpz_powm(y_to_r.get_mpz_t(),y.get_mpz_t(),r.get_mpz_t(),pk.p.get_mpz_t());
	}
	else {
		mpz_powm(g_to_r.get_mpz_t(),pk.g.get_mpz_t(),(*rp).get_mpz_t(),pk.p.get_mpz_t());
		mpz_powm(y_to_r.get_mpz_t(),y.get_mpz_t(),(*rp).get_mpz_t(),pk.p.get_mpz_t());
	}


	return CipherText(ct.c_1 * g_to_r % pk.p, ct.c_2 * y_to_r % pk.p);
}







CipherText DeckAndOperations::unmask_elGamal(const Public_Key &pk, const CipherText &ct){

	mpz_class unmasked;

	mpz_powm(unmasked.get_mpz_t(),ct.c_1.get_mpz_t(),Secret_Key.get_mpz_t(),pk.p.get_mpz_t());
	//	mpz_class unmaskedInverted;
	//	mpz_invert(unmaskedInverted.get_mpz_t(),unmasked.get_mpz_t(),pk.p.get_mpz_t());

	return CipherText(unmasked, ct.c_2);
}


CipherText DeckAndOperations::finalize_unmask_elGamal(const Public_Key &pk, const CipherText &ct){

	mpz_class unmasked;
	mpz_powm(unmasked.get_mpz_t(),ct.c_1.get_mpz_t(),Secret_Key.get_mpz_t(),pk.p.get_mpz_t());
	mpz_invert(unmasked.get_mpz_t(),unmasked.get_mpz_t(),pk.p.get_mpz_t());


	return CipherText(unmasked * ct.c_2 % pk.p);
}

vector<CipherText> DeckAndOperations::mask_elGamal_deck() {
	for(auto i = deckVector.begin(); i != deckVector.end(); i++){
		*i = mask_elGamal(pk, *i, NULL);
	}
	return deckVector;
}

vector<CipherText> DeckAndOperations::re_mask_elGamal_deck(const Public_Key &pk, vector<CipherText> &vectorToRemasked, vector<mpz_class> &rp) {
	int j = 0;

	for(auto i = vectorToRemasked.begin(); i != vectorToRemasked.end(); i++){
		*i = mask_elGamal(pk, *i, &rp[j]);
		j++;

	}
	return vectorToRemasked;
}


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



mpz_class DeckAndOperations::generateP(const mpz_class &nbits) {
//	return mpz_class(19);
	return mpz_class("beb7ff0625cb71c1939bba00527bdf77de8b1d38a16edf5527a8d967eec39c4d77c21551362e915fb1ab6ae3b3075ae456f58bd31794e1bd1b4e99bdf12fb7c9", 16);
}

mpz_class DeckAndOperations::findGforP(const mpz_class &p){
//	return mpz_class(2);
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


vector<mpz_class> DeckAndOperations::generateSecretRandomRVector(const mpz_class &p, int size){
	vector<mpz_class> vectorToReturn;
	for(auto i = 0; i < size; i++){
	vectorToReturn.push_back(secretRandomR(p));
	}
	return vectorToReturn;
}
