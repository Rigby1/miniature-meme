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
   
    
    deck->shuffleDeck();
    

    return 0;
}

