/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   CardClass.cpp
 * Author: rigo
 * 
 * Created on April 23, 2018, 9:30 PM
 */

#include "CardClass.h"

CardClass::CardClass() {
}

CardClass::CardClass(const CardClass& orig) {
}

CardClass::CardClass(mpz_t newId, int newType, int newNumber, string newRepresentation) {
    mpz_init (id);
    mpz_set(id, newId);
    type = newType;
    number = newNumber;
    representation = newRepresentation;   
}

CardClass::~CardClass() {
}

