/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   CardClass.h
 * Author: rigo
 *
 * Created on April 23, 2018, 9:30 PM
 */

#ifndef CARDCLASS_H
#define CARDCLASS_H

#include <gmpxx.h>
#include <string>

using namespace std;

class CardClass {
public:
    CardClass();
    CardClass(mpz_class);
    CardClass(mpz_class, int, int, string);
    CardClass(mpz_class, mpz_class, int, int, string);
    CardClass(const CardClass& orig);
    virtual ~CardClass();
    mpz_class id;
    int type;
    int number;
    string representation;
private:

};

#endif /* CARDCLASS_H */

