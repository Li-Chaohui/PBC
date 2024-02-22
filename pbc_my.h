//
// Created by ch on 24-2-20.
//

#ifndef PBC_MY_H
#define PBC_MY_H
#include <pbc/pbc.h>
#include <pbc/pbc_test.h>


pairing_t pairing;

void ecout(element_t &t){
    element_printf("%B\n",t);

}

void eclear(element_t &t){
    element_clear(t);
}

struct G1;
struct Zr;
struct GT;

struct Zr{
    element_t e;
    Zr();
    void random();
    void operator=(Zr zr);
    void operator=(signed long i);
    Zr operator*(Zr zr);
    G1 operator*(G1 g1);
    Zr operator^(Zr zr);
    Zr operator-(Zr zr);
    Zr operator+(Zr zr);
    Zr operator/(Zr zr);
    void put();
    void clear();
    Zr invert();
};

struct GT{
    element_t e;
    GT();
    void random();
    void operator=(GT gt);
    GT operator*(GT gt);
    GT operator^(Zr zr);
    GT operator/(GT gt);
    bool operator==(GT gt);
    void put();
    void clear();
};

struct G1{
    element_t e;
    G1();
    void random();
    void operator=(G1 g1);
    G1 operator*(G1 g1);
    G1 operator+(G1 g1);
    G1 operator-(G1 g1);
    GT operator&(G1 g1);
    bool operator==(G1 g1);
    void put();
    void clear();
};
//G1
G1::G1(){
    element_init_G1(e,pairing);
}

void G1::random(){
    element_random(e);
}

void G1::operator=(G1 g1){
    element_set(e,g1.e);
}

G1 G1::operator*(G1 g1){
    G1 g1_r;
    element_mul(g1_r.e,e,g1.e);
    return g1_r;
}

G1 G1::operator+(G1 g1){
    G1 g1_r;
    element_add(g1_r.e,g1.e,e);
    return g1_r;
}

G1 G1::operator-(G1 g1){
    G1 g1_r;
    element_sub(g1_r.e,e,g1.e);
    return g1_r;
}

GT G1::operator&(G1 g1){
    GT gt_r;
    pairing_apply(gt_r.e,g1.e,e,pairing);
    return gt_r;
}

bool G1::operator==(G1 g1){
    if(element_cmp(g1.e,e) == 0){
        return 1;
    }
    else{
        return 0;
    }
}

void G1::put(){
    element_printf("%B\n",e);
}

void G1::clear(){
    element_clear(e);
}
//GT
GT::GT(){
    element_init_GT(e,pairing);
}

void GT::random(){
    element_random(e);
}

void GT::operator=(GT gt){
    element_set(e,gt.e);
}

GT GT::operator*(GT gt){
    GT gt_r;
    element_mul(gt_r.e,e,gt.e);
    return gt_r;
}

GT GT::operator^(Zr zr){
    GT gt_r;
    element_pow_zn(gt_r.e,e,zr.e);
    return gt_r;
}

GT GT::operator/(GT gt){
    GT gt_r;
    element_div(gt_r.e,e,gt.e);
    return gt_r;
}

bool GT::operator==(GT gt){
    if(element_cmp(gt.e,e)==0){
        return true;
    }
    else{
        return false;
    }
}

void GT::put(){
    element_printf("%B\n",e);
}

void GT::clear(){
    element_clear(e);
}
//Zr
Zr::Zr(){
    element_init_Zr(e,pairing);
}

void Zr::random(){
    element_random(e);
}

void Zr::operator=(Zr zr){
    element_set(e,zr.e);
}

void Zr::operator=(signed long i){
    element_set_si(e,i);
}

Zr Zr::operator*(Zr zr){
    Zr zr_r;
    element_mul(zr_r.e,zr.e,e);
    return zr_r;
}

G1 Zr::operator*(G1 g1){
    G1 g1_r;
    element_mul_zn(g1_r.e,g1.e,e);
    return g1_r;
}

Zr Zr::operator^(Zr zr){
    Zr zr_r;
    element_pow_zn(zr_r.e,e,zr.e);
    return zr_r;
}

Zr Zr::operator-(Zr zr){
    Zr zr_r;
    element_sub(zr_r.e,e,zr.e);
    return zr_r;
}

Zr Zr::operator+(Zr zr){
    Zr zr_r;
    element_add(zr_r.e,e,zr.e);
    return zr_r;
}

Zr Zr::operator/(Zr zr){
    Zr zr_r;
    element_div(zr_r.e,e,zr.e);
    return zr_r;
}

void Zr::put(){
    element_printf("%B\n",e);
}

void Zr::clear(){
    element_clear(e);
}

Zr Zr::invert(){
        Zr zr_r;
        element_invert(zr_r.e,e);
        return zr_r;
    }
#endif //PBC_MY_H