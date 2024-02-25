#include <pbc/pbc.h>
#include <pbc/pbc_test.h>
#include <bits/stdc++.h>

using namespace std;

pairing_t pairing;

//通配符取-1
vector<vector<int>> S = {
        {1,2},{3,4,5},{6,7,8,9},{10,11,12,13,14}
};

struct Ui{
    element_t U;
};

struct PK{
    element_t G,G1,G2,G3,U0,Un1;
    vector<Ui> U;
    PK():U(S.size()){}
};


struct CT{
    element_t C0,C1,C2,C3,E;
};

struct SK1{
    element_t D10,D11,D3;
    vector<int> D4;
    SK1():D4(S.size()+1){}
};

struct SK2{
    element_t D20,D21;
};

struct SK{
    SK1 sk1;
    SK2 sk2;
};

void ecout(element_t &t){
    element_printf("%B\n",t);
}

void int_to_hash(int number,element_t &t) {
    char* charArray =(char*)malloc(sizeof(char) * 10);
    sprintf(charArray, "%d", number);
    size_t len = strlen(charArray);
    element_from_hash(t,(void*)charArray,len);
    free(charArray);
}

void toIDhash(string ID,element_t &ID_hash){
    char charID[ID.size()+1];
    strcpy(charID,ID.c_str());
    element_from_hash(ID_hash,(void*)charID,sizeof(charID));
}

class AA{
private:
    void setup(){
        element_t alpha,alpha1,alpha2;
        //初始化
        element_init_Zr(alpha,pairing);
        element_init_Zr(alpha1,pairing);
        element_init_Zr(alpha2,pairing);
        element_init_G1(pk.G,pairing);
        element_init_G1(pk.G1,pairing);
        element_init_G1(pk.G2,pairing);
        element_init_G1(pk.G3,pairing);
        element_init_G1(pk.U0,pairing);
        element_init_G1(pk.Un1,pairing);
        for(int i = 0;i < S.size();i++){
            element_init_G1(pk.U[i].U,pairing);
            //随机生成
            element_random(pk.U[i].U);
        }
        //随机生成
        element_random(alpha);
        element_random(alpha1);
        element_random(pk.G);
        element_random(pk.G2);
        element_random(pk.G3);
        element_random(pk.U0);
        element_random(pk.Un1);
        //计算alpha2
        element_sub(alpha2,alpha,alpha1);
        //计算G1 OK AK
        element_mul_zn(pk.G1,pk.G,alpha);
        element_mul_zn(OK,pk.G2,alpha1);
        element_mul_zn(AK,pk.G2,alpha2);
        //清除临时变量
        element_clear(alpha);
        element_clear(alpha1);
        element_clear(alpha2);
    }
public:
    PK pk;
    element_t M,ID_hash,OK,AK;
    AA(string ID){
        setup();
        element_init_Zr(ID_hash,pairing);
        toIDhash(ID,ID_hash);
    }
};

class KG_CSP{
    void keygen(SK1 &sk1,element_t &OK,element_t &ID_hash,PK &pk,vector<int> &L){
        element_t r1;
        //初始化
        element_init_Zr(r1,pairing);
        //随机生成r1
        element_random(r1);
    }
};

class User{
public:
    SK sk;
};

int main(int argc,char** argv){
    pbc_demo_pairing_init(pairing,argc,argv);

    

    pairing_clear(pairing);
    return 0;
}