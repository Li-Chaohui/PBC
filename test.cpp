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

struct Ti{
    element_t T;
};

struct CT{
    element_t C0,C1,C2,C3,E;
    vector<Ti> T;
    CT():T(S.size()){}
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



class AA{
private:
    //系统初始化
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
        element_init_G1(OK,pairing);
        element_init_G1(AK,pairing);
        for(int i = 0;i < S.size();i++){
            element_init_G1(pk.U[i].U,pairing);

            element_random(pk.U[i].U);
        }
        //选取G,G2,G3,U0,Un1
        element_random(pk.G);
        element_random(pk.G2);
        element_random(pk.G3);
        element_random(pk.U0);
        element_random(pk.Un1);
        //选取alpha,alpha1
        element_random(alpha);
        element_random(alpha1);
        //计算alpha2
        element_sub(alpha2,alpha,alpha1);
        //计算G1,OK,AK
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
    element_t OK,AK,IDHash,M;
    AA(string ID){
        setup();
        //计算IDHash
        element_init_Zr(IDHash,pairing);
        char charID[ID.size()+1];
        strcpy(charID,ID.c_str());
        element_from_hash(IDHash,(void*)charID,sizeof(charID));
    }

    void keygen(SK2 &sk2,vector<int> &L){
        element_t r2,tempG1,ZrL;
        //初始化
        element_init_Zr(r2,pairing);
        element_init_Zr(ZrL,pairing);
        element_init_G1(tempG1,pairing);
        element_init_G1(sk2.D20,pairing);
        element_init_G1(sk2.D21,pairing);
        //选取r2
        element_random(r2);
        //计算D20
        element_set(sk2.D20,AK);
        int_to_hash(L[S.size()],ZrL);
        element_mul_zn(tempG1,pk.Un1,ZrL);
        element_mul_zn(tempG1,tempG1,r2);
        element_add(sk2.D20,sk2.D20,tempG1);
        //计算D21
        element_mul_zn(sk2.D21,pk.G,r2);
        //清除临时变量
        element_clear(r2);
        element_clear(tempG1);
        element_clear(ZrL);
    }

    void encrypt(vector<int> &W,CT &ct){
        element_t s,tempG1,WZr;
        //初始化
        element_init_Zr(s,pairing);
        element_init_Zr(WZr,pairing);
        element_init_GT(M,pairing);
        element_init_GT(ct.C0,pairing);
        element_init_G1(ct.C1,pairing);
        element_init_G1(ct.C2,pairing);
        element_init_G1(ct.C3,pairing);
        element_init_G1(ct.E,pairing);
        element_init_G1(tempG1,pairing);
        for(int i = 0;i < S.size();i++){
            element_init_G1(ct.T[i].T,pairing);
        }
        //选取s，M
        element_random(s);
        element_random(M);
        //计算C0
        pairing_apply(ct.C0,pk.G1,pk.G2,pairing);
        element_pow_zn(ct.C0,ct.C0,s);
        element_mul_zn(ct.C0,ct.C0,M);
        //计算C1
        element_mul_zn(ct.C1,pk.G,s);
        //计算C2 T
        for(int i = 0;i < S.size();i++){
            if(W[i] != -1){
                element_t tempmul;
                element_init_G1(tempmul,pairing);
                int_to_hash(W[i],WZr);
                element_mul_zn(tempmul,pk.U[i].U,WZr);

                element_add(ct.C2,ct.C2,tempmul);

                element_random(ct.T[i].T);
                element_clear(tempmul);
            }
            else{
                element_mul_zn(ct.T[i].T,pk.U[i].U,s);
            }
        }
        element_mul_zn(ct.C2,ct.C2,s);
        //计算C3
        int_to_hash(W[S.size()],WZr);
        element_mul_zn(ct.C3,pk.Un1,WZr);
        element_mul_zn(ct.C3,ct.C3,s);
        //计算E
        element_mul_zn(ct.E,pk.U0,s);
        //清除临时变量
        element_clear(s);
        element_clear(tempG1);
        element_clear(WZr);
    }

    void clear(){
        element_clear(AK);
        element_clear(OK);
        element_clear(M);
        element_clear(IDHash);
        element_clear(pk.G);
        element_clear(pk.G1);
        element_clear(pk.G2);
        element_clear(pk.G3);
        element_clear(pk.U0);
        element_clear(pk.Un1);
        for(int i = 0;i < S.size();i++){
            element_clear(pk.U[i].U);
        }
    }
};

class KG_CSP{
public:
    void keygen(PK &pk,element_t &ID_hash,vector<int> &L,element_t &OK,SK1 &sk1){
        element_t r1,tempG1;
        //初始化
        element_init_Zr(r1,pairing);
        element_init_G1(tempG1,pairing);
        element_init_G1(sk1.D10,pairing);
        element_init_G1(sk1.D11,pairing);
        element_init_Zr(sk1.D3,pairing);
        //生成r1
        element_random(r1);
        //计算D10
        element_set(sk1.D10,OK);
        ecout(ID_hash);
        element_mul_zn(tempG1,pk.U0,ID_hash);
        for(int i = 0;i < S.size();i++){
            element_t tempL,tempmul;
            element_init_Zr(tempL,pairing);
            element_init_G1(tempmul,pairing);
            int_to_hash(L[i],tempL);
            element_mul_zn(tempmul,pk.U[i].U,tempL);
            element_add(tempG1,tempG1,tempmul);
            //清除临时变量
            element_clear(tempL);
            element_clear(tempmul);
        }
        element_add(tempG1,tempG1,pk.G3);
        element_mul_zn(tempG1,tempG1,r1);
        element_add(sk1.D10,sk1.D10,tempG1);
        //计算D11
        element_mul_zn(sk1.D11,pk.G,r1);
        //D3
        element_set(sk1.D3,ID_hash);
        for(int i = 0;i < L.size();i++){
            sk1.D4[i] = L[i];
        }
        //清除临时变量
        element_clear(r1);
        element_clear(tempG1);
    }
};

class User{
public:
    SK sk;
    void varify(PK &pk){
        element_t tempGTl,tempGTr1,tempGTr2,tempGTr3,tempG1,tempZr;
        //初始化
        element_init_G1(tempG1,pairing);
        element_init_GT(tempGTl,pairing);
        element_init_GT(tempGTr1,pairing);
        element_init_GT(tempGTr2,pairing);
        element_init_GT(tempGTr3,pairing);
        element_init_Zr(tempZr,pairing);
        //计算左等式
        element_add(tempG1,sk.sk1.D10,sk.sk2.D20);
        pairing_apply(tempGTl,tempG1,pk.G,pairing);
        //计算右1等式
        pairing_apply(tempGTr1,pk.G2,pk.G1,pairing);
        //计算右2等式
        element_mul_zn(tempG1,pk.U0,sk.sk1.D3);
        for(int i = 0;i < S.size();i++){
            element_t hashL,tempmul;
            element_init_Zr(hashL,pairing);
            element_init_G1(tempmul,pairing);
            int_to_hash(sk.sk1.D4[i],hashL);
            element_mul_zn(tempmul,pk.U[i].U,hashL);
            element_add(tempG1,tempG1,tempmul);
            //清除临时变量
            element_clear(hashL);
            element_clear(tempmul);
        }
        element_add(tempG1,tempG1,pk.G3);
        pairing_apply(tempGTr2,tempG1,sk.sk1.D11,pairing);
        //计算右3等式
        int_to_hash(sk.sk1.D4[S.size()],tempZr);
        element_mul_zn(tempG1,pk.Un1,tempZr);
        pairing_apply(tempGTr3,tempG1,sk.sk2.D21,pairing);
        //计算右式
        element_mul(tempGTr2,tempGTr2,tempGTr3);
        element_mul(tempGTr1,tempGTr1,tempGTr2);
        //验证！
        if(!element_cmp(tempGTl,tempGTr1)){
            cout<<"验证成功！"<<endl;
        }
        else{
            cout<<"验证失败！"<<endl;
        }
        //清除临时变量
        element_clear(tempGTl);
        element_clear(tempGTr1);
        element_clear(tempGTr2);
        element_clear(tempGTr3);
        element_clear(tempG1);
        element_clear(tempZr);
    }

    void decrypt(CT &ct,element_t &M){
        element_t C2p,tempG1,fz1,fz2,fm1,fm2,decM;
        //初始化
        element_init_G1(C2p,pairing);
        element_init_G1(tempG1,pairing);
        element_init_GT(fz1,pairing);
        element_init_GT(fz2,pairing);
        element_init_GT(fm1,pairing);
        element_init_GT(fm2,pairing);
        element_init_GT(decM,pairing);
        //计算C2p
        ecout(sk.sk1.D3);
        element_mul_zn(tempG1,ct.E,sk.sk1.D3);
        element_add(C2p,ct.C2,tempG1);
        //分子部分
        pairing_apply(fz1,sk.sk1.D11,C2p,pairing);
        pairing_apply(fz2,sk.sk2.D21,ct.C3,pairing);
        element_mul(fz1,fz1,fz2);
        element_mul(fz1,fz1,ct.C0);
        //分母部分
        pairing_apply(fm1,sk.sk1.D10,ct.C1,pairing);
        pairing_apply(fm2,sk.sk2.D20,ct.C1,pairing);
        element_mul(fm1,fm1,fm2);
        //解密
        element_div(decM,fm1,fz1);
        if(!element_cmp(M,decM)){
            cout<<"解密成功！"<<endl;
        }
        else{
            cout<<"解密失败！"<<endl;
        }
        //清除临时变量
        element_clear(C2p);
        element_clear(tempG1);
        element_clear(fz1);
        element_clear(fz2);
        element_clear(fm1);
        element_clear(fm2);
        element_clear(decM);
    }

    void clear(){
        //sk1
        element_clear(sk.sk1.D10);
        element_clear(sk.sk1.D11);
        element_clear(sk.sk1.D3);
        //sk2
        element_clear(sk.sk2.D20);
        element_clear(sk.sk2.D21);
    }
};

void clearCT(CT &ct){
    element_clear(ct.C0);
    element_clear(ct.C1);
    element_clear(ct.C2);
    element_clear(ct.C3);
    element_clear(ct.E);
    for(int i = 0;i < S.size();i++){
        element_clear(ct.T[i].T);
    }
}

int main(int argc,char** argv){
    pbc_demo_pairing_init(pairing,argc,argv);
    vector<int> L = {1,3,6,10,2};
    AA aa("lichaohui");
    KG_CSP kgCsp;
    User u;
    CT ct;
    kgCsp.keygen(aa.pk,aa.IDHash,L,aa.OK,u.sk.sk1);
    aa.keygen(u.sk.sk2,L);
    u.varify(aa.pk);
    aa.encrypt(L,ct);
    u.decrypt(ct,aa.M);

    clearCT(ct);
    aa.clear();
    u.clear();
    pairing_clear(pairing);
    return 0;
}