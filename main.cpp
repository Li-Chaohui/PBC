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
        element_init_G1(OK,pairing);
        element_init_G1(AK,pairing);
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
    void keygen(SK2 &sk2,vector<int> &L){
        element_t r2,tempL;
        //初始化
        element_init_Zr(r2,pairing);
        element_init_Zr(tempL,pairing);
        element_init_G1(sk2.D20,pairing);
        element_init_G1(sk2.D21,pairing);
        //初始化r2
        element_random(r2);
        //计算D20
        int_to_hash(L[S.size()],tempL);
        element_mul_zn(sk2.D20,pk.Un1,tempL);
        element_mul_zn(sk2.D20,sk2.D20,r2);
        element_add(sk2.D20,sk2.D20,AK);
        //计算D21
        element_mul_zn(sk2.D21,pk.G,r2);
        //清除临时变量
        element_clear(r2);
        element_clear(tempL);
    }
    void encrypt(CT &ct,vector<int> &W){
        element_t s,tempGT,tempG1,Wn1Hash;
        //初始化
        element_init_Zr(s,pairing);
        element_init_Zr(Wn1Hash,pairing);
        element_init_GT(ct.C0,pairing);
        element_init_GT(tempGT,pairing);
        element_init_GT(M,pairing);
        element_init_G1(ct.C1,pairing);
        element_init_G1(ct.C2,pairing);
        element_init_G1(ct.C3,pairing);
        element_init_G1(ct.E,pairing);
        element_init_G1(tempG1,pairing);
        //选取s M
        element_random(s);
        element_random(M);
        //计算C0
        pairing_apply(tempGT,pk.G1,pk.G2,pairing);
        element_pow_zn(tempGT,tempGT,s);
        element_mul(ct.C0,M,tempGT);
        //计算C1
        element_mul_zn(ct.C1,pk.G,s);
        //计算C2
        element_set(tempG1,pk.G3);
        for(int i = 0;i < S.size();i++){
            element_t tempmul,Whash;
            element_init_G1(tempmul,pairing);
            element_init_Zr(Whash,pairing);
            int_to_hash(W[i],Whash);
            element_mul_zn(tempmul,pk.U[i].U,Whash);
            element_add(tempG1,tempG1,tempmul);

            //清除
            element_clear(tempmul);
            element_clear(Whash);
        }
        element_mul_zn(tempG1,tempG1,s);
        element_add(ct.C2,ct.C2,tempG1);
        //计算C3
        int_to_hash(W[S.size()],Wn1Hash);
        element_mul_zn(ct.C3,pk.Un1,Wn1Hash);
        element_mul_zn(ct.C3,ct.C3,s);
        //计算E
        element_mul_zn(ct.E,pk.U0,s);
    }
};

class KG_CSP{
public:
    void keygen(SK1 &sk1,element_t &OK,element_t &ID_hash,PK &pk,vector<int> &L){
        element_t r1,tempG1;
        //初始化
        element_init_Zr(r1,pairing);
        element_init_G1(tempG1,pairing);
        element_init_G1(sk1.D10,pairing);
        element_init_G1(sk1.D11,pairing);
        element_init_Zr(sk1.D3,pairing);
        //随机生成r1
        element_random(r1);
        //计算D10
        element_mul_zn(tempG1,pk.U0,ID_hash);
        for(int i = 0;i < S.size();i++){
            element_t Lhash,tempMul;
            element_init_Zr(Lhash,pairing);
            element_init_G1(tempMul,pairing);
            int_to_hash(L[i],Lhash);
            element_mul_zn(tempMul,pk.U[i].U,Lhash);
            element_add(tempG1,tempG1,tempMul);
            //清除临时变量
            element_clear(Lhash);
            element_clear(tempMul);
        }
        element_add(tempG1,tempG1,pk.G3);
        element_mul_zn(tempG1,tempG1,r1);
        element_add(sk1.D10,OK,tempG1);
        //计算D11
        element_mul_zn(sk1.D11,pk.G,r1);
        //计算D3
        element_set(sk1.D3,ID_hash);
        for(int i = 0;i < S.size()+1;i++){
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
};

int main(int argc,char** argv){
    pbc_demo_pairing_init(pairing,argc,argv);

    AA aa("lichaohui");
    KG_CSP kg;
    User u;
    CT ct;
    vector<int> L = {1,3,6,10,20};
    kg.keygen(u.sk.sk1,aa.OK,aa.ID_hash,aa.pk,L);
    aa.keygen(u.sk.sk2,L);
    u.varify(aa.pk);
    aa.encrypt(ct,L);
    pairing_clear(pairing);
    return 0;
}