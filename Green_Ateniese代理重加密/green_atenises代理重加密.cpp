#include <bits/stdc++.h>
#include <pbc/pbc.h>
#include <pbc/pbc_test.h>

using namespace std;

pairing_t pairing;

struct Key_ID{
    element_t sk,pk;
};

struct CT{
    element_t c1,c2;
};

void ecout(element_t &t){
    element_printf("%B\n",t);
}

void toIDhash(string &ID,element_t &ID_hash){
    char charID[ID.size()+1];
    strcpy(charID,ID.c_str());
    element_from_hash(ID_hash,(void*)charID,sizeof(charID));
}

class GA{
    element_t G,msk;
    void setup(){
        //初始化
        element_init_Zr(msk,pairing);
        element_init_G1(G,pairing);
        element_init_G1(pk,pairing);
        //生成G msk
        element_random(msk);
        element_random(G);
        //计算pk
        element_mul_zn(pk,G,msk);
    }
public:
    element_t pk,M;

    GA(){
        setup();
    }

    void keygen(Key_ID &key_id,string ID){
        //初始化
        element_init_G1(key_id.sk,pairing);
        element_init_G1(key_id.pk,pairing);
        //计算sk
        toIDhash(ID,key_id.pk);
        //计算pk
        element_mul_zn(key_id.sk,key_id.pk,msk);
    }

    void encrypt(CT &ct,element_t &key_id_pk){
        element_t r,tempGT;
        //初始化
        element_init_Zr(r,pairing);
        element_init_G1(ct.c1,pairing);
        element_init_GT(ct.c2,pairing);
        element_init_GT(M,pairing);
        element_init_GT(tempGT,pairing);
        //生成 r M
        element_random(r);
        element_random(M);
        //计算ct1
        element_mul_zn(ct.c1,G,r);
        //计算ct2
        pairing_apply(tempGT,pk,key_id_pk,pairing);
        element_pow_zn(ct.c2,tempGT,r);
        element_mul(ct.c2,ct.c2,M);
        //清除临时变量
        element_clear(r);
        element_clear(tempGT);
    }

    void clear(){
        element_clear(G);
        element_clear(msk);
        element_clear(pk);
        element_clear(M);
    }
};

class User{
public:
    Key_ID key_id;
    void decrypt(CT &ct,element_t &M){
        element_t tempGT,decM;
        element_init_GT(tempGT,pairing);
        element_init_GT(decM,pairing);
        //计算分母
        pairing_apply(tempGT,ct.c1,key_id.sk,pairing);
        element_div(decM,ct.c2,tempGT);
        if(element_cmp(decM,M) == 0){
            cout<<"解密成功！"<<endl;
        }
        else{
            cout<<"解密失败！"<<endl;
        }
        element_clear(tempGT);
        element_clear(decM);
    }
    void clear(){
        element_clear(key_id.pk);
        element_clear(key_id.sk);
    }
};

void clear(CT &ct){
    element_clear(ct.c1);
    element_clear(ct.c2);
}

int main(int argc,char** argv){
    pbc_demo_pairing_init(pairing,argc,argv);
    GA ga;
    User u;
    CT ct;
    ga.keygen(u.key_id,"lichaohui");
    ga.encrypt(ct,u.key_id.pk);
    u.decrypt(ct,ga.M);
    //清除变量
    ga.clear();
    u.clear();
    clear(ct);
    pairing_clear(pairing);
    return 0;
}