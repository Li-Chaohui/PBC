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
    element_t G,G1,G2,G3,U0;
    vector<Ui> U;
    PK():U(S.size()){}
};

struct SK_ID_L{
    element_t D0,D1,D2;
    vector<int> D3;
    SK_ID_L():D3(S.size()){}
};

struct Ti{
    element_t T;
    bool isvaild;
};

struct CT{
    element_t C0,C1,C2,E;
    vector<Ti> T;
    CT():T(S.size()){}
};

void L_to_hash(int number,element_t &t) {
    char charArray[10];
    sprintf(charArray, "%d", number);
    element_init_Zr(t,pairing);
    element_from_hash(t,(void*)charArray,sizeof(charArray));
}

class AA{
    element_t msk,alpha,M,s;
    CT ct;
    vector<int> W;
    SK_ID_L skl;
    //系统初始化
    void setup(){
        //初始化pk
        element_init_G1(pk.G,pairing);
        element_init_G1(pk.G2,pairing);
        element_init_G1(pk.G3,pairing);
        //选取G G2 G3
        element_random(pk.G);
        element_random(pk.G2);
        element_random(pk.G3);
        //初始化U
        element_init_G1(pk.U0,pairing);
        for(int i = 0;i < S.size();i++){
            element_init_G1(pk.U[i].U,pairing);
            //选取Ui
            element_random(pk.U[i].U);
        }
        //选取alpha
        element_init_Zr(alpha,pairing);
        element_random(alpha);
        //计算G1 msk;
        element_init_G1(pk.G1,pairing);
        element_init_G1(msk,pairing);

        element_mul_zn(pk.G1,pk.G,alpha);
        element_mul_zn(msk,pk.G2,alpha);
    }

public:
    PK pk;
    //密钥产生
    AA(vector<int> &W):W(S.size()){
        for(int i = 0;i < S.size();i++){
            this->W[i] = W[i];
        }
        setup();
    }

    //密钥生成
    void keygen(const vector<int> &L,string ID){
        //选取r
        element_t r,tempG1,tempG2,tempG3;;
        element_init_Zr(r,pairing);
        element_random(r);
        //初始化skl
        element_init_G1(skl.D0,pairing);
        element_init_G1(skl.D1,pairing);
        element_init_Zr(skl.D2,pairing);
        //计算D0

        element_init_G1(tempG1,pairing);
        element_init_G1(tempG2,pairing);
        element_init_G1(tempG3,pairing);
        element_mul_zn(tempG1,pk.G2,alpha);
        element_t ID_hash;
        //计算ID
        char charID[ID.size()+1];
        strcpy(charID,ID.c_str());
        element_init_Zr(ID_hash,pairing);
        element_from_hash(ID_hash,(void*)charID,sizeof(charID));
        //ID.U0
        element_mul(tempG2,pk.U0,ID_hash);

        for(int i = 0;i < pk.U.size();i++){
            element_t Li_hash;
            //Li哈希
            L_to_hash(L[i],Li_hash);
            //计算Li.Ui
            element_mul_zn(tempG3,pk.U[i].U,Li_hash);
            //求和
            element_add(tempG2,tempG2,tempG3);

            element_clear(Li_hash);
        }
        //加G3
        element_add(tempG2,tempG2,pk.G3);
        element_mul_zn(tempG3,tempG2,r);
        //D0
        element_add(skl.D0,tempG1,tempG3);
        //计算D1
        element_mul_zn(skl.D1,pk.G,r);
        //D2
        element_set(skl.D2,ID_hash);
        //D3
        for(int i = 0;i < L.size();i++){
            skl.D3[i] = L[i];
        }

        element_clear(ID_hash);
        element_clear(tempG1);
        element_clear(tempG2);
        element_clear(tempG3);
        element_clear(r);
    }

    //加密
    void encrypt(){
        //选取s
        element_init_Zr(s,pairing);
        element_random(s);
        //选取M
        element_init_GT(M,pairing);
        element_random(M);
        //计算C0
        element_init_GT(ct.C0,pairing);
        pairing_apply(ct.C0,pk.G1,pk.G2,pairing);
        element_pow_zn(ct.C0,ct.C0,s);
        element_mul(ct.C0,ct.C0,M);
        //计算C1
        element_init_G1(ct.C1,pairing);
        element_mul_zn(ct.C1,pk.G,s);
        //计算C2
        element_init_G1(ct.C2,pairing);
        element_t tempG1;
        element_init_G1(tempG1,pairing);
        element_set(tempG1,pk.G3);
        for(int i = 0;i < S.size();i++){
            if(W[i]!=-1){
                element_t hash_w,temp;
                element_init_G1(temp,pairing);
                L_to_hash(W[i],hash_w);
                element_mul_zn(temp,pk.U[i].U,hash_w);
                element_add(tempG1,tempG1,temp);

                element_clear(hash_w);
                element_clear(temp);
            }
            else{
                //计算Ti
                element_init_G1(ct.T[i].T,pairing);
                element_mul_zn(ct.T[i].T,pk.U[i].U,s);
                ct.T[i].isvaild = true;
            }
        }
        element_mul_zn(ct.C2,tempG1,s);
        //计算E
        element_init_G1(ct.E,pairing);
        element_mul_zn(ct.E,pk.U0,s);

        element_clear(tempG1);
    }

    //解密
    void decrypt(){
        for(int i = 0;i < S.size();i++){
            if(skl.D3[i] != W[i]){
                cout<<"用户访问策略不匹配"<<endl;
                return;
            }
        }
        element_t Cp;
        element_init_G1(Cp,pairing);
        //临时变量
        element_set(Cp,ct.C2);
        for(int i = 0;i < S.size();i++){
            if(W[i] == -1){
                element_t hash_L,temp;
                element_init_G1(temp,pairing);
                L_to_hash(skl.D3[i],hash_L);
                element_mul_zn(temp,ct.T[i].T,hash_L);
                element_add(Cp,Cp,temp);

                element_clear(hash_L);
                element_clear(temp);
            }
        }
        element_t temp1;
        element_init_G1(temp1,pairing);
        element_mul_zn(temp1,ct.E,skl.D2);
        element_add(Cp,Cp,temp1);
        //分子部分
        element_t fz;
        element_init_GT(fz,pairing);
        pairing_apply(fz,skl.D1,Cp,pairing);
        element_mul(fz,fz,ct.C0);
        //分母部分
        element_t fm;
        element_init_GT(fm,pairing);
        pairing_apply(fm,skl.D0,ct.C1,pairing);
        //解密
        element_t dec_m;
        element_init_GT(dec_m,pairing);
        element_div(dec_m,fz,fm);
        if(element_cmp(M,dec_m)==0){
            cout<<"解密成功！"<<endl;
        }
        else{
            cout<<"失败！"<<endl;
        }

        element_clear(Cp);
        element_clear(fz);
        element_clear(fm);
        element_clear(dec_m);
        element_clear(temp1);
    }

    void clear(){
        for(int i = 0;i < S.size();i++){
            element_clear(pk.U[i].U);
        }

        element_clear(skl.D0);
        element_clear(skl.D1);
        element_clear(skl.D2);

        //清除pk
        element_clear(pk.G1);
        element_clear(pk.G2);
        element_clear(pk.G3);
        element_clear(pk.G);
        element_clear(pk.U0);

        element_clear(ct.C0);
        element_clear(ct.C1);
        element_clear(ct.C2);
        element_clear(ct.E);

        element_clear(msk);
        element_clear(alpha);
        element_clear(M);
        element_clear(s);
    }

    void varify(){
        element_t GTl,GTr,GTr1,tempG1;
        element_init_GT(GTl,pairing);
        element_init_GT(GTr,pairing);
        element_init_GT(GTr1,pairing);

        pairing_apply(GTl,pk.G,skl.D0,pairing);
        pairing_apply(GTr,pk.G2,pk.G1,pairing);

        element_init_G1(tempG1,pairing);
        element_mul_zn(tempG1,pk.U0,skl.D2);

        for(int i = 0;i < pk.U.size();i++){
            element_t hash_L,tempG1p;
            element_init_G1(tempG1p,pairing);
            L_to_hash(skl.D3[i],hash_L);
            element_mul_zn(tempG1p,pk.U[i].U,hash_L);
            element_add(tempG1,tempG1,tempG1p);

            //清除临时变量
            element_clear(hash_L);
            element_clear(tempG1p);
        }
        element_add(tempG1,tempG1,pk.G3);
        pairing_apply(GTr1,tempG1,skl.D1,pairing);

        element_mul(GTr,GTr,GTr1);

        if(element_cmp(GTl,GTr) == 0){
            cout<<"验证成功"<<endl;
        }
        else{
            cout<<"验证失败"<<endl;
        }

        element_clear(GTl);
        element_clear(GTr);
        element_clear(GTr1);
        element_clear(tempG1);
    }

    

};

int main(int argc,char** argv){
    pbc_demo_pairing_init(pairing,argc,argv);
    vector<int> W = {1,3,6,10};
    AA aa(W);
    vector<int> L = {1,3,6,10};
    aa.keygen(L,"lichaohui");
    aa.varify();
    aa.encrypt();
    aa.decrypt();
    aa.clear();
    pairing_clear(pairing);

    return 0;
}