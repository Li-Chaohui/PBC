#include "../my.h"

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
    void operator=(CT ct){
        element_init_GT(C0,pairing);
        element_init_G1(C1,pairing);
        element_init_G1(C2,pairing);
        element_init_G1(C3,pairing);
        element_init_G1(E,pairing);

        element_set(C0,ct.C0);
        element_set(C1,ct.C1);
        element_set(C2,ct.C2);
        element_set(C3,ct.C3);
        element_set(E,ct.E);
    }
};

struct SK1{
    element_t D10,D11,D3;
    vector<int> D4;
    SK1():D4(S.size()+1){}
    void operator=(SK1 sk1){
        element_init_G1(D10,pairing);
        element_init_G1(D11,pairing);
        element_init_Zr(D3,pairing);
        element_set(D10,sk1.D10);
        element_set(D11,sk1.D11);
        element_set(D3,sk1.D3);
        for(int i = 0;i <= S.size();i++){
            D4[i] = sk1.D4[i];
        }
    }
};

struct SK2{
    element_t D20,D21;
    void operator=(SK2 sk2){
        element_init_G1(D20,pairing);
        element_init_G1(D21,pairing);
        element_set(D20,sk2.D20);
        element_set(D21,sk2.D21);
    }
};

struct SK{
    SK1 sk1;
    SK2 sk2;
    void operator=(SK sk){
        sk1 = sk.sk1;
        sk2 = sk.sk2;
    }
};

struct IDHash{
    element_t ID_h;
};

void int_to_hashZr(int number,element_t &t) {
    char charArray[10];
    sprintf(charArray, "%d", number);
    element_init_Zr(t,pairing);
    element_from_hash(t,(void*)charArray,sizeof(charArray));
}

class AA{
private:
    element_t AK;
    //系统建立
    void setup(){
        //初始化pk
        element_init_G1(pk.G,pairing);
        element_init_G1(pk.G2,pairing);
        element_init_G1(pk.G3,pairing);
        element_init_G1(pk.U0,pairing);
        element_init_G1(pk.Un1,pairing);
        //选取 G G2 G3 U0 ... Un1
        element_random(pk.G);
        element_random(pk.G2);
        element_random(pk.G3);
        element_random(pk.U0);
        element_random(pk.Un1);
        for(int i = 0;i < S.size();i++){
            element_init_G1(pk.U[i].U,pairing);
            element_random(pk.U[i].U);
        }
        //选取alpha,alpha1,计算alpha2
        element_t alpha,alpha1,alpha2;
        element_init_Zr(alpha,pairing);
        element_init_Zr(alpha1,pairing);
        element_init_Zr(alpha2,pairing);
        element_random(alpha);
        element_random(alpha1);
        element_sub(alpha2,alpha,alpha1);
        //计算G1
        element_init_G1(pk.G1,pairing);
        element_mul_zn(pk.G1,pk.G,alpha);
        //初始化OK AK 计算OK AK
        element_init_G1(OK,pairing);
        element_init_G1(AK,pairing);
        element_mul_zn(OK,pk.G2,alpha1);
        element_mul_zn(AK,pk.G2,alpha2);
        //清除临时变量
        eclear(alpha);
        eclear(alpha1);
        eclear(alpha2);
    }
public:
    PK pk;
    element_t OK;
    AA(){
        setup();
    }
    //产生ID哈希
    IDHash idtohash(string ID){
        IDHash idhash;
        element_init_Zr(idhash.ID_h,pairing);
        char charID[ID.size()+1];
        strcpy(charID,ID.c_str());
        element_from_hash(idhash.ID_h,(void*)charID,sizeof(charID));
        return idhash;
    }

    //密钥产生
    SK keygen(SK1 &recsk1){
        SK sk;
        sk.sk1 = recsk1;
        //初始化r2
        element_t r2;
        element_init_Zr(r2,pairing);
        element_random(r2);
        //初始化sk2
        element_init_G1(sk.sk2.D20,pairing);
        element_init_G1(sk.sk2.D21,pairing);
        //计算sk2.D20
        element_set(sk.sk2.D20,AK);
        element_t hash_Ln1;
        int_to_hashZr(sk.sk1.D4[S.size()],hash_Ln1);
        element_t tempG1;
        element_init_G1(tempG1,pairing);
        element_mul_zn(tempG1,pk.Un1,hash_Ln1);
        element_mul_zn(tempG1,tempG1,r2);
        element_add(sk.sk2.D20,sk.sk2.D20,tempG1);
        //计算sk2.D21
        element_mul_zn(sk.sk2.D21,pk.G,r2);
        //清除临时变量
        eclear(r2);
        eclear(hash_Ln1);
        eclear(tempG1);
        return sk;
    }

    CT encrypt(element_t &M,vector<int> &W){//加密,M已初始化
        CT ct;
        //选取s
        element_t s;
        element_init_Zr(s,pairing);
        element_random(s);
        //计算从C0
        element_init_GT(ct.C0,pairing);
        pairing_apply(ct.C0,pk.G1,pk.G2,pairing);
        element_pow_zn(ct.C0,ct.C0,s);
        element_mul(ct.C0,ct.C0,M);
        //计算C1
        element_init_G1(ct.C1,pairing);
        element_mul_zn(ct.C1,pk.G,s);
        //计算C2
        element_init_G1(ct.C2,pairing);
        for(int i = 0;i < S.size();i++){
            element_t hash_l,tempmul;
            int_to_hashZr(W[i],hash_l);
            element_init_G1(tempmul,pairing);
            element_mul_zn(tempmul,pk.U[i].U,hash_l);
            element_add(ct.C2,ct.C2,tempmul);
            eclear(hash_l);
            eclear(tempmul);
        }
        element_mul_zn(ct.C2,ct.C2,s);
        //计算C3
        element_init_G1(ct.C3,pairing);
        element_t hashN1;
        int_to_hashZr(W[S.size()],hashN1);
        element_mul_zn(ct.C3,pk.Un1,hashN1);
        element_mul_zn(ct.C3,ct.C3,s);
        //计算E
        element_init_G1(ct.E,pairing);
        element_mul_zn(ct.E,pk.U0,s);
        eclear(s);
        eclear(hashN1);
        return ct;
    }
};

class KG_CSP{
public:
    SK1 keygen(vector<int> &L,element_t &ok,IDHash &idhash,PK &pk){
        SK1 sk1;
        //初始化r1
        element_t r1;
        element_init_Zr(r1,pairing);
        element_random(r1);
        //初始化sk1
        element_init_G1(sk1.D10,pairing);
        element_init_G1(sk1.D11,pairing);
        element_init_Zr(sk1.D3,pairing);
        //计算D10
        element_set(sk1.D10,ok);
        element_t temp;
        element_init_G1(temp,pairing);
        //id.u0
        element_mul_zn(temp,pk.U0,idhash.ID_h);
        //计算求和
        for(int i = 0;i < S.size();i++){
            element_t tempmul,hash_L;
            element_init_G1(tempmul,pairing);
            int_to_hashZr(L[i],hash_L);
            element_mul_zn(tempmul,pk.U[i].U,hash_L);
            element_add(temp,temp,tempmul);
            eclear(tempmul);
            eclear(hash_L);
        }
        //加G3
        element_add(temp,temp,pk.G3);
        element_mul_zn(temp,temp,r1);
        element_add(sk1.D10,sk1.D10,temp);
        //计算D11
        element_mul_zn(sk1.D11,pk.G,r1);
        //计算D3
        element_set(sk1.D3,idhash.ID_h);
        for(int i = 0;i <= S.size();i++){
            sk1.D4[i] = L[i];
        }
        eclear(r1);
        eclear(temp);
        return sk1;
    }
};

class User{
public:
    SK sk;
    void varify(PK &pk){
        element_t GTl;
        element_init_GT(GTl,pairing);
        //计算D10 + D20
        element_t temp_sum;
        element_init_G1(temp_sum,pairing);
        element_add(temp_sum,sk.sk1.D10,sk.sk2.D20);
        //计算左等式
        pairing_apply(GTl,temp_sum,pk.G,pairing);
        //右侧第一个映射
        element_t tempGT1;
        element_init_GT(tempGT1,pairing);
        pairing_apply(tempGT1,pk.G2,pk.G1,pairing);
        //临时
        element_t tempG1;
        element_init_G1(tempG1,pairing);
        element_mul_zn(tempG1,pk.U0,sk.sk1.D3);
        for(int i = 0;i < S.size();i++){
            element_t tempG11,hash_L;
            element_init_G1(tempG11,pairing);
            int_to_hashZr(sk.sk1.D4[i],hash_L);
            element_mul_zn(tempG11,pk.U[i].U,hash_L);
            element_add(tempG1,tempG1,tempG11);
            //清除临时变量
            eclear(hash_L);
            eclear(tempG11);
        }
        element_add(tempG1,tempG1,pk.G3);
        //右侧第二个映射
        element_t tempGT2;
        element_init_GT(tempGT2,pairing);
        pairing_apply(tempGT2,tempG1,sk.sk1.D11,pairing);
        //右侧第三个映射
        element_t tempGT3,hash_L1,tempG12;
        element_init_GT(tempGT3,pairing);
        int_to_hashZr(sk.sk1.D4[S.size()],hash_L1);
        element_init_G1(tempG12,pairing);
        element_mul_zn(tempG12,pk.Un1,hash_L1);
        pairing_apply(tempGT3,tempG12,sk.sk2.D21,pairing);
        element_t GTr;
        element_init_GT(GTr,pairing);
        element_mul(GTr,tempGT1,tempGT2);
        element_mul(GTr,GTr,tempGT3);
        if(element_cmp(GTr,GTl) == 0){
            cout<<"验证成功！"<<endl;
        }
        else{
            cout<<"验证失败!"<<endl;
        }
    }

    void decrypt(CT &ct,element_t &M){
        //生成C2‘
        element_t C2p;
        element_init_G1(C2p,pairing);
        element_set(C2p,ct.C2);
        element_t temp;
        element_init_G1(temp,pairing);
        element_mul_zn(temp,ct.E,sk.sk1.D3);
        element_add(C2p,C2p,temp);
        //分子部分
        element_t tempGT1,tempGT2,fz;
        element_init_GT(tempGT1,pairing);
        element_init_GT(tempGT2,pairing);
        element_init_GT(fz,pairing);
        pairing_apply(tempGT1,sk.sk1.D11,C2p,pairing);
        pairing_apply(tempGT2,sk.sk2.D21,ct.C3,pairing);
        element_mul(fz,tempGT1,tempGT2);
        element_mul(fz,fz,ct.C0);
        //分母部分
        element_t fm;
        element_init_GT(fm,pairing);
        pairing_apply(tempGT1,sk.sk1.D10,ct.C1,pairing);
        pairing_apply(tempGT2,sk.sk2.D20,ct.C1,pairing);
        element_mul(fm,tempGT1,tempGT1);
        //解密
        element_t dec_M;
        element_init_GT(dec_M,pairing);
        element_div(dec_M,fz,fm);
        if(element_cmp(M,dec_M) == 0){
            cout<<"解密成功！"<<endl;
        }
        else{
            cout<<"解密失败"<<endl;
        }
    }
};

int main(int argc,char** argv){
    pbc_demo_pairing_init(pairing,argc,argv);
    User u;
    AA aa;
    vector<int> L = {1,3,6,10,1};
    vector<int> W = {1,3,6,10,1};
    KG_CSP kg_csp;
    IDHash idhash;
    idhash = aa.idtohash("lichaohui");
    SK1 sk1;
    sk1 = kg_csp.keygen(L,aa.OK,idhash,aa.pk);
    u.sk = aa.keygen(sk1);
    u.varify(aa.pk);
    element_t M;
    element_init_GT(M,pairing);
    element_random(M);
    CT ct;
    ct = aa.encrypt(M,W);
    u.decrypt(ct,M);
    return 0;
}