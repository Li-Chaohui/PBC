#include <pbc/pbc.h>
#include <pbc/pbc_test.h>
#include <bits/stdc++.h>

using namespace std;
//用户数量
#define n 10
#define m 10

std::chrono::duration<double> AA_setup_time,
Keygen_kscsp_time,
Keygen_aa_time,
user_verify_time,
DO_setup_time,
DO_keygen_time,
Encrypt_CT1_time,
Encrypt_CT2_time,
Decrypt_CT2_time,
Decrypt_CT1_time;

pairing_t pairing;

//通配符取-1
vector<int> S(m,1);

struct Ui{
    element_t U;
};

struct PK{
    element_t G,G1,G2,G3,U0,Un1;
    vector<Ui> U;
    PK():U(S.size()){}
};

struct CT1{
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

struct Gi{
    element_t G;
};

struct PK_BGW{
    element_t G,V;
    vector<Gi> G_2N;
    PK_BGW():G_2N(2*n+1){}
};

struct Di{
    element_t D;
};

//用户解密密钥
struct UK{
    vector<Di> D;
    UK():D(n+1){}
};

struct CT2{
    element_t C0,C1,K;//C2为K
};
//输出函数封装
void ecout(element_t &t,string s = ""){
    cout<<s;
    element_printf("%B\n",t);
}
//将用户属性进行哈希
void int_to_hash(int number,element_t &t) {
    char* charArray =(char*)malloc(sizeof(char) * 10);
    sprintf(charArray, "%d", number);
    size_t len = strlen(charArray);
    element_from_hash(t,(void*)charArray,len);
    free(charArray);
}
//对用户ID进行哈希
void toIDhash(string ID,element_t &ID_hash){
    char charID[ID.size()+1];
    strcpy(charID,ID.c_str());
    element_from_hash(ID_hash,(void*)charID,sizeof(charID));
}

class AA{
private:
    /**
     * AA系统建立
     */
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
    AA(string ID) {
        auto start = std::chrono::steady_clock::now();
        setup();
        auto end = std::chrono::steady_clock::now();
        AA_setup_time = end - start;
        //计算IDHash
        element_init_Zr(IDHash, pairing);
        toIDhash(ID, IDHash);
    }
    /**
     * 根据用户属性生成密钥
     * @param sk2
     * @param L
     */
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
    /**
     * 根据访问策略生成CT1
     * @param W
     * @param ct1
     */
    void encrypt(vector<int> &W,CT1 &ct1){
        cout<<"AA执行加密生成密文CT1"<<endl<<endl;
        element_t s,tempG1,WZr;
        //初始化
        element_init_Zr(s,pairing);
        element_init_Zr(WZr,pairing);
        element_init_GT(M,pairing);
        element_init_GT(ct1.C0,pairing);
        element_init_G1(ct1.C1,pairing);
        element_init_G1(ct1.C2,pairing);
        element_init_G1(ct1.C3,pairing);
        element_init_G1(ct1.E,pairing);
        element_init_G1(tempG1,pairing);
        //选取s，M
        element_random(s);
        element_random(M);
        //计算C0
        pairing_apply(ct1.C0,pk.G1,pk.G2,pairing);
        element_pow_zn(ct1.C0,ct1.C0,s);
        element_mul(ct1.C0,ct1.C0,M);
        //计算C1
        element_mul_zn(ct1.C1,pk.G,s);
        //计算C2 T
        element_set(ct1.C2,pk.G3);
        for(int i = 0;i < S.size();i++){
            element_t tempmul;
            element_init_G1(tempmul,pairing);
            int_to_hash(W[i],WZr);
            element_mul_zn(tempmul,pk.U[i].U,WZr);

            element_add(ct1.C2,ct1.C2,tempmul);

            element_clear(tempmul);
        }
        element_mul_zn(ct1.C2,ct1.C2,s);
        //计算C3
        int_to_hash(W[S.size()],WZr);
        element_mul_zn(ct1.C3,pk.Un1,WZr);
        element_mul_zn(ct1.C3,ct1.C3,s);
        //计算E
        element_mul_zn(ct1.E,pk.U0,s);
        //输出密文
        ecout(ct1.C0,"CT1.C0 = ");
        ecout(ct1.C1,"CT1.C1 = ");
        ecout(ct1.C2,"CT1.C2 = ");
        ecout(ct1.C3,"CT1.C3 = ");
        ecout(ct1.E,"CT1.E = ");
        cout<<endl;
        //清除临时变量
        element_clear(s);
        element_clear(tempG1);
        element_clear(WZr);
    }
    /**
     * 用户清除变量
     */
    void clear(){
        element_clear(AK);
        element_clear(OK);
        element_clear(IDHash);
        element_clear(pk.G);
        element_clear(pk.G1);
        element_clear(pk.G2);
        element_clear(pk.G3);
        element_clear(pk.U0);
        element_clear(pk.Un1);
        element_clear(M);
        for(int i = 0;i < S.size();i++){
            element_clear(pk.U[i].U);
        }
    }

};

class KG_CSP{
public:
    /**
     * 根据用户身份信息和属性生成密钥
     * @param pk
     * @param ID_hash
     * @param L
     * @param OK
     * @param sk1
     */
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
    /**
     * 用户对密钥进行验证
     * @param pk
     */
    void verify(PK &pk){
        cout<<"用户对产生的密钥进行验证"<<endl<<endl;
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
            cout<<"用户验证成功！"<<endl<<endl;
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
    /**
     * 用户执行解密，需要验证解密正确性因此传入消息M
     * @param ct1
     * @param M
     */
    void decrypt(CT1 &ct1,element_t &M){
        cout<<endl<<"对CT1执行解密"<<endl<<endl;
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
        element_mul_zn(tempG1,ct1.E,sk.sk1.D3);
        element_add(C2p,ct1.C2,tempG1);
        //分子部分
        pairing_apply(fz1,sk.sk1.D11,C2p,pairing);
        pairing_apply(fz2,sk.sk2.D21,ct1.C3,pairing);
        element_mul(fz1,fz1,fz2);
        element_mul(fz1,fz1,ct1.C0);
        //分母部分
        pairing_apply(fm1,sk.sk1.D10,ct1.C1,pairing);
        pairing_apply(fm2,sk.sk2.D20,ct1.C1,pairing);
        element_mul(fm1,fm1,fm2);
        //解密
        element_div(decM,fz1,fm1);
        if(!element_cmp(M,decM)){
            cout<<"解密成功！"<<endl<<endl;
            ecout(decM,"解密恢复后的消息:");
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
    /**
     * 清除变量
     */
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

class DO{
private:
    UK uk;
    /**
     * DO系统建立
     */
    void setup(){
        element_t alpha;
        //初始化
        element_init_Zr(alpha,pairing);
        element_init_Zr(msk_bgw,pairing);
        element_init_G1(pk_bgw.G,pairing);
        element_init_G1(pk_bgw.V,pairing);
        //生成alpha G
        element_random(alpha);
        element_random(pk_bgw.G);
        element_random(msk_bgw);
        //计算V
        element_pow_zn(pk_bgw.V,pk_bgw.G,msk_bgw);
        //计算Gi
        for(int i = 1;i <= 2*n;i++){
            element_t pow;
            element_init_Zr(pow,pairing);
            element_init_G1(pk_bgw.G_2N[i].G,pairing);
            element_set_si(pow,i);

            element_pow_zn(pow,alpha,pow);
            element_mul_zn(pk_bgw.G_2N[i].G,pk_bgw.G,pow);

            element_clear(pow);
        }
        //计算用户解密密钥
        for(int i = 1;i <= n;i++){
            element_init_G1(uk.D[i].D,pairing);

            element_mul_zn(uk.D[i].D,pk_bgw.G_2N[i].G,msk_bgw);
        }
        //清除临时变量
        element_clear(alpha);
    }
public:
    PK_BGW pk_bgw;
    element_t msk_bgw,M;
    vector<int> vaild;
    DO(){
        setup();
        for(int i = 0;i < n+1;i++){
            vaild.push_back(i%2==0);
        }
    }
    /**
     * DO执行加密生成CT2
     * @param ct2
     */
    void encrypt(CT2 &ct2){
        cout<<"DO执行加密生成CT2"<<endl<<endl;
        element_t t;
        //初始化
        element_init_Zr(t,pairing);
        element_init_G1(ct2.C0,pairing);
        element_init_G1(ct2.C1,pairing);
        element_init_GT(ct2.K,pairing);
        //随机生成t
        element_random(t);
        //计算C0
        element_pow_zn(ct2.C0,pk_bgw.G,t);
        //计算C1
        element_set(ct2.C1,pk_bgw.V);
        for(int i = 1;i <= n;i++){
            if(vaild[i]){
                element_add(ct2.C1,ct2.C1,pk_bgw.G_2N[n+1-i].G);
            }
        }
        element_mul_zn(ct2.C1,ct2.C1,t);
        //计算K
        pairing_apply(ct2.K,pk_bgw.G,pk_bgw.G_2N[n+1].G,pairing);
        element_pow_zn(ct2.K,ct2.K,t);
        //输出密文
        ecout(ct2.C0,"CT2.C0 = ");
        ecout(ct2.C1,"CT2.C1 = ");
        ecout(ct2.K,"CT2.K = ");
        cout<<endl;
        //清除临时变量
        element_clear(t);
    }
    /**
     * 验证用户是否具备数据访问权限
     * @param i 用户下标
     * @param ct2
     * @return
     */
    bool user_verify(int i,CT2 &ct2){
        cout<<"对用户进行数据访问权限的验证"<<endl<<endl;
        //1.判断是否为非法下标
        if(vaild[i] == 0){
            cout<<"非法下标"<<endl;
            return false;
        }
        //2.计算K
        element_t temp_k,temp_GT1,temp_GT2,temp_G1;
        element_init_GT(temp_k,pairing);
        element_init_GT(temp_GT1,pairing);
        element_init_GT(temp_GT2,pairing);
        element_init_G1(temp_G1,pairing);
        //分子
        pairing_apply(temp_GT1,pk_bgw.G_2N[i].G,ct2.C1,pairing);
        //分母
        element_set(temp_G1,uk.D[i].D);
        for(int j = 1;j<=n;j++){
            if(j!=i && vaild[j]==1){
                element_add(temp_G1,temp_G1,pk_bgw.G_2N[n+1-j+i].G);
            }
        }
        pairing_apply(temp_GT2,temp_G1,ct2.C0,pairing);
        //最终计算的K
        element_div(temp_k,temp_GT1,temp_GT2);

        //清除临时变量
        element_clear(temp_G1);
        element_clear(temp_GT1);
        element_clear(temp_GT2);

        if(element_cmp(temp_k,ct2.K)==0){
            cout<<"访问权限验证成功！获得CT1访问权限"<<endl<<endl;
            ecout(temp_k,"恢复密钥:");
            element_clear(temp_k);
            return true;
        }
        else{
            cout<<"访问权限验证失败"<<endl;
            element_clear(temp_k);
            return false;
        }
    }
    /**
     * 清除变量
     */
    void clear(){
        element_clear(pk_bgw.G);
        element_clear(pk_bgw.V);
        element_clear(msk_bgw);
        for(int i = 1;i <= 2*n;i++){
            element_clear(pk_bgw.G_2N[i].G);
            if(i <= n){
                element_clear(uk.D[i].D);
            }
        }
    }
};
/**
 * 清除变量
 * @param ct1
 * @param ct2
 */
void clearCT(CT1 &ct1,CT2 &ct2){
    element_clear(ct1.C0);
    element_clear(ct1.C1);
    element_clear(ct1.C2);
    element_clear(ct1.C3);
    element_clear(ct1.E);

    element_clear(ct2.C0);
    element_clear(ct2.C1);
    element_clear(ct2.K);
}

int main(int argc,char** argv){
    pbc_demo_pairing_init(pairing,argc,argv);
    cout<<"在双线性群环境下进行测试"<<endl<<endl;
    vector<int> L(m+1,1);
    AA aa("lichaohui");
    KG_CSP kg;
    DO dO;
    User u;
    CT1 ct1;
    CT2 ct2;
    //执行密钥产生
    auto start = std::chrono::steady_clock::now();
    kg.keygen(aa.pk,aa.IDHash,L,aa.OK,u.sk.sk1);
    auto end = std::chrono::steady_clock::now();
    Keygen_aa_time = end - start;
    start = std::chrono::steady_clock::now();
    aa.keygen(u.sk.sk2,L);
    end = std::chrono::steady_clock::now();
    Keygen_kscsp_time = end - start;
    //用户对密钥进行验证
    start = std::chrono::steady_clock::now();
    u.verify(aa.pk);
    end = std::chrono::steady_clock::now();
    user_verify_time = end - start;
    //执行加密
    start = std::chrono::steady_clock::now();
    aa.encrypt(L,ct1);
    end = std::chrono::steady_clock::now();
    Encrypt_CT1_time = end - start;
    start = std::chrono::steady_clock::now();
    dO.encrypt(ct2);
    end = std::chrono::steady_clock::now();
    Encrypt_CT2_time = end - start;
    //对用户的文件访问权限进行验证
    start = std::chrono::steady_clock::now();
    bool is_verify =  dO.user_verify(2,ct2);
    if(is_verify){
        u.decrypt(ct1,aa.M);
    }
    else{
        cout<<"访问终止,用户不具备密文下载权限"<<endl;
    }
    //用户追踪
    cout<<endl<<"用户追踪："<<endl;
    ecout(u.sk.sk1.D3,"用户IDHash:");
    //清除变量
    clearCT(ct1,ct2);
    aa.clear();
    dO.clear();
    u.clear();
    pairing_clear(pairing);
    return 0;
}