#include "../my.h"

pairing_t pairing;

vector<vector<int>> S = {
	{1,2},{3,4,5},{6,7,8,9}
};

struct AB{
	element_t aA,bA;
};

struct PK{
	element_t Y,G;
	vector<vector<AB>> aA_bA;
	PK(){
		for(int i = 0;i < S.size();i++){
			vector<AB> t(S[i].size());
			aA_bA.emplace_back(t);
		}
	}
};

struct ab{
	element_t a,b;
};

struct MK{
	element_t w;
	vector<vector<ab>> a_b;
	MK(){
		for(int i = 0;i < S.size();i++){
			vector<ab> t(S[i].size());
			a_b.emplace_back(t);
		}
	}
};

struct e{
    element_t A;
};

struct Di{
    element_t D0,D1,D2;
};

struct SK_L{
    element_t D0;
    vector<Di> D;
    SK_L():D(S.size()){}
};

struct C_e{
    element_t C1,C2;
};

struct CT{
    vector<int> W;
    element_t C_w,C0;
    vector<vector<C_e>> C;
    CT():W(S.size()){
        for(int i = 0;i < S.size();i++){
            vector<C_e> t(S[i].size());
            C.emplace_back(t);
        }
    }
};

struct r_e{
    element_t r;
};

struct C_p_e{
    element_t C1_1,C2_1;
};

class SP{
private:
    MK mk;
    element_t M;//秘文
    vector<vector<e>> A;
    void setUp(){
        //生成G点
        element_init_G1(pk.G,pairing);
        element_random(pk.G);
        //生成w，计算Y
        element_init_Zr(mk.w,pairing);
        element_init_GT(pk.Y,pairing);

        element_random(mk.w);

        pairing_apply(pk.Y,pk.G,pk.G,pairing);
        element_pow_zn(pk.Y,pk.Y,mk.w);

        //初始化A a b a.A b.A ,计算a.A b.A
        for(int i = 0;i < S.size();i++){
            vector<e> t(S[i].size());
            A.emplace_back(t);
            for(int j = 0;j < S[i].size();j++){
                element_init_Zr(mk.a_b[i][j].a,pairing);
                element_init_Zr(mk.a_b[i][j].b,pairing);

                element_random(mk.a_b[i][j].a);
                element_random(mk.a_b[i][j].b);

                element_init_G1(A[i][j].A,pairing);

                element_random(A[i][j].A);

                element_init_G1(pk.aA_bA[i][j].aA,pairing);
                element_init_G1(pk.aA_bA[i][j].bA,pairing);

                element_mul_zn(pk.aA_bA[i][j].aA,A[i][j].A,mk.a_b[i][j].a);
                element_mul_zn(pk.aA_bA[i][j].bA,A[i][j].A,mk.a_b[i][j].b);
            }
        }

    }

    vector<int> getIndex(const vector<int> &L){
        vector<int> index(L.size(),-1);
        for(int i = 0;i < S.size();i++){
            for(int j = 0;j < S[i].size();j++){
                if(S[i][j] == L[i]){
                    index[i] = j;
                }
            }
            if(index[i] == -1){
                cout<<"用户属性不属于集合"<<endl;
                return {};
            }
        }
        return index;
    }

public:
    PK pk;
    CT ct;
    SP(vector<int> &W){
        setUp();
        for(int i = 0;i < S.size();i++){
            ct.W[i] = W[i];
        }
    }

    SK_L keyGen(const vector<int> &L){
        SK_L skl;
        vector<int> index = getIndex(L);
        if(!index.size()){
            return skl;
        }
        //si,lambda
        vector<element_t> s(S.size());
        vector<element_t> lambda(S.size());
        //s
        element_t s_sum;
        element_init_Zr(s_sum,pairing);
        for(int i = 0;i < S.size();i++){
            //初始化
            element_init_Zr(s[i],pairing);
            element_init_Zr(lambda[i],pairing);
            //选取
            element_random(s[i]);
            element_random(lambda[i]);
            //求和
            element_add(s_sum,s_sum,s[i]);
        }
        //计算D0
        element_t tempZr;
        element_init_G1(skl.D0,pairing);
        element_init_Zr(tempZr,pairing);
        element_sub(tempZr,mk.w,s_sum);
        element_mul_zn(skl.D0,pk.G,tempZr);
        //计算Di
        for(int i = 0;i < S.size();i++){
            //初始化
            element_init_G1(skl.D[i].D0,pairing);
            element_init_G1(skl.D[i].D1,pairing);
            element_init_G1(skl.D[i].D2,pairing);
            //1.计算Di_0
            element_t tempG1_1,tempG1_2;
            element_init_G1(tempG1_1,pairing);
            element_init_G1(tempG1_2,pairing);
            //临时变量s.G
            element_mul_zn(tempG1_1,pk.G,s[i]);
            //临时变量aij.bij
            element_mul(tempZr,mk.a_b[i][index[i]].a,mk.a_b[i][index[i]].b);
            element_mul(tempZr,tempZr,lambda[i]);
            element_mul_zn(tempG1_2,A[i][index[i]].A,tempZr);
            element_add(skl.D[i].D0,tempG1_1,tempG1_2);
            //2.计算Di_1
            element_mul_zn(tempZr,mk.a_b[i][index[i]].a,lambda[i]);
            element_mul_zn(skl.D[i].D1,pk.G,tempZr);
            //3.计算Di_2
            element_mul_zn(tempZr,mk.a_b[i][index[i]].b,lambda[i]);
            element_mul_zn(skl.D[i].D2,pk.G,tempZr);
        }
        return skl;
    }

    void encrypt(){
        //选取r
        element_t r;
        element_init_Zr(r,pairing);
        element_random(r);
        //选取M
        element_init_GT(M,pairing);
        element_random(M);
        //计算C_w
        element_init_GT(ct.C_w,pairing);
        element_pow_zn(ct.C_w,pk.Y,r);
        element_mul(ct.C_w,M,ct.C_w);
        //计算C0
        element_init_G1(ct.C0,pairing);
        element_mul_zn(ct.C0,pk.G,r);
        //选取r
        vector<vector<r_e>> r_set;
        for(int i = 0;i < S.size();i++){
            vector<r_e> t(S[i].size());
            r_set.emplace_back(t);
            for(int j = 0;j < S[i].size();j++){
                element_init_Zr(r_set[i][j].r,pairing);

                element_random(r_set[i][j].r);

                //计算Ci1
                element_init_G1(ct.C[i][j].C1,pairing);
                element_init_G1(ct.C[i][j].C2,pairing);
                if(ct.W[i] == S[i][j]){
                    element_mul_zn(ct.C[i][j].C1,pk.aA_bA[i][j].bA,r_set[i][j].r);
                    //计算Ci2
                    element_t tempZr;
                    element_init_Zr(tempZr,pairing);
                    element_sub(tempZr,r,r_set[i][j].r);
                    element_mul_zn(ct.C[i][j].C2,pk.aA_bA[i][j].aA,tempZr);
                }
                else{
                    element_random(ct.C[i][j].C1);
                    element_random(ct.C[i][j].C2);
                }
            }
        }
    }


    void decrypt(const vector<int> &L,SK_L &skl){
        vector<C_p_e> Cp(S.size());
        vector<int> index = getIndex(L);
        for(int i = 0;i < S.size();i++){
            element_init_G1(Cp[i].C1_1,pairing);
            element_init_G1(Cp[i].C2_1,pairing);

            element_set(Cp[i].C1_1,ct.C[i][index[i]].C1);
            element_set(Cp[i].C2_1,ct.C[i][index[i]].C2);
        }
        //恢复明文
        element_t decM;
        element_init_GT(decM,pairing);
        //初始化临时变量
        element_t tempGt1,tempGt2,tempGt3,tempGt4;
        element_init_GT(tempGt1,pairing);
        element_init_GT(tempGt2,pairing);
        element_init_GT(tempGt3,pairing);
        element_init_GT(tempGt4,pairing);
        //计算分子
        element_set(tempGt1,ct.C_w);
        for(int i = 0;i < S.size();i++){
            pairing_apply(tempGt2,Cp[i].C1_1,skl.D[i].D1,pairing);
            pairing_apply(tempGt3,Cp[i].C2_1,skl.D[i].D2,pairing);

            element_mul(tempGt4,tempGt2,tempGt3);
            element_mul(tempGt1,tempGt1,tempGt4);
        }
        //计算分母
        pairing_apply(tempGt2,ct.C0,skl.D0,pairing);
        for(int i = 0;i < S.size();i++){
            pairing_apply(tempGt3,ct.C0,skl.D[i].D0,pairing);

            element_mul(tempGt2,tempGt2,tempGt3);
        }
        element_div(decM,tempGt1,tempGt2);
        if(element_cmp(decM,M) == 0){
            cout<<"解密成功！"<<endl;
        }
        else{
            cout<<"解密失败！"<<endl;
        }
    }

    void clear(SK_L &skl){
        //清除
        for(int i = 0;i < S.size();i++){
            eclear(skl.D[i].D0);
            eclear(skl.D[i].D1);
            eclear(skl.D[i].D2);
            for(int j = 0;j < S[i].size();j++){
                eclear(pk.aA_bA[i][j].aA);
                eclear(pk.aA_bA[i][j].bA);

                eclear(mk.a_b[i][j].a);
                eclear(mk.a_b[i][j].b);
                eclear(A[i][j].A);
            }
        }
        eclear(pk.Y);
        eclear(pk.G);

        eclear(mk.w);
    }
};



int main(int argc,char** argv){
	pbc_demo_pairing_init(pairing,argc,argv);
    vector<int> W = {1,5,9};
    SP sp(W);
    SK_L skl;
    vector<int> L = {1,5,9};
    skl = sp.keyGen(L);
    sp.encrypt();
    sp.decrypt(L,skl);
    sp.clear(skl);
    pairing_clear(pairing);
	return 0;
}