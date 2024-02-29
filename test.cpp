/*
	本程序对支持外包的Li-Ren-Kim方案进行仿真实现。
	 (1)在公钥中定义数组Attribute_universe，存储属性全集，其中的每个属性用具体数字替代。
用1表示属性A1，用2表示属性A2，以此类推。 
	(2)集合Si的产生方式如下：
	S1={1,2,...,Size_of_attribute_value_set}。
	S2={Size_of_attribute_value_set+1,Size_of_attribute_value_set+2,...,2*Size_of_attribute_value_set}。
	S3={2*Size_of_attribute_value_set+1,2*Size_of_attribute_value_set+2,...,3*Size_of_attribute_value_set}。
	...
	(3)属性全集的规模为Size_of_attribute_universe+1，用户属性列表的长度为Size_of_attribute_list+1，两者相等。其中，
其中，第1至Size_of_attribute_universe个属性为正常的属性，第Size_of_attribute_universe+1个属性为虚拟属性。 
    (4)Trace算法进行了简化。
*/

#include <pbc/pbc.h>
#include <pbc/pbc_test.h>



#define Size_of_attribute_universe 5//定义属性全集的规模
#define Size_of_attribute_list 5//定义用户属性列表的长度
#define Size_of_attribute_value_set 5//定义每个属性可能取值的个数
#define Size_of_embedded_attribute_list 5//定义嵌入在密文中的属性列表的长度

#define Len_msk sizeof(struct master_secret_key) //结构体master_secret_key的长度
#define Len_pp sizeof(struct public_params) //结构体public_params的长度
#define Len_ok sizeof(struct ok)
#define Len_ak sizeof(struct ak)
#define Len_usk_gen_by_AA sizeof(struct user_attribute_secret_key_gen_by_AA)
#define Len_usk_gen_by_KGCSP sizeof(struct user_attribute_secret_key_gen_by_KGCSP)
#define Len_ct sizeof(struct ciphertext) //结构体ciphertext的长度
#define Len_rm sizeof(struct recovered_message) //结构体recovered_message的长度

pairing_t pairing;

/*
	该结构体用于保存属性权威的主密钥
*/
struct master_secret_key{
		element_t alpha;
		element_t alpha1;
		element_t alpha2;
};


/*
	该结构体用于保存属性权威发布的系统公开参数
*/
struct public_params{
		element_t G,G1,G2,G3;//群G的生成元
		element_t Attribute_universe[Size_of_attribute_universe+2];//属性全集
		element_t S[Size_of_attribute_universe+2][Size_of_attribute_value_set+2];//属性值集合
		element_t U[Size_of_attribute_universe+2];//公开元素集合
};

/*
	该结构体用于保存AA为KG-CSP产生的外包密钥
*/
struct ok{
		element_t OK;
};

/*
	该结构体用于保存AA在KeyGen阶段自行使用的部分密钥
*/
struct ak{
		element_t AK;
};

/*
	该结构体用于临时保存用户属性解密私钥
中由属性权威产生的部分（对应于用户其他属性）
*/

struct user_attribute_secret_key_gen_by_KGCSP{
		element_t D10,D11;////用户属性解密私钥元素
		element_t D3;
		element_t D4[Size_of_attribute_list+2];//用户属性列表;
};
/*
	该结构体用于临时保存用户属性解密私钥中
由属性权威产生的部分（对应于虚拟属性）
*/
struct user_attribute_secret_key_gen_by_AA{
		element_t D20,D21;//用户属性列表
};


/*
	该结构体用于保存密文
*/
struct ciphertext{
	element_t W[Size_of_embedded_attribute_list+2];//访问控制策略列表
	element_t C0,C1,C2,C3,E;
};


/*
	该结构体用于保存解密结果。若解密正确，它的取值等于原始消息；若解密错误，它的取值与原始消息不等。
*/
struct recovered_message{
	element_t recovered_M;
};


/*
	作用：模拟方案的系统建立过程。当前函数用于产生属性权威的主密钥。
*/
struct master_secret_key * Setup_gen_msk();

/*
	作用：输出权威主密钥，检查主密钥的产生是否成功。
*/
void Output_master_secret_key(struct master_secret_key * msk);

/*
	作用：模拟方案的系统建立过程。当前函数用于产生系统公开参数。
	参数：
	msk：属性权威主密钥的指针

*/
struct public_params * Setup_gen_pp(struct master_secret_key * msk);

/*
	作用：输出系统公开参数，检查这些参数是否成功产生。
	参数：
	pp:公开参数指针
*/
void Output_pp(struct public_params * pp);


/*
	作用：模拟AA产生OK的过程
	参数：
	ak_gen_by_AA：指向AK的指针
	msk：指向权威主密钥的指针
*/
struct ok * Gen_OK(struct public_params * pp,struct master_secret_key * msk);



/*
	作用：测试OK是否正确。
	参数：
	ok_gen_by_AA：指向OK的指针
*/
void Output_ok(struct ok * ok_gen_by_AA);


/*
	作用：模拟AA产生AK的过程。
	参数：
	msk：指向权威主密钥的指针
	pp：指向公开参数的指针
	
*/
struct ak * Gen_AK(struct public_params * pp, struct master_secret_key * msk);

/*
	作用：测试AK是否正确。
	参数：
	ak_gen_by_AA：指向AK的指针
*/
void Output_ak(struct ak * ak_gen_by_AA);

/*
	作用：模拟KG-CSP协助AA产生部分用户解密私钥的过程

	参数：
	pp：指向公开参数的指针
	ok_gen_by_AA：指向OK的指针
	ID：用户身份
*/
struct user_attribute_secret_key_gen_by_KGCSP * KeyGen_by_KGCSP(struct public_params * pp,
struct ok * ok_gen_by_AA,element_t ID);




/*
	作用：输出KG-CSP产生的部分用户私钥，检查这部分私钥的产生是否成功。
	参数：
	usk_gen_by_KGCSP：指向KG-CSP协助权威产生的部分用户解密私钥的指针
*/
void Output_master_secret_key_by_KGCSP(struct user_attribute_secret_key_gen_by_KGCSP * usk_gen_by_KGCSP);

/*
	作用：模拟AA产生部分用户解密私钥的过程。
	参数：
	pp：指向系统公开参数的指针
	ak_gen_by_AA：指向AK的指针
*/
struct user_attribute_secret_key_gen_by_AA * KeyGen_by_AA(struct public_params * pp,
struct ak * ak_gen_by_AA);


/*
	作用：输出AA产生的剩余用户解密私钥，检查这部分私钥的产生是否成功。
	参数：
	usk_gen_by_AA：指向AA自行产生的剩余用户解密私钥
*/
void Output_master_secret_key_by_AA(struct user_attribute_secret_key_gen_by_AA * usk_gen_by_AA);

/*
	作用：检查该私钥是否满足验证等式。
	参数：
	pp：系统公开参数指针
	usk_gen_by_KGCSP：用户私钥指针
	usk_gen_by_AA：用户私钥指针
	
*/
int Check_user_attribute_secret_key(struct public_params * pp,
struct user_attribute_secret_key_gen_by_KGCSP * usk_gen_by_KGCSP,
struct user_attribute_secret_key_gen_by_AA * usk_gen_by_AA);


/*
	作用：产生属性加密密文
	参数：
	Message：待加密的消息
	pp：公开参数指针
*/
struct ciphertext * Encrypt(element_t Message, struct public_params * pp);



/*
	作用：输出密文，检查密文是否正确。
	参数：
	ct：密文指针
*/
void Output_ciphertext(struct ciphertext * ct);

/*
	作用：检查用户属性集是否满足密文中的访问控制策略，即对于i=1,...,n，是否满足Li属于Wi。 
	最终，函数返回1表示满足，返回0表示不满足。
	参数：
	ct：密文指针
	usk_gen_by_KGCSP：用户解密私钥指针
	dec_result：指向解密恢复得到的消息的指针
*/
int Check(struct ciphertext * ct,struct user_attribute_secret_key_gen_by_KGCSP * usk_gen_by_KGCSP);
/*
	作用：对解密结果进行初始化。
*/
struct recovered_message * Init_rec_m();

/*
	作用：执行属性解密，返回指向被恢复消息的指针。
	参数：
	ct：密文指针
	usk_gen_by_KGCSP：用户解密私钥指针
	usk_gen_by_AA：用户私钥指针
	dec_result：指向解密恢复得到的消息的指针
*/
void Decrypt(struct ciphertext * ct,
struct user_attribute_secret_key_gen_by_KGCSP * usk_gen_by_KGCSP,
struct user_attribute_secret_key_gen_by_AA * usk_gen_by_AA,
struct recovered_message * dec_result);

/*
	作用：评估解密结果。若原始消息与解密得到的消息相同，则判定解密成功。否则，判定解密失败。
	参数：
	Message：原始消息
	result：Decrypt函数返回的指针，它指向解密得到的消息
*/
void Judge_decryption_result(element_t Message,struct recovered_message * dec_result);



/*
	作用：对用户追踪过程进行模拟。
	参数：
	pp：指向系统公开参数
	usk：指向被泄露的用户私钥
*/
void Trace(struct public_params * pp,struct user_attribute_secret_key_gen_by_KGCSP * usk_gen_by_KGCSP,
struct user_attribute_secret_key_gen_by_AA * usk_gen_by_AA);


//测试A类型的对环境
int main(int argc, char ** argv){
	struct master_secret_key * msk;//主密钥指针
	struct public_params * pp;//系统公开参数指针
	struct ciphertext * ct;//密文指针
	struct recovered_message * dec_result;//解密结果指针
	struct ak * ak_gen_by_AA;//AK指针
	struct ok * ok_gen_by_AA;//OK指针
	struct user_attribute_secret_key_gen_by_KGCSP * usk_gen_by_KGCSP;//用户解密私钥（KGCSP产生的部分）指针
	struct user_attribute_secret_key_gen_by_AA * usk_gen_by_AA;//用户解密私钥（AA产生的部分）指针

	element_t ID;//保存用户身份
	element_t Message;//保存原始消息
	
	
	printf("在类型为A的双线性对环境下进行测试\n");
	//初始化对环境A
	pbc_demo_pairing_init(pairing,argc,argv);
	
	//步骤1：对系统系统建立过程进行模拟
	//步骤1.1：产生属性权威的主密钥
	msk=Setup_gen_msk();
	//测试：检查主密钥是否成功产生
	//Output_master_secret_key(msk);
	
	//步骤1.2：产生系统公开参数
	pp=Setup_gen_pp(msk);
	//测试：检查系统公开参数的产生是否正确
	//Output_pp(pp);

	//步骤1.3：产生OK
	ok_gen_by_AA=Gen_OK(pp,msk);
	//输出OK
	//Output_ok(ok_gen_by_AA);
	
	//步骤1.4：产生AK
	ak_gen_by_AA=Gen_AK(pp,msk);
	//输出AK
	//Output_ak(ak_gen_by_AA);

	//步骤2：为用户产生解密私钥
	//步骤2.1：设置用户身份信息
	element_init_Zr(ID,pairing);
	element_random(ID);
	
	//步骤2.2：模拟KGCSP为用户产生部分的解密私钥
	usk_gen_by_KGCSP=KeyGen_by_KGCSP(pp,ok_gen_by_AA,ID);
	//输出KGCSP为用户产生部分的解密私钥
	//Output_master_secret_key_by_KGCSP(usk_gen_by_KGCSP);
	
	//步骤2.3：模拟AA为用户产生部分的解密私钥
	usk_gen_by_AA=KeyGen_by_AA(pp,ak_gen_by_AA);
	//输出AA为用户产生部分的解密私钥
	//Output_master_secret_key_by_AA(usk_gen_by_AA);

	//步骤2.4：检查用户解密私钥是否正确
	Check_user_attribute_secret_key(pp,usk_gen_by_KGCSP,usk_gen_by_AA);


	//步骤3：执行属性加密
	//步骤3.1：选取原始消息
	element_init_GT(Message,pairing);
	element_random(Message);
	
	//步骤3.2：执行属性加密
	printf("\n执行属性加密!\n");
	ct=Encrypt(Message,pp);

	//步骤3.3：输出密文
	Output_ciphertext(ct);
	

	//步骤4：执行属性解密
	printf("\n现在执行解密....\n");
	//初始化解密结果
	dec_result=Init_rec_m();
	
	//执行解密算法
	Decrypt(ct,usk_gen_by_KGCSP,usk_gen_by_AA,dec_result);
	
	//判断解密结果是否正确
	Judge_decryption_result(Message,dec_result);

	//步骤5：执行身份追踪
	Trace(pp,usk_gen_by_KGCSP,usk_gen_by_AA);

	//释放双线性对环境
	pairing_clear(pairing);
	return 0;
}


/*
	作用：模拟方案的系统建立过程。当前函数用于产生属性权威的主密钥。
*/
struct master_secret_key * Setup_gen_msk(){
	struct master_secret_key * msk;
	element_t temp1_Zr;
	
	//创建主密钥
	msk=(struct master_secret_key *)malloc(Len_msk);
	//初始化主密钥元素
	element_init_Zr(msk->alpha,pairing);
	element_init_Zr(msk->alpha1,pairing);
	element_init_Zr(msk->alpha2,pairing);

	element_init_Zr(temp1_Zr,pairing);

	//为主密钥元素赋值
	element_random(msk->alpha);
	element_random(msk->alpha1);
	element_sub(msk->alpha2,msk->alpha,msk->alpha1);
	return msk;
}

/*
	作用：输出权威主密钥，检查主密钥的产生是否成功。
*/
void Output_master_secret_key(struct master_secret_key * msk){
	printf("\n产生的主密钥如下:\n");
	element_printf("msk->alpha=%B\n\n",msk->alpha);
	element_printf("msk->alpha1=%B\n\n",msk->alpha1);
	element_printf("msk->alpha2=%B\n\n",msk->alpha2);
}

/*
	作用：模拟方案的系统建立过程。当前函数用于产生系统公开参数。
	参数：
	msk：属性权威主密钥的指针

*/
struct public_params * Setup_gen_pp(struct master_secret_key * msk){
	int i,j;
	struct public_params * pp;
	//创建公开参数
	pp=(struct public_params *)malloc(Len_pp);

	//创建属性全集
	for(i=1;i<=Size_of_attribute_universe+1;i++){
		element_init_Zr(pp->Attribute_universe[i],pairing);
		element_set_si(pp->Attribute_universe[i],i);
	}
	
	//初始化公开参数
	element_init_G1(pp->G,pairing);
	element_init_G1(pp->G1,pairing);
	element_init_G1(pp->G2,pairing);
	element_init_G1(pp->G3,pairing);
	for(i=1;i<=Size_of_attribute_universe+1;i++)
		for(j=1;j<=Size_of_attribute_value_set;j++){/////////
			element_init_Zr(pp->S[i][j],pairing);
		}
	for(i=0;i<=Size_of_attribute_universe+1;i++)
		element_init_G1(pp->U[i],pairing);		
	//为公开参数中的各元素赋值
	element_random(pp->G);
	element_mul_zn(pp->G1,pp->G,msk->alpha);
	element_random(pp->G2);
	element_random(pp->G3);
	for(i=1;i<=Size_of_attribute_universe+1;i++)
		for(j=1;j<=Size_of_attribute_value_set;j++){
			element_set_si(pp->S[i][j],j+(i-1)*Size_of_attribute_value_set);
	}
	for(i=0;i<=Size_of_attribute_universe+1;i++)
		element_random(pp->U[i]);	
	return pp;
}

/*
	作用：输出系统公开参数，检查这些参数是否成功产生。
	参数：
	pp:公开参数指针
*/
void Output_pp(struct public_params * pp){
	int i,j;
	printf("\n系统公开参数如下:\n");
	//输出属性全集
	for(i=1;i<=Size_of_attribute_universe+1;i++){
		element_printf("Attribute_universe[%d]=%B\n",i,pp->Attribute_universe[i]);
	}
	element_printf("pp->G=%B\n\n",pp->G);
	element_printf("pp->G1=%B\n\n",pp->G1);
	element_printf("pp->G2=%B\n\n",pp->G2);
	element_printf("pp->G3=%B\n\n",pp->G3);

	for(i=1;i<=Size_of_attribute_universe+1;i++)
		for(j=1;j<=Size_of_attribute_value_set;j++){
			element_printf("pp->S[%d][%d]=%B\n",i,j,pp->S[i][j]);
		}
	for(i=0;i<=Size_of_attribute_universe+1;i++)
		element_printf("pp->U[%d]=%B\n",i,pp->U[i]);	
}


/*
	作用：模拟AA产生OK的过程
	参数：
	ak_gen_by_AA：指向AK的指针
	msk：指向权威主密钥的指针
*/
struct ok * Gen_OK(struct public_params * pp,struct master_secret_key * msk){
	struct ok * ok_gen_by_AA;
	//产生ok
	ok_gen_by_AA=(struct ok *)malloc(Len_ok);
	//对OK中的各元素进行初始化
	element_init_G1(ok_gen_by_AA->OK,pairing);
	element_mul_zn(ok_gen_by_AA->OK,pp->G2,msk->alpha1);
	return ok_gen_by_AA;
}



/*
	作用：测试OK是否正确。
	参数：
	ok_gen_by_AA：指向OK的指针
*/
void Output_ok(struct ok * ok_gen_by_AA){
	printf("\nAA产生的OK如下：\n");
	element_printf("ok_gen_by_AA->OK=%B\n",ok_gen_by_AA->OK);
}


/*
	作用：模拟AA产生AK的过程。
	参数：
	msk：指向权威主密钥的指针
	pp：指向公开参数的指针
	
*/
struct ak * Gen_AK(struct public_params * pp, struct master_secret_key * msk){
	struct ak * ak_gen_by_AA;
	
	//产生ak
	ak_gen_by_AA=(struct ak *)malloc(Len_ak);
	
	//对AK中的各元素进行初始化
	element_init_G1(ak_gen_by_AA->AK,pairing);
	element_mul_zn(ak_gen_by_AA->AK,pp->G2,msk->alpha2);
	
	return ak_gen_by_AA;
}

/*
	作用：测试AK是否正确。
	参数：
	ak_gen_by_AA：指向AK的指针
*/
void Output_ak(struct ak * ak_gen_by_AA){
	printf("\nAA产生的AK如下：\n");
	element_printf("ak_gen_by_AA->AK=%B\n",ak_gen_by_AA->AK);
}

/*
	作用：模拟KG-CSP协助AA产生部分用户解密私钥的过程

	参数：
	pp：指向公开参数的指针
	ok_gen_by_AA：指向OK的指针
	ID：用户身份
*/
struct user_attribute_secret_key_gen_by_KGCSP * KeyGen_by_KGCSP(struct public_params * pp,
struct ok * ok_gen_by_AA,element_t ID){
	int i;
	element_t temp1_G1,temp2_G1;
	element_t temp1_Zr,temp2_Zr;
	element_t r1;//随机数
	struct user_attribute_secret_key_gen_by_KGCSP * usk_gen_by_KGCSP;
	
	//创建部分的用户解密私钥（即方案描述中的SK_L,1）
	usk_gen_by_KGCSP=(struct user_attribute_secret_key_gen_by_KGCSP *)malloc(Len_usk_gen_by_KGCSP);
	
	//初始化部分的用户解密私钥中的元素
	element_init_G1(usk_gen_by_KGCSP->D10,pairing);
	element_init_G1(usk_gen_by_KGCSP->D11,pairing);
	element_init_Zr(usk_gen_by_KGCSP->D3,pairing);
	for(i=1;i<=Size_of_attribute_list+1;i++)
		element_init_Zr(usk_gen_by_KGCSP->D4[i],pairing);
	
	element_init_Zr(temp1_Zr,pairing);
	element_init_Zr(temp2_Zr,pairing);
	element_init_G1(temp1_G1,pairing);
	element_init_G1(temp2_G1,pairing);

	element_init_Zr(r1,pairing);
	element_random(r1);

	//产生usk_gen_by_KGCSP->D10
	element_from_hash(temp1_Zr,(void*)"ID",2);
	element_mul_zn(temp1_G1,pp->U[0],temp1_Zr);
	element_from_hash(temp2_Zr,(void*)"hash_of_attribute_value",23);
	for(i=1;i<=Size_of_attribute_list;i++){		
		element_mul_zn(temp2_G1,pp->U[i],temp2_Zr);
		element_add(temp1_G1,temp1_G1,temp2_G1);
	}
	element_add(temp1_G1,temp1_G1,pp->G3);
	element_mul_zn(temp1_G1,temp1_G1,r1);
	element_add(usk_gen_by_KGCSP->D10,temp1_G1,ok_gen_by_AA->OK);

	//产生usk_gen_by_KGCSP->D11
	element_mul_zn(usk_gen_by_KGCSP->D11,pp->G,r1);

	//产生usk_gen_by_KGCSP->D3
	element_from_hash(usk_gen_by_KGCSP->D3,(void*)"ID",2);
	
	//产生usk_gen_by_KGCSP->D4
	for(i=1;i<=Size_of_attribute_list+1;++i){
		element_set(usk_gen_by_KGCSP->D4[i],pp->S[i][1]);////////
    }

	return usk_gen_by_KGCSP;
}




/*
	作用：输出KG-CSP产生的部分用户私钥，检查这部分私钥的产生是否成功。
	参数：
	usk_gen_by_KGCSP：指向KG-CSP协助权威产生的部分用户解密私钥的指针
*/
void Output_master_secret_key_by_KGCSP(struct user_attribute_secret_key_gen_by_KGCSP * usk_gen_by_KGCSP){
	int i;
	printf("\nKG-CSP产生的部分用户私密如下:\n");
	element_printf("usk_gen_by_KGCSP->D10=%B\n",usk_gen_by_KGCSP->D10);
	element_printf("usk_gen_by_KGCSP->D11=%B\n",usk_gen_by_KGCSP->D11);
	element_printf("usk_gen_by_KGCSP->D3=%B\n",usk_gen_by_KGCSP->D3);
	for(i=1;i<=Size_of_attribute_list+1;++i){
		element_printf("usk_gen_by_KGCSP->D4[%d]=%B\n",i,usk_gen_by_KGCSP->D4[i]);
    }
}

/*
	作用：模拟AA产生部分用户解密私钥的过程。
	注意：在本函数中，AA为用户产生属性列表的L0。注意：在本函数中，KG-CSP为用户产生属性列表的L1..Ln。为了简单起见，假设
L0取集合pp->S[0]中的唯一属性值（即pp->S[0][1]）。
	参数：
	pp：指向系统公开参数的指针
	ak_gen_by_AA：指向AK的指针
*/
struct user_attribute_secret_key_gen_by_AA * KeyGen_by_AA(struct public_params * pp,struct ak * ak_gen_by_AA){
	element_t r2;//随机数
	element_t temp1_Zr;
	element_t temp1_G1;

	struct user_attribute_secret_key_gen_by_AA * usk_gen_by_AA;
	
	//创建部分的用户解密私钥（即方案描述中的SK_L,1）
	usk_gen_by_AA=(struct user_attribute_secret_key_gen_by_AA *)malloc(Len_usk_gen_by_AA);
	//初始化部分的用户解密私钥
	element_init_G1(usk_gen_by_AA->D20,pairing);
	element_init_G1(usk_gen_by_AA->D21,pairing);

	//初始化中间变量
	element_init_Zr(temp1_Zr,pairing);
	element_init_G1(temp1_G1,pairing);

	//初始化随机数
	element_init_Zr(r2,pairing);

	//选取随机数
	element_random(r2);

	//产生usk_gen_by_AA->D20
	element_from_hash(temp1_Zr,(void*)"hash_of_attribute_value",23);
	element_mul_zn(temp1_G1,pp->U[Size_of_attribute_universe+1],temp1_Zr);
	element_mul_zn(temp1_G1,temp1_G1,r2);
	element_add(usk_gen_by_AA->D20,ak_gen_by_AA->AK,temp1_G1);

	//产生usk_gen_by_AA->D21
	element_mul_zn(usk_gen_by_AA->D21,pp->G,r2);
	
	return usk_gen_by_AA;
}


/*
	作用：输出AA产生的剩余用户解密私钥，检查这部分私钥的产生是否成功。
	参数：
	usk_gen_by_AA：指向AA自行产生的剩余用户解密私钥
*/
void Output_master_secret_key_by_AA(struct user_attribute_secret_key_gen_by_AA * usk_gen_by_AA){
	printf("\nAA产生的部分用户私密如下:\n");
	element_printf("usk_gen_by_AA->D20=%B\n",usk_gen_by_AA->D20);
	element_printf("usk_gen_by_AA->D21=%B\n",usk_gen_by_AA->D21);
}

/*
	作用：检查该私钥是否满足验证等式。
	参数：
	pp：系统公开参数指针
	usk_gen_by_KGCSP：用户私钥指针
	usk_gen_by_AA：用户私钥指针
	
*/
int Check_user_attribute_secret_key(struct public_params * pp,
struct user_attribute_secret_key_gen_by_KGCSP * usk_gen_by_KGCSP,
struct user_attribute_secret_key_gen_by_AA * usk_gen_by_AA){
	int i;
	element_t left_of_equation,right_of_equation;
	element_t temp1_GT,temp2_GT,temp3_GT;
	element_t temp1_G1,temp2_G1,temp3_G1;
	element_t temp1_Zr;

	element_init_GT(left_of_equation,pairing);
	element_init_GT(right_of_equation,pairing);
	element_init_GT(temp1_GT,pairing);
	element_init_GT(temp2_GT,pairing);
	element_init_GT(temp3_GT,pairing);
	element_init_G1(temp1_G1,pairing);
	element_init_G1(temp2_G1,pairing);
	element_init_G1(temp3_G1,pairing);
	element_init_Zr(temp1_Zr,pairing);
	
	//计算验证等式左端
	element_add(temp1_G1,usk_gen_by_KGCSP->D10,usk_gen_by_AA->D20);
	pairing_apply(left_of_equation,temp1_G1,pp->G,pairing);

	//计算验证等式右端
	pairing_apply(temp1_GT,pp->G2,pp->G1,pairing);
	element_mul_zn(temp1_G1,pp->U[0],usk_gen_by_KGCSP->D3);
	element_from_hash(temp1_Zr,(void*)"hash_of_attribute_value",23);
	for(i=1;i<=Size_of_attribute_list;i++){
		element_mul_zn(temp2_G1,pp->U[i],temp1_Zr);
		element_add(temp1_G1,temp1_G1,temp2_G1);
	}
	element_add(temp1_G1,temp1_G1,pp->G3);
	pairing_apply(temp2_GT,temp1_G1,usk_gen_by_KGCSP->D11,pairing);
	element_mul_zn(temp3_G1,pp->U[Size_of_attribute_list+1],temp1_Zr);
	pairing_apply(temp3_GT,temp3_G1,usk_gen_by_AA->D21,pairing);
	element_mul(right_of_equation,temp1_GT,temp2_GT);
	element_mul(right_of_equation,right_of_equation,temp3_GT);


	if(!element_cmp(left_of_equation,right_of_equation)){
		printf("\n用户解密私钥验证成功!\n");
		return 1;
	}	
	else{
		printf("\n用户解密私钥验证失败!\n");
		return 0;
	}
}


/*
	作用：产生属性加密密文
	参数：
	Message：待加密的消息
	pp：公开参数指针
*/
struct ciphertext * Encrypt(element_t Message, struct public_params * pp){
	int i;
	element_t s;//随机数

	element_t temp1_GT;
	element_t temp1_G1,temp2_G1,temp3_G1;
	element_t temp1_Zr;

	struct ciphertext * ct;

	//创建密文
	ct=(struct ciphertext *)malloc(Len_ct);
	//初始化访问控制策略
	for(i=1;i<=Size_of_attribute_universe+1;i++)
			element_init_Zr(ct->W[i],pairing);
	
	//初始化密文元素
	element_init_GT(ct->C0,pairing);
	element_init_G1(ct->C1,pairing);
	element_init_G1(ct->C2,pairing);
	element_init_G1(ct->C3,pairing);
	element_init_G1(ct->E,pairing);
	
	//初始化中间变量
	element_init_GT(temp1_GT,pairing);
	element_init_G1(temp1_G1,pairing);
	element_init_G1(temp2_G1,pairing);
	element_init_G1(temp3_G1,pairing);
	element_init_Zr(temp1_Zr,pairing);

	//产生访问控制策略
	for(i=1;i<=Size_of_attribute_universe+1;i++)
			element_set_si(ct->W[i],1+(i-1)*Size_of_attribute_value_set);////////////////
	
	//选取随机数
	element_init_Zr(s,pairing);
	element_random(s);
	
	//产生密文元素ct->C0
	pairing_apply(temp1_GT,pp->G1,pp->G2,pairing);
	element_pow_zn(temp1_GT,temp1_GT,s);
	element_mul(ct->C0,Message,temp1_GT);

	//产生密文元素ct->c1
	element_mul_zn(ct->C1,pp->G,s);
	
	//产生密文元素ct->c2
	//element_from_hash(temp1_Zr,"hash_of_access_policy",21);
	element_from_hash(temp1_Zr,(void*)"hash_of_attribute_value",23);

	element_set(temp1_G1,pp->G3);
	for(i=1;i<=Size_of_attribute_universe;i++){
		element_mul_zn(temp2_G1,pp->U[i],temp1_Zr);
		element_add(temp1_G1,temp1_G1,temp2_G1);
	}
	element_mul_zn(ct->C2,temp1_G1,s);

	//产生密文元素ct->c3
	element_mul_zn(temp3_G1,pp->U[Size_of_attribute_universe+1],temp1_Zr);
	element_mul_zn(ct->C3,temp3_G1,s);

	//产生密文元素ct->E
	element_mul_zn(ct->E,pp->U[0],s);

	//返回密文指针
	return ct;
}



/*
	作用：输出密文，检查密文是否正确。
	参数：
	ct：密文指针
*/
void Output_ciphertext(struct ciphertext * ct){
	int i;
	printf("所产生的密文如下\n");
	
	//输出访问控制策略
	printf("访问控制策略如下\n");
	for(i=1;i<=Size_of_attribute_universe+1;i++)
			element_printf("ct->W[%d]=%B\n",i,ct->W[i]);

	//输出密文元素
	printf("密文元素如下\n");
	element_printf("ct->C0=%B\n",ct->C0);
	element_printf("ct->C1=%B\n",ct->C1);
	element_printf("ct->C2=%B\n",ct->C2);
	element_printf("ct->C3=%B\n",ct->C3);
	element_printf("ct->E=%B\n",ct->E);
}

/*
	作用：检查用户属性集是否满足密文中的访问控制策略，即对于i=1,...,n，是否满足Li属于Wi。 
	最终，函数返回1表示满足，返回0表示不满足。
	参数：
	ct：密文指针
	usk_gen_by_KGCSP：用户解密私钥指针
	dec_result：指向解密恢复得到的消息的指针
*/
int Check(struct ciphertext * ct,struct user_attribute_secret_key_gen_by_KGCSP * usk_gen_by_KGCSP) {
	int i;
	for(i=1;i<=Size_of_attribute_universe+1;i++){
			if(!element_cmp(usk_gen_by_KGCSP->D4[i],ct->W[i])) 
				printf("用户的第%d个属性值与访问控制子策略ct->W[%d]匹配.\n",i,i);
			else{
				printf("用户的第%d个属性值与访问控制子策略ct->W[%d]不匹配.\n",i,i);
				return 0;
			}
	}
	return 1;//满足
}

/*
	作用：对解密结果进行初始化。
*/
struct recovered_message * Init_rec_m(){	
	struct recovered_message * rm;
	//创建主密钥
	rm=(struct recovered_message *)malloc(Len_rm);
	//初始化主密钥
	element_init_GT(rm->recovered_M,pairing);
	//选取主密钥
	return rm;
}

/*
	作用：执行属性解密，返回指向被恢复消息的指针。
	参数：
	ct：密文指针
	usk_gen_by_KGCSP：用户解密私钥指针
	usk_gen_by_AA：用户私钥指针
	dec_result：指向解密恢复得到的消息的指针
*/
void Decrypt(struct ciphertext * ct,
struct user_attribute_secret_key_gen_by_KGCSP * usk_gen_by_KGCSP,
struct user_attribute_secret_key_gen_by_AA * usk_gen_by_AA,
struct recovered_message * dec_result){
	
	element_t temp1_GT,temp2_GT,temp3_GT,temp4_GT;
	element_t temp1_G1;
	element_t C2_prime;
	element_t numerator;//解密等式分子的运算结果
	element_t denominator;//解密等式分母的运算结果
	
	//若用户属性集不满足密文中的访问控制策略

	if(!Check(ct,usk_gen_by_KGCSP)){
		printf("用户属性集不满足密文中的访问控制策略\n");; 
		return;
	}
	//初始化临时变量
	element_init_GT(numerator,pairing);
	element_init_GT(denominator,pairing);
	element_init_G1(C2_prime,pairing);
	element_init_G1(temp1_G1,pairing);
	element_init_GT(temp1_GT,pairing);
	element_init_GT(temp2_GT,pairing);
	element_init_GT(temp3_GT,pairing);
	element_init_GT(temp4_GT,pairing);

	element_mul_zn(temp1_G1,ct->E,usk_gen_by_KGCSP->D3);
	element_add(C2_prime,ct->C2,temp1_G1);


	//解密等式的分子部分
	pairing_apply(temp1_GT,usk_gen_by_KGCSP->D11,C2_prime,pairing);
	pairing_apply(temp2_GT,usk_gen_by_AA->D21,ct->C3,pairing);
	element_mul(numerator,ct->C0,temp1_GT);
	element_mul(numerator,numerator,temp2_GT);
	
	//解密等式的分母部分
	pairing_apply(temp3_GT,usk_gen_by_KGCSP->D10,ct->C1,pairing);
	pairing_apply(temp4_GT,usk_gen_by_AA->D20,ct->C1,pairing);
	element_mul(denominator,temp3_GT,temp4_GT);

	//恢复明文
	element_div(dec_result->recovered_M,numerator,denominator);

}

/*
	作用：评估解密结果。若原始消息与解密得到的消息相同，则判定解密成功。否则，判定解密失败。
	参数：
	Message：原始消息
	result：Decrypt函数返回的指针，它指向解密得到的消息
*/
void Judge_decryption_result(element_t Message,struct recovered_message * dec_result){
	element_printf("原始消息=%B\n",Message);
	element_printf("解密恢复的消息=%B\n",dec_result->recovered_M);
	if(!element_cmp(Message,dec_result->recovered_M))
		printf("\n解密成功!\n");
	else
		printf("\n解密失败!\n");
}



/*
	作用：对用户追踪过程进行模拟。
	参数：
	pp：指向系统公开参数
	usk：指向被泄露的用户私钥
*/
void Trace(struct public_params * pp,struct user_attribute_secret_key_gen_by_KGCSP * usk_gen_by_KGCSP,
struct user_attribute_secret_key_gen_by_AA * usk_gen_by_AA){
	int result;
	element_t temp1_Zr;
	element_init_Zr(temp1_Zr,pairing);
	//步骤1：检查被泄露的用户私钥是否有效
	result=Check_user_attribute_secret_key(pp,usk_gen_by_KGCSP,usk_gen_by_AA);
	//若有效，则执行身份追踪
	if(result){
		element_from_hash(temp1_Zr,(void*)"ID",2);
		if(!element_cmp(temp1_Zr,usk_gen_by_KGCSP->D3))
			element_printf("被追踪的用户身份为: %B\n",usk_gen_by_KGCSP->D3);
	}	
	else
		printf("身份追踪失败!\n");
}
