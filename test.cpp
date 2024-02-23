/*
	本程序对Li-Ren-Kim方案的简化版本进行仿真实现。
	 (1)在公钥中定义数组Attribute_universe，存储属性全集，其中的每个属性用具体数字替代。
	用1表示属性A1，用2表示属性A2，以此类推。 
	(2)集合Si的产生方式如下：
	S1={1,2,...,Size_of_attribute_value_set}。
	S2={Size_of_attribute_value_set+1,Size_of_attribute_value_set+2,...,2*Size_of_attribute_value_set}。
	S3={2*Size_of_attribute_value_set+1,2*Size_of_attribute_value_set+2,...,3*Size_of_attribute_value_set}。
	...

*/

#include <pbc/pbc.h>
#include <pbc/pbc_test.h>



#define Size_of_attribute_universe 3//定义属性全集的规模
#define Size_of_attribute_list 3//定义用户属性列表的长度
#define Size_of_attribute_value_set 3//定义每个属性可能取值的个数
#define Size_of_embedded_attribute_list 3//定义嵌入在密文中的属性列表的长度

#define Len_msk sizeof(struct master_secret_key) //结构体master_secret_key的长度
#define Len_pp sizeof(struct public_params) //结构体public_params的长度
#define Len_usk sizeof(struct user_attribute_secret_key) //结构体user_attribute_secret_key的长度
#define Len_ct sizeof(struct ciphertext) //结构体ciphertext的长度
#define Len_rm sizeof(struct recovered_message) //结构体recovered_message的长度

pairing_t pairing;

/*
	该结构体用于保存属性权威的主密钥
*/
struct master_secret_key{
		element_t alpha;
};

/*
	该结构体用于保存属性权威发布的系统公开参数
*/
struct public_params{
		element_t G,G1,G2,G3;//群G的生成元
		element_t Attribute_universe[Size_of_attribute_universe+1];//属性全集
		element_t S[Size_of_attribute_universe+1][Size_of_attribute_value_set+1];//属性值集合
		element_t U[Size_of_attribute_universe+1];//公开元素集合
};


/*
	该结构体用于保存用户的属性解密私钥
*/
struct user_attribute_secret_key{
		element_t D0,D1,D2;////用户属性解密私钥元素
		element_t D3[Size_of_attribute_list+1];//用户属性列表
};


/*
	该结构体用于保存密文
*/
struct ciphertext{
	element_t W[Size_of_embedded_attribute_list+1][Size_of_attribute_value_set+1];//访问控制策略列表
	element_t C0,C1,C2,E;
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
	作用：为用户产生属性列表L，即用户解密私钥中的数组D3。
	思想：为了简单起见，采取以下模拟方式：
	D3中的第1个属性值取集合pp->S[1]中的第1个属性值（即pp->S[1][1]）。
    D3中的第2个属性值取集合pp->S[2]中的第2个属性值（即pp->S[2][2]）。
	D3中的第3个属性值取集合pp->S[3]中的第3个属性值（即pp->S[3][3]）。
	以此类推...
	参数：
	length决定产生的比特串长度。 
*/
void set_user_attribute_list(int length,struct user_attribute_secret_key * usk,struct public_params * pp);

/*
	作用：产生用户属性列表以及属性解密私钥
	思想：为了简单起见，采用以下模拟产生私钥元素msk->D3[i]，
	即假设用户的第i个属性值L恰好等于属性值集合中的第i个属性值（pp->S[i][i]）。
	注意：msk->D3[i]是群Zr上的元素，PBC库并未提供为群Zr上的元素计算散列值的函数。为了简单期间，在计算用户私钥
元素msk->D0时，使用了一个固定的散列值。
	
*/
struct user_attribute_secret_key * KeyGen(struct public_params * pp,struct master_secret_key * msk,element_t ID);

/*
	作用：输出用户解密私钥，检查该私钥的产生是否正确。
	参数：
	usk：用户解密私钥指针
*/
void Output_user_attribute_secret_key(struct user_attribute_secret_key * usk);

/*
	作用：检查该私钥是否满足验证等式。
	参数：
	usk：用户解密私钥指针
*/
int Check_user_attribute_secret_key(struct public_params * pp,struct user_attribute_secret_key * usk);


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
	usk：用户解密私钥指针
	dec_result：指向解密恢复得到的消息的指针
*/
int Check(struct ciphertext * ct,struct user_attribute_secret_key * usk);


/*
	作用：对解密结果进行初始化。
*/
struct recovered_message * Init_rec_m();

/*
	作用：执行属性解密，返回指向被恢复消息的指针。
	参数：
	ct：密文指针
	usk：用户解密私钥指针
	dec_result：指向解密恢复得到的消息的指针
*/
void Decrypt(struct ciphertext * ct,struct user_attribute_secret_key * usk,struct recovered_message * dec_result);

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
void Trace(struct public_params * pp,struct user_attribute_secret_key * usk);


//测试A类型的对环境
int main(int argc, char ** argv){
	struct master_secret_key * msk;
	struct public_params * pp;
	struct user_attribute_secret_key * usk;
	struct ciphertext * ct;
	struct recovered_message * dec_result;

	element_t ID;//保存用户身份
	element_t Message;//保存原始消息
	
	
	printf("Testing in the bilinear pairing environment of type A.\n");
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

	//步骤1.3：产生用户属性解密私钥
	//设置用户身份信息
	element_init_Zr(ID,pairing);
	element_random(ID);
	//创建用户解密私钥
	usk=KeyGen(pp,msk,ID);

	//测试：检查用户解密私钥是否正确
	//Output_user_attribute_secret_key(usk);
	//检查用户解密私钥是否正确
	Check_user_attribute_secret_key(pp,usk);
	
	//步骤2：选取原始消息
	element_init_GT(Message,pairing);
	element_random(Message);

	//步骤3：执行属性加密
	//步骤3.1：执行属性加密
	printf("\nPerforming the encryption!\n");
	ct=Encrypt(Message,pp);

	//步骤3.2：输出密文
	//Output_ciphertext(ct);

	//步骤4：执行属性解密
	printf("\nPerforming the decryption....\n");
	//初始化解密结果
	dec_result=Init_rec_m();
	
	//执行解密算法
	Decrypt(ct,usk,dec_result);
	
	//判断解密结果是否正确
	Judge_decryption_result(Message,dec_result);

	//步骤5：执行身份追踪
	Trace(pp,usk);

	//释放双线性对环境
	pairing_clear(pairing);
	return 0;
}


/*
	作用：模拟方案的系统建立过程。当前函数用于产生属性权威的主密钥。
*/
struct master_secret_key * Setup_gen_msk(){
	struct master_secret_key * msk;
	
	//创建主密钥
	msk=(struct master_secret_key *)malloc(Len_msk);
	//初始化主密钥
	element_init_Zr(msk->alpha,pairing);

	//为主密钥元素赋值
	element_random(msk->alpha);
	return msk;
}

/*
	作用：输出权威主密钥，检查主密钥的产生是否成功。
*/
void Output_master_secret_key(struct master_secret_key * msk){
	printf("\nThe master key is as follows:\n");
	element_printf("msk->alpha=%B\n\n",msk->alpha);
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
	for(i=1;i<=Size_of_attribute_universe;i++){
		element_init_Zr(pp->Attribute_universe[i],pairing);
		element_set_si(pp->Attribute_universe[i],i);
	}
	//初始化公开参数
	element_init_G1(pp->G,pairing);
	element_init_G1(pp->G1,pairing);
	element_init_G1(pp->G2,pairing);
	element_init_G1(pp->G3,pairing);
	for(i=1;i<=Size_of_attribute_universe;i++)
		for(j=1;j<=Size_of_attribute_value_set;j++){
			element_init_Zr(pp->S[i][j],pairing);
		}
	for(i=0;i<=Size_of_attribute_universe;i++)
		element_init_G1(pp->U[i],pairing);		
	//为公开参数中的各元素赋值
	element_random(pp->G);
	element_mul_zn(pp->G1,pp->G,msk->alpha);
	element_random(pp->G2);
	element_random(pp->G3);
	for(i=1;i<=Size_of_attribute_universe;i++)
		for(j=1;j<=Size_of_attribute_value_set;j++){
			element_set_si(pp->S[i][j],j+(i-1)*Size_of_attribute_value_set);
	}
	for(i=0;i<=Size_of_attribute_universe;i++)
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
	printf("\nThe system public parameters are as follows:\n");
	//输出属性全集
	for(i=1;i<=Size_of_attribute_universe;i++){
		element_printf("Attribute_universe[%d]=%B\n",i,pp->Attribute_universe[i]);
	}
	element_printf("pp->G=%B\n\n",pp->G);
	element_printf("pp->G1=%B\n\n",pp->G1);
	element_printf("pp->G2=%B\n\n",pp->G2);
	element_printf("pp->G3=%B\n\n",pp->G3);

	for(i=1;i<=Size_of_attribute_universe;i++)
		for(j=1;j<=Size_of_attribute_value_set;j++){
			element_printf("pp->S[%d][%d]=%B\n",i,j,pp->S[i][j]);
		}
	for(i=0;i<=Size_of_attribute_universe;i++)
		element_printf("pp->U[%d]=%B\n",i,pp->U[i]);	
}

/*
	作用：为用户产生属性列表L，即用户解密私钥中的数组D3。
	思想：为了简单起见，采取以下模拟方式：
	D3中的第1个属性值取集合pp->S[1]中的第1个属性值（即pp->S[1][1]）。
    D3中的第2个属性值取集合pp->S[2]中的第2个属性值（即pp->S[2][2]）。
	D3中的第3个属性值取集合pp->S[3]中的第3个属性值（即pp->S[3][3]）。
	以此类推...
	参数：
	length决定产生的比特串长度。 
*/
void set_user_attribute_list(int length,struct user_attribute_secret_key * usk,struct public_params * pp){
	int i;//控制变量
	for(i=1;i<=length;++i){
		element_set(usk->D3[i],pp->S[i][i]);
		//element_printf("usk->D3[%d]=%B\n\n",i,usk->D3[i]);
    }
}



/*
	作用：产生用户属性列表以及属性解密私钥
	思想：为了简单起见，采用以下模拟产生私钥元素msk->D3[i]，
	即假设用户的第i个属性值L恰好等于属性值集合中的第i个属性值（pp->S[i][i]）。
	注意：msk->D3[i]是群Zr上的元素，PBC库并未提供为群Zr上的元素计算散列值的函数。为了简单期间，在计算用户私钥
元素msk->D0时，使用了一个固定的散列值。
	
*/
struct user_attribute_secret_key * KeyGen(struct public_params * pp,struct master_secret_key * msk,element_t ID){
	int i;
	element_t r;//随机数
	element_t temp1_G1,temp2_G1,temp3_G1;
	element_t temp1_Zr;

	struct user_attribute_secret_key * usk;
	
	//创建用户属性解密私钥
	usk=(struct user_attribute_secret_key *)malloc(Len_usk);

	//对用户属性解密私钥进行初始化
	element_init_G1(usk->D0,pairing);
	element_init_G1(usk->D1,pairing);
	element_init_Zr(usk->D2,pairing);
	for(i=1;i<=Size_of_attribute_list;i++)
		element_init_Zr(usk->D3[i],pairing);
	//初始化随机数
	element_init_Zr(r,pairing);

	//初始化中间变量
	element_init_G1(temp1_G1,pairing);
	element_init_G1(temp2_G1,pairing);
	element_init_G1(temp3_G1,pairing);

	element_init_Zr(temp1_Zr,pairing);
	//选取随机数
	element_random(r);
	//产生用户私钥元素usk->D1
	element_mul_zn(usk->D1,pp->G,r);
	//产生用户私钥元素usk->D2
	element_set(usk->D2,ID);
	//产生用户属性列表usk->D3
    set_user_attribute_list(Size_of_attribute_list,usk,pp);//产生用户的属性列表

	//产生用户私钥元素usk->D0
	element_mul_zn(temp1_G1,pp->U[0],ID);
	element_from_hash(temp1_Zr,(void*)"hash_of_attribute_value",23);
	for(i=1;i<=Size_of_attribute_list;i++){		
		element_mul_zn(temp2_G1,pp->U[i],temp1_Zr);
		element_add(temp1_G1,temp1_G1,temp2_G1);
	}
	element_add(temp1_G1,temp1_G1,pp->G3);
	element_mul_zn(temp1_G1,temp1_G1,r);
	element_mul_zn(temp3_G1,pp->G2,msk->alpha);	
	element_add(usk->D0,temp1_G1,temp3_G1);	

	return usk;
}

/*
	作用：输出用户解密私钥，检查该私钥的产生是否正确。
	参数：
	usk：用户解密私钥指针
*/
void Output_user_attribute_secret_key(struct user_attribute_secret_key * usk){
	int i;
	//输出用户解密私钥
	printf("The user's secret key is as follows：\n");
	element_printf("usk->D0=%B\n",usk->D0);
	element_printf("usk->D1=%B\n",usk->D1);
	element_printf("usk->D2=%B\n",usk->D2);
	for(i=1;i<=Size_of_attribute_list;++i)
		element_printf("usk->D3[%d]=%B\n",i,usk->D3[i]);
}

/*
	作用：检查该私钥是否满足验证等式。
	参数：
	usk：用户解密私钥指针
*/
int Check_user_attribute_secret_key(struct public_params * pp,struct user_attribute_secret_key * usk){
	int i;
	element_t left_of_equation,right_of_equation;
	element_t temp1_GT,temp2_GT;
	element_t temp1_G1,temp2_G1;
	element_t temp1_Zr;

	element_init_GT(left_of_equation,pairing);
	element_init_GT(right_of_equation,pairing);
	element_init_GT(temp1_GT,pairing);
	element_init_GT(temp2_GT,pairing);
	element_init_G1(temp1_G1,pairing);
	element_init_G1(temp2_G1,pairing);
	element_init_Zr(temp1_Zr,pairing);
	
	//计算验证等式左端
	pairing_apply(left_of_equation,usk->D0,pp->G,pairing);

	//计算验证等式右端
	pairing_apply(temp1_GT,pp->G2,pp->G1,pairing);
	element_mul_zn(temp1_G1,pp->U[0],usk->D2);
	for(i=1;i<=Size_of_attribute_list;i++){
		element_from_hash(temp1_Zr,(void*)"hash_of_attribute_value",23);
		element_mul_zn(temp2_G1,pp->U[i],temp1_Zr);
		element_add(temp1_G1,temp1_G1,temp2_G1);
	}
	element_add(temp1_G1,temp1_G1,pp->G3);
	pairing_apply(temp2_GT,temp1_G1,usk->D1,pairing);
	element_mul(right_of_equation,temp1_GT,temp2_GT);

	if(!element_cmp(left_of_equation,right_of_equation)){
		printf("\nThe verification of user's secret key is successful!\n");
		return 1;
	}
		
	else{
		printf("\nThe verification of user's secret key is failure!\n");
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
	int i,j;
	element_t s;//随机数

	element_t temp1_GT;
	element_t temp1_G1,temp2_G1;
	element_t temp1_Zr;

	struct ciphertext * ct;

	//创建密文
	ct=(struct ciphertext *)malloc(Len_ct);
	//初始化访问控制策略
	for(i=1;i<=Size_of_attribute_universe;i++)
		for(j=1;j<=Size_of_attribute_value_set;j++){
			element_init_Zr(ct->W[i][j],pairing);
	}
	//初始化密文元素
	element_init_GT(ct->C0,pairing);
	element_init_G1(ct->C1,pairing);
	element_init_G1(ct->C2,pairing);
	element_init_G1(ct->E,pairing);
	
	//初始化中间变量
	element_init_GT(temp1_GT,pairing);
	element_init_G1(temp1_G1,pairing);
	element_init_G1(temp2_G1,pairing);
	element_init_Zr(temp1_Zr,pairing);

	//产生访问控制策略
	for(i=1;i<=Size_of_attribute_universe;i++)
		for(j=1;j<=Size_of_attribute_value_set;j++){
			element_set_si(ct->W[i][j],j+(i-1)*Size_of_attribute_value_set);
	}

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
	int i,j;
	printf("The ciphertext is as follows:\n");
	
	//输出访问控制策略
	printf("The access control policy is as follows:\n");
	for(i=1;i<=Size_of_attribute_universe;i++)
		for(j=1;j<=Size_of_attribute_value_set;j++){
			element_printf("ct->W[%d][%d]=%B\n",i,j,ct->W[i][j]);
	}

	//输出密文元素
	printf("The elements of the ciphertext are as follows:\n");
	element_printf("ct->C0=%B\n",ct->C0);
	element_printf("ct->C1=%B\n",ct->C1);
	element_printf("ct->C2=%B\n",ct->C2);
	element_printf("ct->E=%B\n",ct->E);
}

/*
	作用：检查用户属性集是否满足密文中的访问控制策略，即对于i=1,...,n，是否满足Li属于Wi。 
	最终，函数返回1表示满足，返回0表示不满足。
	参数：
	ct：密文指针
	usk：用户解密私钥指针
	dec_result：指向解密恢复得到的消息的指针
*/
int Check(struct ciphertext * ct,struct user_attribute_secret_key * usk) {
	int i,k;
	for(i=1;i<=Size_of_attribute_universe;i++){
		k=1;
		while(k<=Size_of_embedded_attribute_list){
			if(!element_cmp(usk->D3[i],ct->W[i][k])) {
				printf("The %d-th attribute value of the user matches the %d-th attribute value of the access control sub-policy ct->W[%d].\n",i,i,k);
				break;
			}		
			k++;
		}
		if(k>Size_of_embedded_attribute_list){
			return 0;//不满足
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
	usk：用户解密私钥指针
	dec_result：指向解密恢复得到的消息的指针
*/
void Decrypt(struct ciphertext * ct,struct user_attribute_secret_key * usk,struct recovered_message * dec_result){
	
	element_t temp1_GT;
	element_t temp1_G1;
	element_t C2_prime;
	element_t numerator;//解密等式分子的运算结果
	element_t denominator;//解密等式分母的运算结果
	
	//若用户属性集不满足密文中的访问控制策略
	if(!Check(ct,usk)){
		printf("The user's attribute set does not satisfy the access control policy in the ciphertext.\n");; 
		return;
	}
	
	//初始化临时变量
	element_init_GT(numerator,pairing);
	element_init_GT(denominator,pairing);
	element_init_G1(C2_prime,pairing);
	element_init_G1(temp1_G1,pairing);
	element_init_GT(temp1_GT,pairing);

	element_mul_zn(temp1_G1,ct->E,usk->D2);
	element_add(C2_prime,ct->C2,temp1_G1);


	//解密等式的分子部分
	pairing_apply(temp1_GT,usk->D1,C2_prime,pairing);
	element_mul(numerator,ct->C0,temp1_GT);
	//解密等式的分母部分
	pairing_apply(denominator,usk->D0,ct->C1,pairing);
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
	element_printf("The original message=%B\n",Message);
	element_printf("The recovered message=%B\n",dec_result->recovered_M);
	if(!element_cmp(Message,dec_result->recovered_M))
		printf("\nDecryption Success!\n");
	else
		printf("\nDecryption Failure!\n");
}

/*
	作用：对用户追踪过程进行模拟。
	参数：
	pp：指向系统公开参数
	usk：指向被泄露的用户私钥
*/
void Trace(struct public_params * pp,struct user_attribute_secret_key * usk){
	int result;
	result=Check_user_attribute_secret_key(pp,usk);
	if(result)
		element_printf("The identity of the traced user is %B\n",usk->D2);
	else
		printf("Identity tracing failure!\n");
}
