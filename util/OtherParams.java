package util;

import java.security.SecureRandom;

import Common.Commitments.MultiTrapdoorCommitment;
import Common.Commitments.MultiTrapdoorMasterPublicKey;
import paillierp.Paillier;
import paillierp.key.PaillPrivateKeyGen;
import paillierp.key.PaillierPublicKey;
import paillierp.key.PaillierPrivateKey;
import ACNS.ZeroKnowledgeProofs.PublicParameters;

public class OtherParams {
	
	

	//secure random
	public static final SecureRandom SecureRnd;
	
	
	//paillier
	public static final PaillierPrivateKey PaillPrivKey;
	public static final PaillierPublicKey PaillPubKey;
	
	public static final Paillier PaillEnc;	
	public static final Paillier PaillDec;
	
	public static final PublicParameters ZKParams;
	
	
	//commitment
	public static final MultiTrapdoorMasterPublicKey MPK;

	static {

		//secure random
		SecureRnd = new SecureRandom();

		
		//paillier
		PaillPrivKey = PaillPrivateKeyGen.PaillierPrivateKeyGen(1024 , SecureRnd.nextLong());
		PaillPubKey = PaillPrivKey.getPublicKey();
		
		PaillEnc = new Paillier(PaillPrivKey.getPublicKey());
		PaillDec = new Paillier(PaillPrivKey);
		
		
		//zk
		ZKParams = OtherUtil.generatePublicParams(BitcoinParams.CURVE, 256, 512, SecureRnd, PaillPubKey.getPublicKey());

		
		//commitment
		MPK = MultiTrapdoorCommitment.generateNMMasterPublicKey();
		
	}

}
