import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import org.bouncycastle.math.ec.ECPoint;
import common.Commitments.Commitment;
import common.Commitments.MultiTrapdoorCommitment;
import common.Commitments.MultiTrapdoorMasterPublicKey;
import common.Commitments.Open;
import paillierp.Paillier;
import paillierp.key.PaillPrivateKeyGen;
import paillierp.key.PaillierPrivateKey;
import util.BitcoinParams;
import util.ECDSASignature;
import util.OtherParams;
import util.RandomUtil;
import util.User;
import util.OtherUtil;
import ACNS.ZeroKnowledgeProofs.PublicParameters;
import ACNS.ZeroKnowledgeProofs.Zkp_i1;
import ACNS.ZeroKnowledgeProofs.Zkp_i2;

public class ThresholdECDSA {
	
	
	
	public static List<User> keyGenerate(int userCnt) {
		
		User temUser;
		List<User> userList = new ArrayList<User>();
		
		BigInteger xShare, xShareRnd, encXShare;
		ECPoint yShare;
		
		
		for(int i=0 ; i<userCnt ; i++) {
			temUser = new User();
			
			xShare = RandomUtil.randomFromZn(BitcoinParams.q, OtherParams.SecureRnd);
			yShare = BitcoinParams.G.multiply(xShare);
			
			xShareRnd = RandomUtil.randomFromZnStar(OtherParams.PaillPubKey.getN(), OtherParams.SecureRnd);
			encXShare = OtherParams.PaillEnc.encrypt(xShare, xShareRnd);
			
			temUser.setxShare(xShare);
			temUser.setyShare(yShare);
			temUser.setxShareRnd(xShareRnd);
			temUser.setEncXShare(encXShare);
			
			userList.add(temUser);
			
			System.out.println("\n--Info: User "+i+" generate Private Key Share"+
					"\n PrivateKey Share: "+xShare);
		}
		
		//BROADCAST yShare, encXShare		
		return userList;
	}
	
	
	
	
	public static ECPoint calculatePubKey(List<User> userList) {
		
		ECPoint pubKey = userList.get(0).getyShare();
		
		for(int i = 1; i < userList.size() ; i++) {
			pubKey = pubKey.add(userList.get(i).getyShare());
		}
		
		System.out.println("\n--Info: Calculate the Public Key"+
				"\n PublicKey: "+pubKey.toString());
		
		//BROADCAST pubKey
		return pubKey;
	}
	
	
	
	
	public static BigInteger calculateEncPrivateKey(List<User> userList) {
		
		BigInteger encX = userList.get(0).getEncXShare();
		
		for(int i = 1; i < userList.size() ; i++) {
			encX = OtherParams.PaillEnc.add(encX, userList.get(i).getEncXShare());
		}
		
		System.out.println("\n--Info: Calculate the Encrypted Private Key"+
				"\n EncPrivateKey: "+encX);
		
		//BROADCAST encX
		return encX;
	}
	
	
	
	
	
	public static void signRoudOne(List<User> userList, BigInteger encX) {
		
		BigInteger rhoI, rhoIRnd, uI, vI;
		
		MultiTrapdoorCommitment mpkUiVi;
		Open<BigInteger> openUiVi;
		Commitment cmtUiVi;
		
		
		for(int i = 0; i < userList.size() ; i ++) {
			
			rhoI = RandomUtil.randomFromZn(BitcoinParams.q, OtherParams.SecureRnd);
			rhoIRnd = RandomUtil.randomFromZnStar(OtherParams.PaillPubKey.getN(), OtherParams.SecureRnd);
			
			uI = OtherParams.PaillEnc.encrypt(rhoI, rhoIRnd);
			vI = OtherParams.PaillEnc.multiply(encX, rhoI);
			
			mpkUiVi = MultiTrapdoorCommitment.multiLinnearCommit(OtherParams.SecureRnd, OtherParams.MPK, uI, vI);
			openUiVi = mpkUiVi.getOpen();
			cmtUiVi = mpkUiVi.getCommitment();

			userList.get(i).setRhoI(rhoI);
			userList.get(i).setRhoIRnd(rhoIRnd);
			userList.get(i).setuI(uI);
			userList.get(i).setvI(vI);
			userList.get(i).setMpkUiVi(mpkUiVi);
			userList.get(i).setOpenUiVi(openUiVi);
			userList.get(i).setCmtUiVi(cmtUiVi);
			
			System.out.println("\n--Info: User "+i+" calculate Commitment in round ONE");
			
			//BROADCAST cmtUiVi
		}
		
	}
	
	
	
	
	public static void signRoudTwo(List<User> userList, BigInteger encX) {
	
		Zkp_i1 zkp1;
		
		for(int i = 0; i < userList.size() ; i ++) {
			zkp1 = new Zkp_i1(OtherParams.ZKParams, userList.get(i).getRhoI(), OtherParams.SecureRnd, userList.get(i).getRhoIRnd(), 
					userList.get(i).getvI(), encX, userList.get(i).getuI());
			
			userList.get(i).setZkp1(zkp1);
			
			System.out.println("\n--Info: User "+i+" calculate Zero-Knowledge in round TWO");
			
			//BROADCAST zkp1, openUiVi
		}
	}

	
	

	public static BigInteger calculateU(List<User> userList) {
		BigInteger u;
		
		u = userList.get(0).getOpenUiVi().getSecrets()[0];
		for (int i = 1; i < userList.size(); i++) {
			u = OtherParams.PaillEnc.add(u, userList.get(i).getOpenUiVi().getSecrets()[0]);
		}

		System.out.println("\n--Info: Calculate the Encrypted Inner-Data u"+
				"\n u: "+u);
		
		return u;
		//BROADCAST u
	}
	
	
	
	public static BigInteger calculateV(List<User> userList) {
		BigInteger v;
		
		v = userList.get(0).getOpenUiVi().getSecrets()[1];
		for (int i = 1; i < userList.size(); i++) {
			v = OtherParams.PaillEnc.add(v, userList.get(i).getOpenUiVi().getSecrets()[1]);
		}

		System.out.println("\n--Info: Calculate the Encrypted Inner-Data v"+
				"\n v: "+v);
		
		return v;
		//BROADCAST v
	}

	
	
	
	public static Boolean signRoundThree(List<User> userList, BigInteger encX, BigInteger u, BigInteger v) {
		
		Boolean aborted = false;
				
		//1 check commitment
		for (int i = 0; i < userList.size(); i++) {
			if (!MultiTrapdoorCommitment.checkcommitment(userList.get(i).getCmtUiVi(), userList.get(i).getOpenUiVi(), OtherParams.MPK)) {
				aborted = true;
				System.out.println("\n##Error####################: "+
						"\n SignRound 3, User "+i+"does not pass checking Commitment!");
				return aborted;
			}
		}
		
		//2 verify zk
		for (int i = 0; i < userList.size(); i++) {
			if (!userList.get(i).getZkp1().verify(OtherParams.ZKParams, BitcoinParams.CURVE, userList.get(i).getOpenUiVi().getSecrets()[1], 
					encX, userList.get(i).getOpenUiVi().getSecrets()[0])) {
				aborted = true;				
				System.out.println("\n##Error####################: "+
						"\n SignRound 3, User "+i+"does not pass verifying Zero-Knowledge!");
				return aborted;
			}			
		}
		
		//3
		BigInteger kI, cI, cIRnd;
		ECPoint rI;

		BigInteger mask, wI;
		
		MultiTrapdoorCommitment mpkRiWi;
		Open<BigInteger> openRiWi;
		Commitment cmtRiWi;
		

		for (int i = 0; i < userList.size(); i++) {
			kI = RandomUtil.randomFromZn(BitcoinParams.q, OtherParams.SecureRnd);
			rI = BitcoinParams.G.multiply(kI);
			
			cI = RandomUtil.randomFromZn(BitcoinParams.q, OtherParams.SecureRnd);
			cIRnd = RandomUtil.randomFromZnStar(OtherParams.PaillPubKey.getN(),OtherParams.SecureRnd);
			
			mask = OtherParams.PaillEnc.encrypt(BitcoinParams.q.multiply(cI), cIRnd);
			wI = OtherParams.PaillEnc.add(OtherParams.PaillEnc.multiply(u, kI), mask);
			
			mpkRiWi = MultiTrapdoorCommitment.multiLinnearCommit(OtherParams.SecureRnd, OtherParams.MPK, new BigInteger(rI.getEncoded()), wI);
			openRiWi = mpkRiWi.getOpen();
			cmtRiWi = mpkRiWi.getCommitment();
			
			userList.get(i).setkI(kI);
			userList.get(i).setcI(cI);
			userList.get(i).setcIRnd(cIRnd);
			userList.get(i).setrI(rI);
			
			userList.get(i).setMask(mask);
			userList.get(i).setwI(wI);
			
			userList.get(i).setMpkRiWi(mpkRiWi);
			userList.get(i).setOpenRiWi(openRiWi);
			userList.get(i).setCmtRiWi(cmtRiWi);
			
			System.out.println("\n--Info: User "+i+" calculate Commitment in round THREE");
			
		}
		//BROADCAST cmtRiWi
		
		return aborted;
	}
	
	
	
	
	
	
	public static void signRoundFour(List<User> userList, BigInteger u) {

		Zkp_i2 zkp2;
		
		for (int i = 0; i < userList.size(); i++) {	
			zkp2 = new Zkp_i2(OtherParams.ZKParams, userList.get(i).getkI(), userList.get(i).getcI(), OtherParams.SecureRnd, BitcoinParams.G, 
					userList.get(i).getwI(), u, userList.get(i).getcIRnd());
			
			userList.get(i).setZkp_i2(zkp2);
			
			System.out.println("\n--Info: User "+i+" calculate Zero-Knowledge in round FOUR");
			
			//BROADCSAT zkp_i2, openRiWi
		}
		
	}
	
	
	
	
	
	
	
	public static BigInteger calculateW(List<User> userList) {
		BigInteger w;
		
		w = userList.get(0).getOpenRiWi().getSecrets()[1];
		for (int i = 1; i < userList.size(); i++) {
			w = OtherParams.PaillEnc.add(w, userList.get(i).getOpenRiWi().getSecrets()[1]);
		}
		
		System.out.println("\n--Info: Calculate the Encrypted Inner-Data w"+
				"\n w: "+w);
		
		return w;
	}
	
	
	
	
	
	
	public static ECPoint calculateR(List<User> userList) {
		ECPoint R;
		
		R= BitcoinParams.CURVE.getCurve().decodePoint(userList.get(0).getOpenRiWi().getSecrets()[0].toByteArray());
		for (int i = 1; i < userList.size(); i++) {
			R = R.add(BitcoinParams.CURVE.getCurve().decodePoint(userList.get(i).getOpenRiWi().getSecrets()[0].toByteArray()));
		}
		
		System.out.println("\n--Info: Calculate the Encrypted Inner-Data R"+
				"\n R: "+R.toString());
		
		return R;
	}
	
	
	
	public static ECDSASignature signRoundFive(List<User> userList, BigInteger u, BigInteger v, ECPoint R, BigInteger w, String message) {
		
		ECDSASignature signature = new ECDSASignature();		
		Boolean aborted = false;		
		
		//1 check commitment
		for (int i = 0; i < userList.size(); i++) {
			if (!MultiTrapdoorCommitment.checkcommitment(userList.get(i).getCmtRiWi(), userList.get(i).getOpenRiWi(), OtherParams.MPK)) {
				aborted = true;
				System.out.println("\n##Error####################: "+
						"\n SignRound 5, User "+i+"does not pass checking Commitment!");
				signature.setRoudFiveAborted(aborted);
			}
		}
		
		//2 verify zk
		for (int i = 0; i < userList.size(); i++) {
			if (!userList.get(i).getZkp_i2().verify(OtherParams.ZKParams, BitcoinParams.CURVE, 
					BitcoinParams.CURVE.getCurve().decodePoint(userList.get(i).getOpenRiWi().getSecrets()[0].toByteArray()), 
					u, userList.get(i).getOpenRiWi().getSecrets()[1])){
				aborted = true;
				System.out.println("\n##Error####################: "+
						"\n SignRound 5, User "+i+"does not pass verifying Zero-Knowledge!");
				signature.setRoudFiveAborted(aborted);
			}
		}
		
		
		//3 calculate the signature (r,s)
		BigInteger r, mu;
		
		r = R.getX().toBigInteger().mod(BitcoinParams.q);		
		mu = OtherParams.PaillDec.decrypt(w).mod(BitcoinParams.q);
		
		BigInteger muInverse, mMultiU, rMultiV, sEnc, s;
		
		muInverse = mu.modInverse(BitcoinParams.q);
		mMultiU = OtherParams.PaillEnc.multiply(u, OtherUtil.calculateMPrime(BitcoinParams.q, message.getBytes()));
		rMultiV = OtherParams.PaillEnc.multiply(v, r);
		
		sEnc = OtherParams.PaillEnc.multiply(OtherParams.PaillEnc.add(mMultiU, rMultiV), muInverse);
		
		s = OtherParams.PaillDec.decrypt(sEnc).mod(BitcoinParams.q);

		signature.setRoudFiveAborted(aborted);
		signature.setR(r);
		signature.setS(s);
		
		System.out.println("\n--Info: Calculate the ECDSA Signature in round FIVE"+
				"\n signature: "+signature.toString());
		
		return signature;
	}
	
	
	
	
	public static ECDSASignature sign(List<User> userList, BigInteger encX, String message) {
		
		signRoudOne(userList, encX);
		signRoudTwo(userList, encX);
		
		BigInteger u = calculateU(userList);
		BigInteger v = calculateV(userList);
		
		Boolean roudThreeAborted = signRoundThree(userList, encX, u, v);
		if(roudThreeAborted) {
			return null;
		}
		
		signRoundFour(userList, u);
		

		BigInteger w = calculateW(userList);
		ECPoint R = calculateR(userList);
		
		ECDSASignature signature = signRoundFive(userList, u, v, R, w, message);
		if(signature.getRoudFiveAborted()) {
			return null;
		}
		
		return signature;
	}
	
	
	public static Boolean verify(ECDSASignature signature, String message, ECPoint pk) {
		
		return signature.verify(message, pk);
	}

	
}
