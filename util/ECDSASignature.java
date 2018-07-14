package util;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

public class ECDSASignature {
	
	private BigInteger r;
	
	private BigInteger s;
	
	private Boolean roudFiveAborted;

	
	public ECDSASignature() {}
	
	public ECDSASignature(BigInteger r, BigInteger s) {
		this.r = r;
		this.s = s;		
	}
	

	public Boolean verify(String message, ECPoint pk) {
		
		BigInteger z = OtherUtil.calculateMPrime(BitcoinParams.q, message.getBytes());
		
		BigInteger u1 = (z.multiply(s.modInverse(BitcoinParams.q))).mod(BitcoinParams.q);
		BigInteger u2 = (r.multiply(s.modInverse(BitcoinParams.q))).mod(BitcoinParams.q);
		
		BigInteger xR = (BitcoinParams.G.multiply(u1).add(pk.multiply(u2))).getX().toBigInteger().mod(BitcoinParams.q);

		
		if(xR.equals(r)) {
			System.out.println("\n\n--Info: ECDSA Signature Verify Passed!"+
					"\n (r,s)=("+ r +","+ s +") is a Valid Siganture!\n\n");			
			return true;
		}else {
			System.out.println("\n\n@@ERROR@@@@@@@@@@@@@@@@@@@@@@@@@@@@: ECDSA Signature Verify NOT Passed!"+
					"\n (r,s)=("+ r +","+ s +") is a InValid Siganture!\n\n");
			return false;
		}
	}
	
	
	
	

	@Override
	public String toString() {
		// TODO Auto-generated method stub
		return "(r,s)=("+ r +","+ s +")";
	}
	
	
	

	public Boolean getRoudFiveAborted() {
		return roudFiveAborted;
	}

	
	public void setRoudFiveAborted(Boolean roudFiveAborted) {
		this.roudFiveAborted = roudFiveAborted;
	}
	

	public BigInteger getR() {
		return r;
	}


	public void setR(BigInteger r) {
		this.r = r;
	}


	public BigInteger getS() {
		return s;
	}


	public void setS(BigInteger s) {
		this.s = s;
	}
	
	
}
