package util;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;
import Common.Commitments.Commitment;
import Common.Commitments.MultiTrapdoorCommitment;
import Common.Commitments.Open;
import ACNS.ZeroKnowledgeProofs.Zkp_i1;
import ACNS.ZeroKnowledgeProofs.Zkp_i2;

public class User {
	
	//keyGenerate
	private BigInteger xShare, xShareRnd, encXShare;
	private ECPoint yShare;
	
	
	
	//round 1
	private BigInteger rhoI, rhoIRnd, uI, vI;
	
	private MultiTrapdoorCommitment mpkUiVi;
	private Open<BigInteger> openUiVi;
	private Commitment cmtUiVi;
	
	
	
	//round 2
	private Zkp_i1 zkp1;
	
	
	
	//round 3	
	private BigInteger kI, cI, cIRnd;
	private ECPoint rI;

	private BigInteger mask, wI;
	
	private MultiTrapdoorCommitment mpkRiWi;
	private Open<BigInteger> openRiWi;
	private Commitment cmtRiWi;
	
	
	
	//round 4
	private Zkp_i2 zkp_i2;
	
	
	
	
	public BigInteger getxShare() {
		return xShare;
	}
	public void setxShare(BigInteger xShare) {
		this.xShare = xShare;
	}
	public BigInteger getxShareRnd() {
		return xShareRnd;
	}
	public void setxShareRnd(BigInteger xShareRnd) {
		this.xShareRnd = xShareRnd;
	}
	public BigInteger getRhoI() {
		return rhoI;
	}
	public void setRhoI(BigInteger rhoI) {
		this.rhoI = rhoI;
	}
	public BigInteger getRhoIRnd() {
		return rhoIRnd;
	}
	public void setRhoIRnd(BigInteger rhoIRnd) {
		this.rhoIRnd = rhoIRnd;
	}
	public Open<BigInteger> getOpenUiVi() {
		return openUiVi;
	}
	public void setOpenUiVi(Open<BigInteger> openUiVi) {
		this.openUiVi = openUiVi;
	}
	public Open<BigInteger> getOpenRiWi() {
		return openRiWi;
	}
	public void setOpenRiWi(Open<BigInteger> openRiWi) {
		this.openRiWi = openRiWi;
	}
	public BigInteger getkI() {
		return kI;
	}
	public void setkI(BigInteger kI) {
		this.kI = kI;
	}
	public BigInteger getcI() {
		return cI;
	}
	public void setcI(BigInteger cI) {
		this.cI = cI;
	}
	public BigInteger getcIRnd() {
		return cIRnd;
	}
	public void setcIRnd(BigInteger cIRnd) {
		this.cIRnd = cIRnd;
	}
	public BigInteger getuI() {
		return uI;
	}
	public void setuI(BigInteger uI) {
		this.uI = uI;
	}
	public BigInteger getvI() {
		return vI;
	}
	public void setvI(BigInteger vI) {
		this.vI = vI;
	}
	public BigInteger getwI() {
		return wI;
	}
	public void setwI(BigInteger wI) {
		this.wI = wI;
	}
	public BigInteger getEncXShare() {
		return encXShare;
	}
	public void setEncXShare(BigInteger encXShare) {
		this.encXShare = encXShare;
	}
	public ECPoint getyShare() {
		return yShare;
	}
	public void setyShare(ECPoint yShare) {
		this.yShare = yShare;
	}
	public MultiTrapdoorCommitment getMpkUiVi() {
		return mpkUiVi;
	}
	public void setMpkUiVi(MultiTrapdoorCommitment mpkUiVi) {
		this.mpkUiVi = mpkUiVi;
	}
	public Commitment getCmtUiVi() {
		return cmtUiVi;
	}
	public void setCmtUiVi(Commitment cmtUiVi) {
		this.cmtUiVi = cmtUiVi;
	}
	public Zkp_i1 getZkp1() {
		return zkp1;
	}
	public void setZkp1(Zkp_i1 zkp1) {
		this.zkp1 = zkp1;
	}
	public ECPoint getrI() {
		return rI;
	}
	public void setrI(ECPoint rI) {
		this.rI = rI;
	}
	public BigInteger getMask() {
		return mask;
	}
	public void setMask(BigInteger mask) {
		this.mask = mask;
	}
	public MultiTrapdoorCommitment getMpkRiWi() {
		return mpkRiWi;
	}
	public void setMpkRiWi(MultiTrapdoorCommitment mpkRiWi) {
		this.mpkRiWi = mpkRiWi;
	}
	public Commitment getCmtRiWi() {
		return cmtRiWi;
	}
	public void setCmtRiWi(Commitment cmtRiWi) {
		this.cmtRiWi = cmtRiWi;
	}
	public Zkp_i2 getZkp_i2() {
		return zkp_i2;
	}
	public void setZkp_i2(Zkp_i2 zkp_i2) {
		this.zkp_i2 = zkp_i2;
	}
	
}
