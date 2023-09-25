package it.ipzs.cie.nis.core;

import java.util.Arrays;

public class ApduResponse {

	private byte[] response;
	private byte[] sw;


	public ApduResponse(byte[] fullResponse)throws Exception {
		this.response = Arrays.copyOfRange(fullResponse, 0, fullResponse.length - 2);
		this.sw = Arrays.copyOfRange(fullResponse, fullResponse.length - 2, fullResponse.length);
	}
	public ApduResponse(byte[] res, byte[] sw)throws Exception {
		this.response = res;
		this.sw = sw;
	}
	public byte[] getResponse()throws Exception {
		return response;
	}

	public String getSwHex()throws Exception {
		return bytesToHex(this.sw);
	}
	public byte[] getSwByte()throws Exception {
		return this.sw;
	}
	public int getSwInt()throws Exception {
		return AppUtil.toUint(this.sw);
	}

	protected String bytesToHex (byte[] bytes) throws Exception {
		StringBuilder sb = new StringBuilder(bytes.length * 2);
		for (byte aByte : bytes) {
			sb.append(String.format("%02x", aByte));
		}
		return sb.toString();
	}

}
