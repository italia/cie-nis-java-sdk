package it.ipzs.cie.nis.core;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Calendar;


public class AppUtil {

	public static int toUint(byte[] dataB) {
		if(dataB == null)
			return 0;
		int val = +0;
		for (byte b : dataB) {
			val = (val << 8) | b;
		}
		return val;
	}

	public static byte[] getRandomByte(byte[] array,int numByte) {
		SecureRandom random = new SecureRandom();
		array = random.generateSeed(numByte);
		return array;
	}

	public static boolean byteArrayCompare(byte[] a, byte[] b){
		boolean uguali = true;
		if(a.length == b.length){
			for(int i=0;i<a.length;i++)
				if(!byteCompare(a[i],b[i])){
					uguali = false;
					break;
				}
		}
		return uguali;
	}
	public static boolean byteCompare(byte a, byte b){
		return a == b;
	}
	public static int byteCompare(int a, int b){
		return Byte.compare((byte)a,(byte)b);
	}

	public static byte[] getSha(String instance, byte[] array) throws Exception {
		MessageDigest md = MessageDigest.getInstance(instance);
		return md.digest(array);
	}

	public static  byte unsignedToBytes(int b)throws Exception {
		return (byte) (b & 0xFF);
	}
	static byte[] lenToBytes(int value) throws Exception {
		if (value<0x80) {
			return new byte[] {(byte)value};
		}
		if (value<=0xff) {
			return new byte[] {(byte)0x81,(byte)value};
		}
		else if (value<=0xffff) {
			return new byte[] {(byte)0x82,(byte)(value >> 8),(byte)(value & 0xff)};
		}
		else if (value<=0xffffff) {
			return new byte[] {(byte)0x83,(byte)(value>> 16),(byte)((value>> 8) & 0xff),(byte)(value & 0xff)};
		}
		else if (value<=0xffffffff) {
			return new byte[] {(byte)0x84,(byte)(value>>24),(byte)((value>> 16) & 0xff),(byte)((value>> 8) & 0xff),(byte)(value & 0xff)};
		}
		throw new Exception("dati troppo lunghi");
	}
	public static byte[] asn1Tag(byte[] array,int tag) throws Exception {

		byte[] _tag=  tagToByte(tag);//1

		byte[] _len=lenToBytes(array.length);//2

		byte[] data=new byte[_tag.length+_len.length+array.length];//131

		System.arraycopy(_tag,0,data,0,_tag.length);
		System.arraycopy(_len,0,data,_tag.length,_len.length);
		System.arraycopy(array,0,data,_tag.length+_len.length,array.length);
		return data;
	}


	public static byte[] tagToByte(int value) throws Exception {
		if (value<=0xff) {
			return new byte[] { unsignedToBytes(value)};
		}
		else if (value<=0xffff) {
			return new byte[] {(byte)(value >> 8),(byte)(value & 0xff)};
		}
		else if (value<=0xffffff) {
			return new byte[] {(byte)(value>> 16),(byte)((value>> 8) & 0xff),(byte)(value & 0xff)};
		}
		else if (value<=0xffffffff) {
			return new byte[] {(byte)(value>>24),(byte)((value>> 16) & 0xff),(byte)((value>> 8) & 0xff),(byte)(value & 0xff)};
		}
		throw new Exception("tag troppo lungo");
	}

	public static byte[] getSub(byte[] array, int start,int num)throws Exception {
		if(Math.signum(num) < 0)
			num = num & 0xff;
		byte[] data = new byte[num];
		System.arraycopy(array, start, data, 0, data.length);
		return data;
	}

	public static  byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
					+ Character.digit(s.charAt(i+1), 16));
		}
		return data;
	}

	public static byte[] getRight(byte[] array,int num)throws Exception {
		if(num > array.length)
			return array.clone();
		byte data[] = new byte[num];
		System.arraycopy(array, array.length - num, data, 0, num);
		return data;
	}
	public static byte[] getLeft(byte[] array,int num)throws Exception {
		if(num > array.length)
			return array.clone();
		byte data[] = new byte[num];
		System.arraycopy(array, 0, data, 0, num);
		return data;
	}

	public static byte[] appendByteArray(byte[] a, byte[]b)throws Exception {
		byte[] c = new byte[a.length + b.length];
		System.arraycopy(a, 0, c, 0, a.length);
		System.arraycopy(b, 0, c, a.length, b.length);
		return c;
	}
	public static byte[] appendByte(byte[] a, byte b)throws Exception {
		byte[] c = new byte[a.length + 1];
		System.arraycopy(a, 0, c, 0, a.length);
		c[a.length] = b;
		return c;
	}

	public static String bytesToHex (byte[] bytes) throws Exception {
		StringBuilder sb = new StringBuilder(bytes.length * 2);
		for (byte aByte : bytes) {
			sb.append(String.format("%02x", aByte).toUpperCase());
		}
		return sb.toString();
	}


}
