package it.ipzs.cie.nis.core;

public interface Nfc {
    ApduResponse transmit(byte[] apdu)throws Exception;
    void initTerminal()throws Exception;
}
