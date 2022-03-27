package it.ipzs.cie.nis.core;

import javax.smartcardio.*;
import java.util.Arrays;
import java.util.List;

public class NfcTerminalImpl implements Nfc {

    static Card card = null;
    static CardChannel channel = null;

    @Override
    public ApduResponse transmit(byte[] apdu) throws Exception {
        SDKLogCore.log("APDU: " + AppUtil.bytesToHex(apdu));
        ResponseAPDU risposta = channel.transmit(new CommandAPDU(apdu));
        byte[] ris = risposta.getBytes();
        byte[] filteredByteArray = Arrays.copyOfRange(ris, 0, ris.length - 2);
        byte[] temp = Arrays.copyOfRange(ris, ris.length - 2,ris.length);
        ApduResponse resp  = new ApduResponse(filteredByteArray, temp);
        SDKLogCore.log("RESPONSE: " + AppUtil.bytesToHex(resp.getResponse()));
        SDKLogCore.log("SW: " + AppUtil.bytesToHex(resp.getSwByte()));
        return resp;
    }

    @Override
    public void initTerminal() throws Exception {
        TerminalFactory factory = getTerminalFactory4Os();
        CardTerminals terminals;
        terminals = factory.terminals();
        List<CardTerminal> cardTerminalList;
        try {
            cardTerminalList = terminals.list();
        }catch (Exception e){
            throw new Exception("Nessun terminale collegato");
        }
        SDKLogCore.log("Numero lettori: " + cardTerminalList.size());
        if (cardTerminalList.isEmpty()) {
            SDKLogCore.log("Nessun terminale...");
            throw new Exception("Nessun terminale collegato");
        }else {
            for (CardTerminal t : cardTerminalList) {
                SDKLogCore.log(("provo il terminale: " + t.getName()).toUpperCase());
                try {
                    card = t.connect("T=1");//t=1
                }catch (Exception exc){
                    continue;
                }
                channel = card.getBasicChannel();
            }
            if(channel==null){
                throw new Exception("Nessuna carta sul lettore");
            }
        }
    }

    private TerminalFactory getTerminalFactory4Os() throws Exception {
        TerminalFactory factory = null;
        if (UtilOs.getOS() == UtilOs.OS.MAC) {
            System.setProperty("sun.security.smartcardio.library", "/System/Library/Frameworks/PCSC.framework/Versions/Current/PCSC");
            factory = TerminalFactory.getInstance("PC/SC", null);
        }else
            factory = TerminalFactory.getDefault();
        return factory;
    }

}
