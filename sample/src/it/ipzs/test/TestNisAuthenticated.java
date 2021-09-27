package it.ipzs.test;

import it.ipzs.cie.nis.core.NfcTerminalImpl;
import it.ipzs.cie.nis.ias.NisSdk;
import it.ipzs.cie.nis.ias.NisAutheticated;
import it.ipzs.cie.nis.ias.NisSdkCallback;

public class TestNisAuthenticated implements NisSdkCallback {


    public static void main(String[] args) {
        NisSdk nisSdk = new TestNisAuthenticated().initSdk();

        if(nisSdk.isReady()){
            //metodo per eseguire la registrazione
            nisSdk.enroll();

            //metodo che mostra le operazioni di accesso da eseguire al tornello
            nisSdk.access();
        }

    }

    public NisSdk initSdk() {
        return new NisSdk(new NfcTerminalImpl(), this, true);
    }

    @Override
    public void onSuccess(NisAutheticated nisAutheticated) {
        System.out.println("NIS : " + nisAutheticated.getNis());
        System.out.println("HASH CHIAVE PUBBLICA SERVIZI : " + nisAutheticated.getHaskKpubIntServ());
    }

    @Override
    public void onError(Exception error) {
        System.out.println("ERRORE : "+error.getMessage());
    }
}
