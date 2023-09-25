package it.ipzs.cie.nis.ias;

import it.ipzs.cie.nis.core.Nfc;


public class NisSdk {

    private IasHsm ias;
    private NisSdkCallback nisSdkCallback;
    private boolean isReady;

    public NisSdk(Nfc nfcInterface, NisSdkCallback nisSdkCallback, boolean isLogEnabled){
        try {
            this.nisSdkCallback = nisSdkCallback;
            this.ias = new IasHsm(nfcInterface, isLogEnabled);
            this.isReady = true;

        }catch (Exception exc){
            this.nisSdkCallback.onError(exc);
            this.isReady = false;
        }
    }


    public void enroll()  {
        try {
            //lego NIS, KPUB e calcolo HASH
            String idServizi = ias.getIdServiziFromEf();
            String hashKpubServ = ias.readIntAuthServ1005();

            //verifica originalità
            try{
                if(!ias.intAuth()){
                    //internal authentication ko
                    return;
                }
            }catch (Exception exception){
                nisSdkCallback.onError(exception);
            }

            //verifica autenticità
            try{
                ias.readEfSod();
                ias.verifySod();
                nisSdkCallback.onSuccess(new NisAutheticated(idServizi,hashKpubServ));
            }catch (Exception exception){
                nisSdkCallback.onError(exception);
            }

        }catch (Exception exc){
            nisSdkCallback.onError(exc);
        }
    }

    /**
     * metodo di esempio per mostrare il flow di accesso
     */
    public void access()  {
        try {
            //lego NIS, KPUB e calcolo HASH
            String idServizi = ias.getIdServiziFromEf();
            String hashKpubServ = ias.readIntAuthServ1005();

            //verifico originalità
            try{
                if(ias.intAuth()){
                    //internal authentication ok
                    nisSdkCallback.onSuccess(new NisAutheticated(idServizi, hashKpubServ));
                }
            }catch (Exception exception){
                nisSdkCallback.onError(exception);
            }

        }catch (Exception exc){
            nisSdkCallback.onError(exc);
        }
    }

    public boolean isReady() {
        return isReady;
    }
}
