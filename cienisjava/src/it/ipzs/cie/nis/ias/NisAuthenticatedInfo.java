package it.ipzs.cie.nis.ias;

import it.ipzs.cie.nis.core.X509Utils;

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

public class NisAuthenticatedInfo {
    //NIS
    private String idServizi;

    //Kpub SERVIZI_INT.KPUB
    private byte[] ef1005Raw;
    private String hashEf1005FromEf;
    //sod
    private byte[] ef1006Raw;

    private boolean intAuthpassed;
    private X509Certificate documentSigner;
    private X509Certificate csca;

    //contenitore hash df
    private final Map<String, byte[]> mappaDg;

    public NisAuthenticatedInfo() {
        this.mappaDg = new HashMap<>();
        this.idServizi = "";
        this.ef1005Raw = new byte[]{};
        this.ef1006Raw = new byte[]{};
        this.intAuthpassed = false;
        this.documentSigner = null;
        this.csca = null;
    }


    public String getIdServizi() {
        return idServizi;
    }

    public void setIdServizi(String idServizi) {
        this.idServizi = idServizi;
    }

    public byte[] getEf1005Raw() {
        return ef1005Raw;
    }

    public void setEf1005Raw(byte[] ef1005Raw) {
        this.ef1005Raw = ef1005Raw;
    }

    public byte[] getEf1006Raw() {
        return ef1006Raw;
    }

    public void setEf1006Raw(byte[] ef1006Raw) {
        this.ef1006Raw = ef1006Raw;
    }

    public boolean isIntAuthpassed() {
        return intAuthpassed;
    }

    public X509Certificate getDocumentSigner() {
        return documentSigner;
    }

    public void setDocumentSigner(X509Certificate documentSigner) {
        this.documentSigner = documentSigner;
    }

    public void setIntAuthpassed(boolean intAuthpassed) {
        this.intAuthpassed = intAuthpassed;
    }

    public X509Certificate getCsca() {
        return csca;
    }

    public void setCsca(X509Certificate csca) {
        this.csca = csca;
    }

    public String getHashEf1005FromEf() {
        return hashEf1005FromEf;
    }

    public void setHashEf1005FromEf(String hashEf1005FromEf) {
        this.hashEf1005FromEf = hashEf1005FromEf;
    }

    public Map<String, byte[]> getMappaDg() {
        return mappaDg;
    }

    @Override
    public String toString() {
        try {
            String document = ("\n**************************************************************************") + "\n";
            document = document + ("ID SERVIZI(NIS): " + idServizi) + "\n";
            document = document + ("CHIAVE PUBBLICA SERVIZI (HashKPub):" + hashEf1005FromEf) + " \n";
            document = document + ("INTERNAL AUTHENTICATION: " + intAuthpassed) + "\n";
            if (documentSigner != null) {
                document = document + ("DOCUMENT SIGNER CERTIFICATE: ") + "\n";
                document = document + X509Utils.getX509CertificateInfo(documentSigner) + "\n";
            }
            if (csca != null) {
                document = document + ("CSCA CERTIFICATE: ") + "\n";
                document = document + X509Utils.getX509CertificateInfo(csca) + "\n";
            }
            document = document + ("**************************************************************************");
            return document;
        } catch (Exception exc) {
            return "";
        }

    }
}
