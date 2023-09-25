package it.ipzs.cie.nis.ias;

import it.ipzs.cie.nis.core.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;


/**
 *Classe per la gestione delle funzionalità di autenticazione
 */
public class IasHsm extends Hsm {

    private final Nfc nfc;
    private final NisAuthenticatedInfo nisAuthenticatedInfo;

    protected IasHsm(Nfc nfc, boolean isLogEnabled) throws Exception{
        this.nfc = nfc;
        this.nisAuthenticatedInfo = new NisAuthenticatedInfo();

        SDKLogCore.logEnabled = isLogEnabled;
        SDKLogNis.logEnabled = isLogEnabled;

        nfc.initTerminal();

    }


    protected void selectAidCie() throws Exception {
        byte[] selectCie = { 0x00, (byte)0xa4, 0x04, 0x0c };
        byte[] CIE_AID = { (byte)0xA0, 0x00, 0x00, 0x00, 0x00, 0x39 };
        sendApdu(selectCie,CIE_AID,null);
    }

    /**
     * legge il Sod
     * @throws Exception
     */
    protected void readEfSod()throws Exception {
        SDKLogNis.log("readSod()");
        selectAidCie();
        byte[] sod = readFile(0x1006);
        nisAuthenticatedInfo.setEf1006Raw(sod);
        //set sulla mappadg per la verifica del SOD
        nisAuthenticatedInfo.getMappaDg().put("A6",sod);
    }

    private byte[] signIntAuth(byte[] dataToSign)throws Exception {
        SDKLogNis.log("sign()");
        byte[] setKey = { 0x00, 0x22, 0x41, (byte)0xA4 };
        byte[] val02 = {0x02};
        byte[] keyId = {(byte)0x83};
        byte[] dati = AppUtil.appendByteArray(AppUtil.asn1Tag(val02,0x80),AppUtil.asn1Tag(keyId,0x84));

        sendApdu(setKey,dati,null);
        byte[] signApdu = { 0x00, (byte)0x88, 0x00, 0x00 };
        ApduResponse response = sendApdu(signApdu,dataToSign,null);
        return response.getResponse();

    }
    protected boolean intAuth() throws Exception {
        SDKLogNis.log("internal authentication...");

        byte[] random = new byte[]{};
        random = AppUtil.getRandomByte(random,16);
        SDKLogNis.log("random..."+AppUtil.bytesToHex(random));
        byte[] firmato = signIntAuth(random);

        //recupero la chiave pubblica
        byte[] pubKeyFile = nisAuthenticatedInfo.getEf1005Raw();
        Asn1Tag pubKeyFileAsn = Asn1Tag.parse(pubKeyFile,false);
        byte[] modulo = pubKeyFileAsn.child(0).getData();
        byte[] esponente = pubKeyFileAsn.child(1).getData();
        RSA rsa = new RSA(modulo,esponente);

        //decifra
        byte[] decrypt = rsa.decrypt(firmato);
        SDKLogNis.log("decrypt: " + AppUtil.bytesToHex(decrypt));
        byte[] ultimiOtto = AppUtil.getRight(decrypt,16);

        //compara
        if(AppUtil.byteArrayCompare(random,ultimiOtto)) {
            SDKLogNis.log("Internal Authentication corretta");
            nisAuthenticatedInfo.setIntAuthpassed(true);
            return true;
        }
        else {
            SDKLogNis.log("Errore authenticazione con il chip!");
            nisAuthenticatedInfo.setIntAuthpassed(false);
            return false;
        }
    }


    protected String readIntAuthServ1005() throws Exception {
        //1.2.	Lettura della chiave pubblica Kpub da EF.SERVIZI_INT.KPUB;
        SDKLogNis.log("Lettura della chiave pubblica Kpub da EF.SERVIZI_INT.KPUB: ");
        byte[] bytes = readFile(0x1005);
        nisAuthenticatedInfo.setEf1005Raw(bytes);
        //parser per il controllo sulla verifica del SOD
        Asn1Tag asn1Tag = Asn1Tag.parse(bytes,false);
        byte[] A5noHash = AppUtil.getLeft(bytes, (int) asn1Tag.getEndPos());
        nisAuthenticatedInfo.getMappaDg().put("A5",A5noHash);
        //Setto l'hash sul documento di ritorno
        String hashKpub = AppUtil.bytesToHex(Algoritmi.getSha("SHA-256",A5noHash));
        nisAuthenticatedInfo.setHashEf1005FromEf(hashKpub);
        return hashKpub;
    }


    protected byte[] readEfIdServizi1001()throws Exception{
        SDKLogNis.log("readEfServizi1001()");
        transmit(AppUtil.hexStringToByteArray("00A4040C0DA0000000308000000009816001"));
        selectAidCie();
        byte[] efIntServ1001 = readFile(0x1001);
        String idServizi = AppUtil.bytesToHex(efIntServ1001);
        if(idServizi.isEmpty()){
            throw new Exception("Non si sta leggendo una CIE");
        }
        nisAuthenticatedInfo.setIdServizi(idServizi);
        nisAuthenticatedInfo.getMappaDg().put("A1",efIntServ1001);
        SDKLogNis.log("idServizi: " + idServizi);
        return efIntServ1001;
    }

    protected String getIdServiziFromEf() throws Exception {
        SDKLogNis.log("getIdServiziFromEf()");
        return  new String(readEfIdServizi1001(), StandardCharsets.UTF_8);
    }

    @Override
    public ApduResponse transmit(byte[] apdu)throws Exception {
        return nfc.transmit(apdu);
    }

    protected void verifySod( ) throws Exception {
        SDKLogNis.log("Verifica file SOD");
        byte[] sod = nisAuthenticatedInfo.getMappaDg().get("A6");
        InputStream inStreamCSCA = null;
        Asn1Tag sodTag = Asn1Tag.parse(sod, false);
        Asn1Tag temp;
        temp = sodTag.Child(0, (byte) 0x30);
        temp.Child(0, (byte) 06).verify(new byte[]{0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x07, 0x02});
        Asn1Tag temp2 = temp.Child(1, (byte) 0xA0).Child(0, (byte) 0x30);
        temp2.Child(0, (byte) 0x02).verify(new byte[]{0x03});
        Asn1Tag digestTag = temp2.Child(1, (byte) 0x31).Child(0, (byte) 0x30).Child(0, (byte) 6);
        String OID_SHA;
        try {
            digestTag.verify(new byte[]{0x2B, 0x0E, 0x03, 0x02, 0x1A});
            OID_SHA = "SHA1";
        } catch (Exception exc) {
            try {
                digestTag.verify(new byte[]{0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01});
                OID_SHA = "SHA-256";
            } catch (Exception exc2) {
                try {
                    digestTag.verify(new byte[]{0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04});
                    OID_SHA = "SHA-224";
                } catch (Exception exc3) {
                    try {
                        digestTag.verify(new byte[]{96, -122, 72, 1, 101, 3, 4, 2, 3});
                        OID_SHA = "SHA-512";
                    } catch (Exception excc) {
                        throw new Exception("Digest Tag non verificato! ");
                    }
                }
            }
        }

        try {
            temp2.Child(2, (byte) 0x30).Child(0, (byte) 06).verify(new byte[]{0x67, (byte) 0x81, 0x08, 0x01, 0x01, 0x01});
        } catch (Exception exc) {
            throw exc;
        }
        //verify: 43,27,1,1,1
        byte[] ttData = temp2.Child(2, (byte) 0x30).Child(1, (byte) 0xA0).Child(0, (byte) 04).getData();
        Asn1Tag tt = Asn1Tag.parse(ttData, false);
        Asn1Tag signedData = tt.checkTag(0x30);
        Asn1Tag signerCert = temp2.Child(3, (byte) 0xA0).Child(0, (byte) 0x30);
        Asn1Tag temp3;
        temp3 = temp2.Child(4, (byte) 0x31).Child(0, (byte) 0x30);
        temp3.Child(0, (byte) 0x02).verify(new byte[]{01});
        Asn1Tag issuerName = temp3.Child(1, (byte) 0x30).Child(0, (byte) 0x30);
        Asn1Tag signerCertSerialNumber = temp3.Child(1, (byte) 0x30).Child(1, (byte) 0x02);

        Asn1Tag digestTag2 = temp3.Child(2, (byte) 0x30).Child(0, (byte) 0x06);
        String digestAlgo2 = null;
        try {
            digestTag2.verify(new byte[]{0x2B, 0x0E, 0x03, 0x02, 0x1A});
            digestAlgo2 = "SHA1";
        } catch (Exception exc) {
            try {
                digestTag2.verify(new byte[]{0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01});
                digestAlgo2 = "SHA-256";
            } catch (Exception exc2) {
                try {
                    digestTag2.verify(new byte[]{0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04});
                    digestAlgo2 = "SHA-224";
                } catch (Exception exc3) {
                    try {
                        digestTag2.verify(new byte[]{96, -122, 72, 1, 101, 3, 4, 2, 3});
                        digestAlgo2 = "SHA-512";
                    } catch (Exception excc) {
                        throw new Exception("Digest Tag non verificato! ");
                    }
                }
            }
        }

        Asn1Tag signerInfos = temp3.Child(3, (byte) 0xA0);
        Asn1Tag digest = null;
        byte OID4[] = new byte[]{0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x09, 0x03};
        byte OID5[] = new byte[]{0x67, (byte) 0x81, 0x08, 0x01, 0x01, 0x01};
        byte OID6[] = new byte[]{0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x09, 0x04};
        signerInfos.Child(0, (byte) 0x30).Child(0, (byte) 06).verify(OID4);
        signerInfos.Child(0, (byte) 0x30).Child(1, (byte) 0x31).Child(0, (byte) 06).verify(OID5);
        signerInfos.Child(1, (byte) 0x30).Child(0, (byte) 06).verify(OID6);

        digest = signerInfos.Child(1, (byte) 0x30).Child(1, (byte) 0x31).Child(0, (byte) 04);

        Asn1Tag signAlgoTag = temp3.Child(4, (byte) 0x30).Child(0, (byte) 0x06);
        String signAlgo = null;
        try {
            signAlgoTag.verify(new byte[]{0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x01, 0x01});
            signAlgo = OID_SHA + "withRSA";
        } catch (Exception exx) {
            try {
                signAlgoTag.verify(new byte[]{0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x01, 0x05});
                signAlgo = "SHA1withRSA";
            } catch (Exception exc) {
                try {
                    signAlgoTag.verify(new byte[]{0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x01, 0x0B});
                    signAlgo = "SHA256withRSA";
                    //0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01
                } catch (Exception exc2) {
                    try {
                        signAlgoTag.verify(new byte[]{0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x01, 0x0E});
                        signAlgo = "SHA224withRSA";
                    } catch (Exception exc3) {
                        try {
                            signAlgoTag.verify(new byte[]{0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0D, 0x01, 0x01, 0x0D});
                            signAlgo = "SHA512withRSA";
                        } catch (Exception exc4) {
                            try {
                                signAlgoTag.verify(new byte[]{0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0D, 0x01, 0x01, 0x0A});
                                String sha = OID_SHA.replaceAll("-", "");
                                signAlgo = sha + "withRSA/PSS";
                            } catch (Exception exc5) {
                                try {
                                    signAlgoTag.verify(new byte[]{0x2A, (byte) 0x86, 0x48, (byte) 0xCE, (byte) 0x3D, 0x04, 0x03, 0x02});
                                    String sha = OID_SHA.replaceAll("-", "");
                                    signAlgo = "SHA256WITHECDDSA";
                                } catch (Exception exc6) {
                                    throw new Exception("Algoritmo di firma non riconosciuto");
                                }
                            }
                        }
                    }
                }
            }
        }

        byte[] digestCheck = AppUtil.getSub(ttData, (int) signedData.getStartPos(), (int) (signedData.getEndPos() - signedData.getStartPos()));
        byte[] certDS = AppUtil.getSub(sod, (int) signerCert.getStartPos(), (int) (signerCert.getEndPos() - signerCert.getStartPos()));

        SDKLogNis.log("Verifica Digest");
        if (!Asn1Tag.areEqual(AppUtil.getSha(OID_SHA, digestCheck), digest.getData())) {
            throw new Exception("Il Digest non corrisponde");
        }
        //2.4.	Estrazione del certificato DS
        ByteArrayInputStream inStreamDS = new ByteArrayInputStream(certDS);


        Security.insertProviderAt(new BouncyCastleProvider(),1);

        CertificateFactory cfDS = CertificateFactory.getInstance("X.509");
        X509Certificate certDocS = (X509Certificate) cfDS.generateCertificate(inStreamDS);
        PublicKey pubKeyDS = certDocS.getPublicKey();

        try {
            certDocS.checkValidity();//controlla la validità/scadenza
        } catch (CertificateExpiredException certExp) {
            throw new Exception("Il certificato Document Signer è scaduto il: " + certDocS.getNotAfter());
        }

        // la signature
        Asn1Tag signature = temp3.Child(5, (byte) 0x04);

        //2.12.	Risoluzione della firma dati firmati con la chiave pubblica del DS
        byte[] signatureData = signature.getData();
        byte[] toSign = AppUtil.getSub(sod, (int) signerInfos.getChildren().get(0).getStartPos(), (int) (signerInfos.getChildren().get(signerInfos.getChildren().size() - 1).getEndPos() - signerInfos.getChildren().get(0).getStartPos()));
        byte[] digestSignature2 = AppUtil.asn1Tag(toSign, 0x31);
        Signature sign = null;
        if (signAlgo.contains("PSS")) {
            sign = Signature.getInstance(signAlgo);
            if (digestAlgo2.contains("256"))
                sign.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
            else if (digestAlgo2.contains("512"))
                sign.setParameter(new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1));
            else
                throw new Exception("Caso non previsto");
        } else
            sign = Signature.getInstance(signAlgo);
        sign.initVerify(pubKeyDS);
        sign.update(digestSignature2);
        boolean signIsValid = sign.verify(signatureData);
        if (signIsValid)
            SDKLogNis.log("La firma del SOd è stata verificata");
        else
            SDKLogNis.log("La verifica del SOD ha dato esito negativo");


        //2.10.	Lettura e confronto  ‘Issuer Name’ Dal certificato / SOD
        byte[] sodIssuer = AppUtil.getSub(sod, (int) issuerName.getStartPos(), (int) (issuerName.getEndPos() - issuerName.getStartPos()));
        byte[] issuerCert = certDocS.getIssuerX500Principal().getEncoded();

        Asn1Tag SODIssuer = Asn1Tag.parse(sodIssuer, false);
        Asn1Tag certIssuer = Asn1Tag.parse(issuerCert, false);
        if (SODIssuer.getChildren().size() != certIssuer.getChildren().size())
            SDKLogNis.log("Issuer name non corrispondente");

        for (int i = 0; i < SODIssuer.getChildren().size(); i++) {
            Asn1Tag certElem = certIssuer.getChildren().get(i).getChildren().get(0);
            Asn1Tag sodElem = SODIssuer.getChildren().get(i).getChildren().get(0);
            try {
                certElem.getChildren().get(0).verify(sodElem.getChildren().get(0).getData());
                certElem.getChildren().get(1).verify(sodElem.getChildren().get(1).getData());
            } catch (Exception exc) {
                try {
                    certElem.getChildren().get(0).verify(sodElem.getChildren().get(1).getData());
                    certElem.getChildren().get(1).verify(sodElem.getChildren().get(0).getData());
                } catch (Exception excc) {
                    SDKLogNis.log("Issuer name non corrispondente");
                }
            }
        }
        SDKLogNis.log("Verifica hash dg");
        try {
            signedData.Child(0, (byte) 0x02).verify(new byte[]{0x00});
        } catch (Exception exc) {
            signedData.Child(0, (byte) 0x02).verify(new byte[]{0x01});
        }

        //Asn1Tag digestTag3 = signedData.Child(1, (byte) 0x30).Child(0, (byte) 0x06);
        String digestAlgo3 = "SHA-256";

        //per ogni DG controllo l'hash
        //2.6.	Lettura dati HASH (EF.ID_Servizi) e HASH(EF.SERVIZI_INT.KPUB);
        Asn1Tag hashTag = signedData.Child(2, (byte) 0x30);
        for (Asn1Tag hashDG : hashTag.getChildren()) {
            Asn1Tag dgNum = hashDG.checkTag(0x30).Child(0, (byte) 0x02);
            Asn1Tag dgHash = hashDG.Child(1, (byte) 0x04);
            String num = AppUtil.bytesToHex(dgNum.getData());
            Asn1Tag hashVal = Asn1Tag.parse(AppUtil.getSub(ttData, (int) dgHash.getStartPos(), (int) (dgHash.getEndPos() - dgHash.getStartPos())), false);
            if (nisAuthenticatedInfo.getMappaDg().containsKey(num)) {
                //2.1.	Calcolo h(Kpub) con SHA256 2.2.	Calcolo h(NIS) con SHA256;
                if (hashVal.getData() != null && !Asn1Tag.areEqual(Algoritmi.getSha(digestAlgo3, nisAuthenticatedInfo.getMappaDg().get(num)), hashVal.getData())) {
                    SDKLogNis.log("Digest non corrispondente per il DG" + num + " " + AppUtil.bytesToHex(Algoritmi.getSha(digestAlgo3, nisAuthenticatedInfo.getMappaDg().get(num))));
                } else
                    SDKLogNis.log("Digest  corrispondente per il DG" + num);
            } else
                SDKLogNis.log("Digest presente ma non letto DG" + num);
        }


        //VERIFICA CATENA CERTIFICATI
        SDKLogNis.log("VERIFICA CATENA CERTIFICATI...");
        //devo prendere il certificato csca. è specificato dentro il ds con la chiave autorità
        // autorità certificante del ds struttura asn1
        byte[] tmpidKey = certDocS.getExtensionValue("2.5.29.35");
        Asn1Tag idKeyASN = Asn1Tag.parse(tmpidKey, true);
        byte[] idKey = idKeyASN.child(0).child(0).getData();
        String esadecimaleIdAuth = AppUtil.bytesToHex(idKey).toUpperCase();
        SDKLogNis.log("autorità certificante del ds: " + esadecimaleIdAuth);
        X509Certificate certCSCA;
        CertPathValidator pathValidator = CertPathValidator.getInstance("PKIX");
        CertificateFactory certFactory = CertificateFactory.getInstance("X509");
        CertPath certPath;
        X509Certificate certificatoVerificato;
        try {
            inStreamCSCA = new ByteArrayInputStream(AppUtil.hexStringToByteArray(new X509Utils().getCsca(esadecimaleIdAuth)));
            //carico il certificato di root
            CertificateFactory cfCSCA = CertificateFactory.getInstance("X.509");
            certCSCA = (X509Certificate) cfCSCA.generateCertificate(inStreamCSCA);
            //costruisco la catena dei certificati DS/CSCA
            X509Certificate[] chain = new X509Certificate[]{certDocS, certCSCA};//qui c'è la catena
            certPath = certFactory.generateCertPath(Arrays.asList(chain));

            TrustAnchor trust = new TrustAnchor(certCSCA, null);
            Set<TrustAnchor> trustAnchorsCSCA = new HashSet<TrustAnchor>();
            trustAnchorsCSCA.add(trust);
            PKIXParameters params = new PKIXParameters(trustAnchorsCSCA);
            params.setRevocationEnabled(false);

            PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) pathValidator.validate(certPath, params);//valida la catena
            TrustAnchor trustVerificata = result.getTrustAnchor();
            certificatoVerificato = trustVerificata.getTrustedCert();
            certificatoVerificato.checkValidity();//controlla la validità/scadenza

            //set sul documento
            nisAuthenticatedInfo.setDocumentSigner(certDocS);
            nisAuthenticatedInfo.setCsca(certCSCA);

        } catch (CertPathValidatorException certExc) {
            SDKLogNis.log("Errore nella validazione della catena dei certificati");
            throw new Exception("Errore nella validazione della catena dei certificati");
        } catch (CertificateExpiredException certExp) {
            throw new Exception("Il documento è scaduto");
        } catch (Throwable throwable){
            throw new Exception("Il documento non è valido");
        } finally {
            if (inStreamCSCA != null) {
                inStreamCSCA.close();
            }

            SDKLogNis.log(nisAuthenticatedInfo.toString());
        }
    }
}
