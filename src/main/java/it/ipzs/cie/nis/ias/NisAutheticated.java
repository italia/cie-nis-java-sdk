package it.ipzs.cie.nis.ias;

public class NisAutheticated {

    private String nis;
    private String haskKpubIntServ;

    public NisAutheticated(String nis, String haskKpubIntServ){
        this.nis = nis;
        this.haskKpubIntServ = haskKpubIntServ;
    }

    public String getNis() {
        return nis;
    }

    public String getHaskKpubIntServ() {
        return haskKpubIntServ;
    }

    @Override
    public String toString() {
        return "NisAutheticated{" +
                "nis='" + nis + '\'' +
                ", haskKpubIntServ=" + haskKpubIntServ +
                '}';
    }
}
