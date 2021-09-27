package it.ipzs.cie.nis.ias;

public interface NisSdkCallback {
    void onSuccess(NisAutheticated nisAutheticated);
    void onError(Exception error);
}
