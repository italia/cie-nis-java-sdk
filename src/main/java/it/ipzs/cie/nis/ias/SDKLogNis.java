package it.ipzs.cie.nis.ias;

public class SDKLogNis {

    public static boolean logEnabled = false;
    private static final String TAG = "[SDK-NIS-JAVA]";

    public static void log(String msg){
        if(logEnabled)
            System.out.println(TAG+ msg);
    }


}
