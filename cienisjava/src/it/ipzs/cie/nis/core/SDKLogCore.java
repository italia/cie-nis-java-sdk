package it.ipzs.cie.nis.core;

public class SDKLogCore {
    public static boolean logEnabled = false;
    private static String TAG = "[SDK-CORE-JAVA]";
    public static void log(String msg){
        if(logEnabled)
            System.out.println(TAG+ msg);
    }


}
