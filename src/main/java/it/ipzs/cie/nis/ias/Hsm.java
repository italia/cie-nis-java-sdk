package it.ipzs.cie.nis.ias;

import it.ipzs.cie.nis.core.ApduResponse;
import it.ipzs.cie.nis.core.AppUtil;

public abstract class Hsm {


    protected byte[] readFile(int id) throws Exception {
        byte[] content = new byte[]{};
        byte[] selectFile = { 0x00, (byte)0xa4, 0x02, 0x04 };
        byte[] fileId = { HIBYTE(id), LOBYTE(id) };
        sendApdu(selectFile,fileId,null);
        int cnt = 0;
        int chunk = 256;
        while (true) {
            byte[] readFile = { 0x00, (byte)0xb0, HIBYTE(cnt), LOBYTE(cnt) };
            ApduResponse response = sendApdu(readFile, new byte[]{}, new byte[]{(byte)chunk});
            byte[] chn = response.getResponse();
            if (Byte.compare((byte)(response.getSwInt() >> 8) , (byte)0x6c) == 0)  {
                byte le = AppUtil.unsignedToBytes(response.getSwInt() & 0xff);
                ApduResponse respApdu = sendApdu(readFile, new byte[]{}, new byte[]{le});
                chn = respApdu.getResponse();
            }
            if (response.getSwHex().equals("9000")) {
                content = AppUtil.appendByteArray(content,chn);
                cnt += chn.length;
                chunk = 256;
            }
            else {
                if (response.getSwHex().equals("0x6282")) {
                    content = AppUtil.appendByteArray(content,chn);
                }
                else if (!response.getSwHex().equals("0x6b00")) {
                    return content;
                }
                break;
            }
        }
        return content;
    }

    protected ApduResponse sendApdu(byte[] head, byte[] data, byte[] le) throws Exception {

        byte[] apdu = {};
        byte[] curresp;
        int ds = data.length;
        if(ds > 255){
            int i=0;
            byte cla = head[0];
            while(true){
                apdu = new byte[]{};
                byte[] s = AppUtil.getSub(data,i, Math.min((data.length-i),255));
                i += s.length;
                if(i != data.length)
                    head[0] = (byte)(cla | 0x10);
                else
                    head[0] = cla;
                apdu = AppUtil.appendByteArray(apdu,head);
                apdu = AppUtil.appendByte(apdu,(byte)s.length);
                apdu = AppUtil.appendByteArray(apdu,s);
                if(le != null)
                    apdu = AppUtil.appendByteArray(apdu,le);
                ApduResponse apduResponse = transmit(apdu);
                //curresp = apduResponse.getResponse();
                if(!apduResponse.getSwHex().equals("9000"))
                    throw new Exception("Errore apdu");
                if(i == data.length){
                    return getResp(apduResponse);
                }
            }
        }else{
            if(data.length != 0){
                apdu = AppUtil.appendByteArray(apdu,head);
                apdu = AppUtil.appendByte(apdu,(byte)data.length);
                apdu = AppUtil.appendByteArray(apdu,data);
                if(le != null)
                    apdu = AppUtil.appendByteArray(apdu,le);
            }else{
                apdu = AppUtil.appendByteArray(apdu,head);
                if(le != null)
                    apdu = AppUtil.appendByteArray(apdu,le);
            }
            ApduResponse response = transmit(apdu);
            return getResp(response);
        }
    }

    private ApduResponse getResp(ApduResponse responseTmp) throws Exception {
        ApduResponse response = null;
        byte[] resp = responseTmp.getResponse();
        int sw = responseTmp.getSwInt();
        byte[] elaboraResp = new byte[]{};
        if(resp!=null && resp.length != 0)
            elaboraResp = AppUtil.appendByteArray(elaboraResp, resp);
        byte apduGetRsp[] = { (byte)0x00,(byte) 0xc0, 0x00, 0x00};
        while (true) {
            if (AppUtil.byteCompare((sw >> 8) , 0x61) == 0) {
                byte ln = (byte)(sw & 0xff);
                if(ln != 0){
                    byte[] apdu = AppUtil.appendByte(apduGetRsp,  ln );
                    response = transmit(apdu);
                    sw = response.getSwInt();
                    elaboraResp = AppUtil.appendByteArray(elaboraResp, response.getResponse());
                    return new ApduResponse(AppUtil.appendByteArray(elaboraResp,response.getSwHex().getBytes()));
                }else{
                    byte[] apdu = AppUtil.appendByte(apduGetRsp,  (byte)0x00 );
                    response = transmit(apdu);
                    sw = response.getSwInt();
                    elaboraResp = AppUtil.appendByteArray(elaboraResp, response.getResponse());
                    responseTmp = response;
                }
            }else{
                return responseTmp;

            }
        }
    }

    private byte  HIBYTE(int b){return  (byte)(b >> 8 & 0xFF);}

    private byte LOBYTE(int b){return (byte)b;}

    protected abstract ApduResponse transmit(byte[] apdu)throws Exception;


}
