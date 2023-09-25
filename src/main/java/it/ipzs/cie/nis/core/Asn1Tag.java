package it.ipzs.cie.nis.core;

import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.List;

public class Asn1Tag {

    protected byte unusedBits=0;
    byte[] tag = null;
    private byte[] data;
    private List<Asn1Tag> children;
    private long startPos,endPos,constructed,childSize = 0;
    private int size;
    protected static int iterazione;


    protected Asn1Tag(Object[] objects) throws Exception {
        this.tag = new byte[objects.length];
        for(int i=0;i<objects.length;i++)
            this.tag[i] = (Byte)objects[i];
    }

    protected static  long unsignedToBytes32(int x)throws Exception {
        if(x > 0) return x;
        long res = (long)(Math.pow(2, 32)) + x;
        return res;
    }

    protected static Asn1Tag parse (ByteArrayInputStream asn, long start, long length, boolean reparse) throws Exception {
        iterazione++;
        int readPos = 0;
        ByteArrayInputStream in = asn;
        int tag = unsignedToBytes((byte) in.read());//96
        if (readPos == length)
            throw new Exception();
        List<Byte> tagVal = new ArrayList<Byte>();
        readPos++;
        tagVal.add((byte) tag);
        if (((byte) tag & 0x1f) == 0x1f) {
            // è un tag a più bytes; proseguo finchè non trovo un bit 8 a 0
            while (true) {
                if (readPos == length)
                    throw new Exception();
                tag = in.read();
                readPos++;
                tagVal.add((byte) tag);
                if ((tag & 0x80) != 0x80) {
                    // è l'ultimo byte del tag
                    break;
                }
            }
        }
        // leggo la lunghezza
        if (readPos == length)
            throw new Exception();
        long len = unsignedToBytes((byte) in.read());
        readPos++;
        if (len > unsignedToBytes((byte) 0x80)) {
            int lenlen = unsignedToBytes((byte) (len - 0x80));
            len = 0;
            for (int i = 0; i < lenlen; i++) {
                if (readPos == length)
                    throw new Exception();
                int bTmp = unsignedToBytes((byte) in.read());
                len = unsignedToBytes32((int) ((len << 8) | bTmp));
                readPos++;
            }
        }
        long size = readPos + len;
        if (size > length)
            throw new Exception("ASN1 non valido");
        if (tagVal != null && tagVal.size() == 1 && tagVal.get(0) == 0 && len == 0) {
            return null;
        }
        byte[] data = new byte[(int) len];
        in.read(data, 0, (int) len);
        ByteArrayInputStream ms = new ByteArrayInputStream(data);
        Asn1Tag newTag = new Asn1Tag(tagVal.toArray());
        newTag.setChildSize(size);
        List<Asn1Tag> childern = null;

        long parsedLen = 0;
        boolean parseSubTags = false;
        if (newTag.isTagConstructed())
            parseSubTags = true;
        else if (reparse && knownTag(newTag.getTag()) == "OCTET STRING")
            parseSubTags = true;
        else if (reparse && knownTag(newTag.tag) == "BIT STRING") {
            parseSubTags = true;
            newTag.setUnusedBits((byte) ms.read());
            parsedLen++;
        }
        if (parseSubTags) {
            childern = new ArrayList<Asn1Tag>();
            while (true) {
                Asn1Tag child = parse(ms, start + readPos + parsedLen, len - parsedLen, reparse);
                if (child != null)
                    childern.add(child);

                parsedLen += child.getChildSize();
                if (parsedLen > len) {
                    childern = null;
                    break;
                } else if (parsedLen == len) {
                    data = null;
                    break;
                }
            }
        }
        newTag.setStartPos(start);
        newTag.setEndPos(start + size);
        if (childern == null) {
            newTag.setData(data);
        } else {
            newTag.setChildren(childern);
            newTag.setConstructed(len);
        }
        return newTag;

    }


    protected  boolean isTagConstructed()throws Exception {
        return (this.getTag()[0] & 0x20) != 0;
    }



    protected static int parseLength (byte[] asn) throws Exception {
        int readPos = 0;
        ByteArrayInputStream in = new ByteArrayInputStream(asn);//6
        int tag = in.read();//96
        if (readPos == asn.length)
            throw new Exception();
        List<Byte> tagVal = new ArrayList<Byte>();
        readPos++;
        tagVal.add((byte)tag);
        if (((byte)tag & 0x1f) == 0x1f)
        {
            // è un tag a più bytes; proseguo finchè non trovo un bit 8 a 0
            while (true)
            {
                if (readPos == asn.length)
                    throw new Exception();
                tag = in.read();
                readPos++;
                tagVal.add((byte)tag);
                if ((tag & 0x80) != 0x80)
                    // è l'ultimo byte del tag
                    break;
            }
        }
        // leggo la lunghezza
        if (readPos == asn.length)
            throw new Exception();
        int len = (int)in.read();
        readPos++;
        if (len > unsignedToBytes((byte) 0x80))
        {
            int lenlen = len - 0x80;
            len = 0;
            for (int i = 0; i < lenlen; i++)
            {
                if (readPos == asn.length)
                    throw new Exception();
                len = (len << 8) | in.read();
                readPos++;
            }
        }
        int size = (int)(readPos + len);
        return (int)size;

    }

    static String knownTag(byte[] tag)throws Exception
    {
        if (tag.length == 1) {
            switch (tag[0])
            {
                case 2: return "INTEGER";
                case 3: return "BIT STRING";
                case 4: return "OCTET STRING";
                case 5: return "NULL";
                case 6: return "OBJECT IDENTIFIER";
                case 0x30: return "SEQUENCE";
                case 0x31: return "SET";
                case 12: return "UTF8 String";
                case 19: return "PrintableString";
                case 20: return "T61String";
                case 22: return "IA5String";
                case 23: return "UTCTime";
            }
        }
        return null;
    }

    public static boolean areEqual(byte[] a, byte[] b)throws Exception
    {
        if (a.length != b.length)
            return false;
        for (int i = 0; i < a.length; i++)
            if (a[i] != b[i])
                return false;

        return true;
    }
    protected int getTagRawNumber()throws Exception {
        int num = tag[0];
        for (int i = 1; i < tag.length; i++)
        {
            num = (int)(num << 8) | tag[i];
        }
        return num;
    }



    public Asn1Tag checkTag(int tagCheck) throws Exception
    {
        if (getTagRawNumber() != tagCheck)
            throw new Exception("Check del tag fallito");
        return this;
    }
    protected Asn1Tag CheckTag(byte[] tagCheck) throws Exception
    {
        if (!areEqual(tag, tagCheck))
            throw new Exception("Check del tag fallito");
        return this;
    }
    public Asn1Tag child(int tagNum)throws Exception
    {
        return children.get(tagNum);
    }
    public Asn1Tag Child(int tagNum, byte tagCheck) throws Exception
    {
        Asn1Tag tag = children.get(tagNum);
        if (tag.getTagRawNumber()!=tagCheck)
            throw new Exception("Check del tag fallito");
        return tag;
    }
    protected Asn1Tag Child(int tagNum, byte[] tagCheck) throws Exception
    {
        Asn1Tag subTag = children.get(tagNum);
        if (!areEqual(subTag.tag, tagCheck))
            throw new Exception("Check del tag fallito");
        return subTag;
    }
    public Asn1Tag ChildWhitTagID(byte[] tag)throws Exception {
        for(Asn1Tag subTag :children) {
            if (areEqual(subTag.tag, tag))
                return subTag;
        }
        return null;
    }
    public void verify(byte[] dataCheck) throws Exception {
        if (!areEqual(data, dataCheck))
            throw new Exception("Check del contenuto fallito");
    }
    protected byte[] getTag() {
        return tag;
    }


    protected static  int unsignedToBytes(byte b)throws Exception {
        return b & 0xFF;
    }

    public static Asn1Tag parse(byte[] efCom, boolean reparse) throws Exception {
        int size = 0;
        ByteArrayInputStream in = new ByteArrayInputStream(efCom);
        return parse(in, size, efCom.length, reparse);
    }
    public byte[] getData() {
        if(data != null){
            return data;
        }
       /*
       else{
           for(it.ipzs.sdk.core.Asn1Tag tag : children){
               ByteArrayOutputStream buffer = new ByteArrayOutputStream();
               buffer.write();
               tag.encode(it.ipzs.sdk.core.Asn1Tag.in);
           }
           return in;
       }*/
        return null;
    }

    protected void setTag(byte[] tag)throws Exception {
        this.tag = tag;
    }

    protected static String bytesToHex (byte[] bytes)throws Exception {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (int i=0; i< bytes.length; i++) {
            sb.append(String.format("%02x", bytes[i]));
        }

        return sb.toString();
    }




    protected long getChildSize() {
        return childSize;
    }





    protected byte getUnusedBits() {
        return unusedBits;
    }





    protected void setUnusedBits(byte unusedBits) {
        this.unusedBits = unusedBits;
    }





    public long getStartPos() {
        return startPos;
    }





    protected void setStartPos(long startPos) {
        this.startPos = startPos;
    }





    public long getEndPos() {
        return endPos;
    }





    protected void setEndPos(long endPos) {
        this.endPos = endPos;
    }





    protected long getConstructed() {
        return constructed;
    }





    protected void setConstructed(long constructed) {
        this.constructed = constructed;
    }





    protected int getSize() {
        return size;
    }





    protected void setSize(int size) {
        this.size = size;
    }





    protected void setData(byte[] data) {
        this.data = data;
    }





    protected void setChildren(List<Asn1Tag> children) {
        this.children = children;
    }





    protected void setChildSize(long childSize) {
        this.childSize = childSize;
    }





    public List<Asn1Tag> getChildren() {
        return children;
    }




}
