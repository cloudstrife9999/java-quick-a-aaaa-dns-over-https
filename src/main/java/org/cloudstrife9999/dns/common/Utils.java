package org.cloudstrife9999.dns.common;

public class Utils {

    private Utils(){}

    public static int twoBytesToUnsignedInt(byte[] bytes) {
        if(bytes.length == 2) {
            return Utils.twoBytesToInt(bytes[0], bytes[1]);
        }
        else {
            throw new IllegalArgumentException("There must be exactly 2 bytes for an unsigned short tobe produced.");
        }
    }

    public static byte[] unsignedIntToTwoBytes(int n) {
        if(n >= 0 && n <= 0xFFFF) {
            return new byte[]{(byte)((n >> 8) & 0xFF), (byte)(n & 0xFF)};
        }
        else {
            throw new IllegalArgumentException("Only numbers >= 0 and <= 65535 can fit in 2 unsigned bytes.");
        }
    }

    public static int singleByteToUnsignedInt(byte b) {
        return b & 0xFF;
    }

    public static byte unsignedIntToSingleByte(int n) {
        if(n >= 0 && n <= 0xFF) {
            return (byte)(n & 0xFF);
        }
        else {
            throw new IllegalArgumentException("Only numbers >= 0 and <= 15 can fit in 2 unsigned bytes.");
        }
    }

    private static int twoBytesToInt(byte high, byte low) {
        return ((high & 0xFF) << 8) | (low & 0xFF);
    }

    public static int fourBytesToUnsignedInt(byte[] bytes) {
        if(bytes.length != 4) {
            throw new IllegalArgumentException("The length of the byte array must be 4.");
        }

        return ((bytes[0] & 0xFF) << 24) | ((bytes[1] & 0xFF) << 16) | ((bytes[2] & 0xFF) << 8) | (bytes[3] & 0xFF);
    }

    public static byte[] toPrimitive(Byte[] bytes) {
        byte[] toReturn = new byte[bytes.length];

        System.arraycopy(bytes, 0, toReturn, 0, bytes.length);

        return toReturn;
    }

    public static void printByteArray(byte[] bytes) {
        StringBuilder builder = new StringBuilder();

        for(int i=0; i<bytes.length; i++) {
            builder.append(String.format("%02X", bytes[i]));
            
            if(i > 0 && (i+1) % 16 == 0) {
                builder.append("\n");
            }
            else if (i> 0 && (i+1) % 8 == 0) {
                builder.append("  ");
            }
            else {
                builder.append(" ");
            }
        }

        System.out.println(builder.toString());
    }
}
