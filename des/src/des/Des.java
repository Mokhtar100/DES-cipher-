/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package des;

import static des.desDecrypt.decrypt;
import static des.desEncrypt.encrypt;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author DELL PRECISION 5530
 */
public class Des {

    private static final int[][][] S_BOXES = {
        {
            // S1
            {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
            {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
            {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
            {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
        },
        {
            // S2
            {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
            {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
            {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
            {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
        },
        // S3

        {
            {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
            {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
            {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
            {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}

        },
        //S4

        {
            {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
            {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
            {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
            {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}

        },
        // S5

        {
            {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
            {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
            {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
            {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}

        },
        //S6
        {
            {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
            {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
            {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
            {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}

        },
        //S7
        {
            {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
            {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
            {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
            {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}

        },
        //S8
        {
            {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
            {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
            {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
            {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}

        }

    };

    ////////////////////Step 1: Create 16 subkeys, each of which is 48­bits long///////////////////////////////////////////
    public static String toBinary(String key) {

        if (key.matches("\\d+")) {

            long decimalKey = Long.parseLong(key);
            String decimal = String.format("%64s", Long.toBinaryString(decimalKey)).replace(' ', '0');
            return permuteKey(decimal);
        } else if (key.matches("^[0-9A-Fa-f]+$")) {

            long decimalKey = Long.parseLong(key, 16);
            String hexa = String.format("%64s", Long.toBinaryString(decimalKey)).replace(' ', '0');

            return permuteKey(hexa);
        } else {
            return "Invalid input format. Please provide either hexadecimal or decimal input.";
        }
    }

    public static String permuteKey(String key) {
        StringBuilder permutedKey = new StringBuilder();
        int[] pc1 = {
            57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4
        };
        for (int index : pc1) {

            permutedKey.append(key.charAt(index - 1));
        }

        return permutedKey.toString();
    }

    public static String[] splitIntoHalves(String permutedKey) {
        String[] halves = new String[2];
        halves[0] = permutedKey.substring(0, 28); // Left half
        halves[1] = permutedKey.substring(28);    // Right half
        return halves;
    }

    public static String[][] generateBlocks(String permutedKey) {
        String[][] blocks = new String[2][16];
        String[] halves = splitIntoHalves(permutedKey);

        String Cn = halves[0];
        String Dn = halves[1];

        int[] leftShifts = {
            1, 1, 2, 2, 2, 2, 2, 2,
            1, 2, 2, 2, 2, 2, 2, 1
        };

        for (int i = 0; i < 16; i++) {

            Cn = leftShift(Cn, leftShifts[i]);
            Dn = leftShift(Dn, leftShifts[i]);

            blocks[0][i] = Cn;
            blocks[1][i] = Dn;
        }

        return blocks;
    }

    private static String leftShift(String str, int places) {
        return str.substring(places) + str.substring(0, places);
    }

    public static String[] generateKeys(String permutedKey) {
        String[] keys = new String[16];
        String[] blocks = new String[16];

        String[][] CDblocks = generateBlocks(permutedKey);

        int[] pc2 = {
            14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
        };

        for (int i = 0; i < 16; i++) {

            blocks[i] = CDblocks[0][i] + CDblocks[1][i];
            keys[i] = permuteKey(blocks[i], pc2);
        }

        return keys;
    }

    private static String permuteKey(String key, int[] permutationTable) {
        StringBuilder permutedKey = new StringBuilder();

        for (int index : permutationTable) {

            permutedKey.append(key.charAt(index - 1));
        }

        return permutedKey.toString();
    }

///////////////Step 2: Encode each 64­bit block of data.////////////////////////////////////
    public static String msgToBinary(String msg) {

        long decimalmsg = Long.parseLong(msg, 16);
        String bimsg = String.format("%64s", Long.toBinaryString(decimalmsg)).replace(' ', '0');
        return initialPermutation(bimsg);

    }

    public static String initialPermutation(String message) {
        // Check if the message is a valid 64-bit binary string
        if (message.length() != 64 || !message.matches("[01]+")) {
            throw new IllegalArgumentException("Message must be a 64-bit binary string");
        }

        StringBuilder permutedMessage = new StringBuilder();
        int[] ip = {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
        };
        for (int index : ip) {
            permutedMessage.append(message.charAt(index - 1));
        }

        return permutedMessage.toString();
    }

    public static String[] splitLR(String permutedMessage) {

        String L = permutedMessage.substring(0, 32);
        String R = permutedMessage.substring(32);

        return new String[]{L, R};
    }

    public static String expansion(String RnMinus1) {
        StringBuilder expandedRnMinus1 = new StringBuilder();
        int[] E_TABLE = {
            32, 1, 2, 3, 4, 5, 4, 5,
            6, 7, 8, 9, 8, 9, 10, 11,
            12, 13, 12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21, 20, 21,
            22, 23, 24, 25, 24, 25, 26, 27,
            28, 29, 28, 29, 30, 31, 32, 1
        };
        for (int index : E_TABLE) {
            expandedRnMinus1.append(RnMinus1.charAt(index - 1));
        }
        return expandedRnMinus1.toString();
    }

    public static String xor(String a, String b) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < a.length(); i++) {
            result.append(a.charAt(i) == b.charAt(i) ? '0' : '1');
        }
        return result.toString();
    }

    public static String functionF(String RnMinus1, String Kn) {

        String expandedRnMinus1 = expansion(RnMinus1);

        String xorResult = xor(expandedRnMinus1, Kn);

        //  S-boxes
        StringBuilder sBoxResult = new StringBuilder();
        for (int i = 0; i < 8; i++) {

            String block = xorResult.substring(i * 6, (i + 1) * 6);

            int row = Integer.parseInt(block.substring(0, 1) + block.substring(5, 6), 2);
            int col = Integer.parseInt(block.substring(1, 5), 2);

            int sBoxValue = S_BOXES[i][row][col];

            sBoxResult.append(String.format("%4s", Integer.toBinaryString(sBoxValue)).replace(' ', '0'));
        }

        String fResult = permutationP(sBoxResult.toString());

        return fResult;
    }

    public static String permutationP(String input) {
        StringBuilder permutedInput = new StringBuilder();
        int[] P_TABLE = {
            16, 7, 20, 21, 29, 12, 28, 17,
            1, 15, 23, 26, 5, 18, 31, 10,
            2, 8, 24, 14, 32, 27, 3, 9,
            19, 13, 30, 6, 22, 11, 4, 25
        };
        for (int index : P_TABLE) {
            permutedInput.append(input.charAt(index - 1));
        }
        return permutedInput.toString();
    }

    public static String bin2hex(String s) {
        Map<String, Character> binToHex = new HashMap<>();
        binToHex.put("0000", '0');
        binToHex.put("0001", '1');
        binToHex.put("0010", '2');
        binToHex.put("0011", '3');
        binToHex.put("0100", '4');
        binToHex.put("0101", '5');
        binToHex.put("0110", '6');
        binToHex.put("0111", '7');
        binToHex.put("1000", '8');
        binToHex.put("1001", '9');
        binToHex.put("1010", 'A');
        binToHex.put("1011", 'B');
        binToHex.put("1100", 'C');
        binToHex.put("1101", 'D');
        binToHex.put("1110", 'E');
        binToHex.put("1111", 'F');
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < s.length(); i += 4) {
            String ch = s.substring(i, i + 4);
            hex.append(binToHex.get(ch));
        }

        return hex.toString();
    }

    public static String hex2bin(String hexString) {
        Map<Character, String> hexToBinMap = new HashMap<>();
        hexToBinMap.put('0', "0000");
        hexToBinMap.put('1', "0001");
        hexToBinMap.put('2', "0010");
        hexToBinMap.put('3', "0011");
        hexToBinMap.put('4', "0100");
        hexToBinMap.put('5', "0101");
        hexToBinMap.put('6', "0110");
        hexToBinMap.put('7', "0111");
        hexToBinMap.put('8', "1000");
        hexToBinMap.put('9', "1001");
        hexToBinMap.put('A', "1010");
        hexToBinMap.put('B', "1011");
        hexToBinMap.put('C', "1100");
        hexToBinMap.put('D', "1101");
        hexToBinMap.put('E', "1110");
        hexToBinMap.put('F', "1111");

        StringBuilder binaryString = new StringBuilder();
        for (char ch : hexString.toUpperCase().toCharArray()) {
            if (!hexToBinMap.containsKey(ch)) {
                throw new IllegalArgumentException("Invalid hex character: " + ch);
            }
            binaryString.append(hexToBinMap.get(ch));
        }

        return binaryString.toString();
    }

}
