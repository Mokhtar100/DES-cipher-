/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package des;

import static des.Des.generateKeys;
import static des.Des.toBinary;
import static des.desDecrypt.decrypt;
import static des.desEncrypt.encrypt;

/**
 *
 * @author DELL PRECISION 5530
 */
public class MainTest {
    
      public static void main(String[] args) {
 String key = "133457799BBCDFF1"; // Example decimal key
//
//    // Generate subkeys
    String[] keys = generateKeys(toBinary(key));
////
// for (int i = 0; i < 16; i++) {
//            System.out.println("K" + (i + 1) + ": " + keys[i]);
//      }

//    // Message to be encrypted
    String msg = "0123456789ABCDEF";
//
//    // Initial permutation of the message
//    String msgBinary = msgToBinary(msg);
//
//    // Split the initial permutation into L0 and R0
//    String[] lr = splitLR(msgBinary);
//    String LnMinus1 = lr[0];
//    String RnMinus1 = lr[1];
//
//    // Output L0 and R0
//    System.out.println("L0: " + LnMinus1);
//    System.out.println("R0: " + RnMinus1);
//
//    // Iterate through the 16 rounds of DES
////    for (int n = 0; n < 16; n++) {
////        // Calculate Rn = Ln-1 + f(Rn-1, Kn)
////        String fResult = functionF(RnMinus1, keys[n]);
////        String Rn = xor(LnMinus1, fResult);
////
////        // Output Ln and Rn for this iteration
////        System.out.println("Iteration " + (n + 1) + ":");
////        System.out.println("Ln: " + RnMinus1);
////        System.out.println("Rn: " + Rn);
////
////        // Prepare for the next iteration
////        LnMinus1 = RnMinus1;
////        RnMinus1 = Rn;
////    }
//
      System.out.println("Encrypted Message: " +encrypt(msg,keys));
  

      
//  String ciphertext = "85E813540F0AB405"; // Example ciphertext
//
//    // Check if the ciphertext is in hexadecimal format
//    if (!ciphertext.matches("[0-9A-Fa-f]+")) {
//        System.out.println("Ciphertext is not in hexadecimal format. Converting to hexadecimal...");
//        // Convert binary ciphertext to hexadecimal
//        ciphertext = bin2hex(ciphertext);
//    }
//
//    // Decrypt the ciphertext
//    String decryptedMessage = decrypt(hex2bin(ciphertext), key);
//
//    // Output the decrypted message
//    System.out.println("Decrypted Message: " + decryptedMessage);}
//String key = "133457799BBCDFF1"; // Example decimal key
        String ciphertext = "85E813540F0AB405"; // Example ciphertext

        // Decrypt the ciphertext
       //String decryptedMessage = decrypt(ciphertext, key);

        // Output the decrypted message
      // System.out.println("Decrypted Message: " + decryptedMessage);
     //  String[] keyss = generateKeys(toBinary(key));

        // Perform initial permutation on ciphertext
        
       // String permutedCiphertext = initialPermutation(hex2bin(ciphertext));

        // Split permuted ciphertext into left and right halves
        //String L = hex2bin(ciphertext).substring(0, 32);
        //String R = hex2bin(ciphertext).substring(32);

        // Iterate through the 16 rounds of decryption
//        for (int n = 15; n >= 0; n--) {
//            // Calculate L(n-1) = Rn
//            String LnMinus1 = Rn;
//
//            // Calculate R(n-1) = Ln xor f(Rn, Kn)
//            String fResult = functionF(Rn, keyss[n]);
//            Rn = xor(Ln, fResult);
//
//            // Set Ln for the next iteration
//            Ln = LnMinus1;
//        }
    String decryptedMessage = decrypt(ciphertext, key);

    // Output the decrypted message
    System.out.println("Decrypted Message: " + decryptedMessage);
    
    //        //System.out.println("Hexadecimal key: " + hexKey);
//        System.out.println("K+ " + toBinary(key));
//        System.out.println("K+ " + toBinary(key).length());
//        String[] halves = splitIntoHalves( toBinary(key));
//        System.out.println("\nLeft half (C0): " + halves[0]);
//        System.out.println("Right half (D0): " + halves[1]);
//        
//String[][] blocks = generateBlocks(toBinary(key));
//        for (int i = 0; i < 16; i++) {
//           // System.out.println("\nIteration " + (i + 1) + ":");
//            System.out.println("C" + (i + 1) + ": " + blocks[0][i]);
//            System.out.println("D" + (i + 1) + ": " + blocks[1][i]);
//        }
//
//         String[] keys = generateKeys(toBinary(key));
//        for (int i = 0; i < 16; i++) {
//            System.out.println("K" + (i + 1) + ": " + keys[i]);
//        }
//        
//        String msg="0123456789ABCDEF";
//        System.out.println("msg " + msgToBinary(msg));
//        
//        ///System.out.println("\nDecimal key: " + decimalKey);
//        
//        
//        String[] lr = splitLR(msgToBinary(msg));
//  System.out.println("(L0): " + lr[0]);
//  System.out.println("(R0): " + lr[1]);
//     
//  
//        String LnMinus1 = lr[1];
//        String RnMinus1 = lr[1];
//  
//     
//        System.out.println(expansion(lr[0]));
//        System.out.println(expansion(lr[1]));
//  
//  
//  
// for (int n = 0; n < 16; n++) {
//    // Calculate Rn = Ln-1 + f(Rn-1, Kn)
//    String fResult = functionF(RnMinus1, keys[n]); // Note: index n for key
//    String Rn = xor(LnMinus1, fResult);
//
//    // Prepare for the next iteration
//    LnMinus1 = RnMinus1;
//    RnMinus1 = Rn;
//
//    // Output the result for this iteration
//    System.out.println("Iteration " + (n + 1) + ": L" + (n + 1) + " = " + LnMinus1 + ", R" + (n + 1) + " = " + RnMinus1);
//}
//  
// 
    
}
    
}
