import com.hintsight.n2he.Decryption;
import com.hintsight.n2he.Encryption;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.Arrays;
import java.util.Scanner;

import static com.hintsight.n2he.Utils.*;

public class Main {
    public static void main(String[] args) {

        //Security Parameters
        int polyDegree = 1024;
        long ciphertextModulus = 3_221_225_473L;
        int plaintextModulus = 6000;
        int featureLength = 512;

        System.out.println("============================================");
        System.out.println("Preparing public key and secret key...");

        Scanner scanner = null;
        String pkFilePath = "src/rlwe_pk.txt";
        try {
            scanner = new Scanner(new File(pkFilePath));
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
        scanner.useDelimiter(" ");
        long[][] publicKey = new long[2][polyDegree];
        for (int i = 0; i < 2; i++) {
            for (int j = 0; j < polyDegree; j++) {
                if (!scanner.hasNext())
                    break;
                publicKey[i][j] = Long.parseLong(scanner.next());
            }
            if (!scanner.hasNext())
                break;
            scanner.nextLine(); //to remove '\n'
        }
        scanner.close();
        System.out.println("Read in public key.");

        //read in secret key
        String skFilePath = "src/lwe_sk.txt";
        try {
            scanner = new Scanner(new File(skFilePath));
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
        scanner.useDelimiter(" ");
        long[] secretKey = new long[polyDegree];
        for (int i = 0; i < polyDegree; i++) {
            if (!scanner.hasNext())
                break;
            secretKey[i] = Long.parseLong(scanner.next());
        }
        scanner.close();
        System.out.println("Read in secret key.");
        System.out.println();


        //============================= Create Features =============================
        System.out.println("============================================");
        System.out.println("Preparing features...");

        int[] features1 = new int[featureLength];
        features1[0] = 512;
        for (int i = 0; i < 10; i++) {
            features1[i] = i + 1;
        }
        System.out.println("features1 (length 512): ");
        System.out.println(Arrays.toString(features1));
        System.out.println();

//        int[] features2 = new int[featureLength];
//        Arrays.fill(features2, 2);
//        System.out.println("features2 (length 512): ");
//        System.out.println(Arrays.toString(features2));
//        System.out.println();


        //============================= Encrypt & Decrypt Features =============================
        System.out.println("============================================");
        System.out.println("Encryption & Decryption...");

        long[][] encryptedFeatures1 = Encryption.encrypt(features1, publicKey);
        System.out.println("encrypted features1 (size 2 x 1024): ");
        System.out.println(Arrays.deepToString(encryptedFeatures1));
        System.out.println();

        long[] decryptedResult1 = Decryption.rlwe64Dec(polyDegree, ciphertextModulus, plaintextModulus,
                secretKey, encryptedFeatures1);
        System.out.println("decrypted features1 (length 512): ");
        System.out.println(Arrays.toString(decryptedResult1));
        System.out.println();

    }
}