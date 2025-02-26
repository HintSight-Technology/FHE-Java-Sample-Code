import com.hintsight.n2he.Decryption;
import com.hintsight.n2he.Encryption;
import com.hintsight.n2he.HEOperations;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.Arrays;
import java.util.Scanner;

import static com.hintsight.n2he.Parameters.*;
import static com.hintsight.n2he.Utils.*;

public class Main {
    public static void main(String[] args) {

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
        long[][] publicKey = new long[2][getPolydegree()];
        for (int i = 0; i < 2; i++) {
            for (int j = 0; j < getPolydegree(); j++) {
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
        long[] secretKey = new long[getPolydegree()];
        for (int i = 0; i < getPolydegree(); i++) {
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

        int[] features1 = new int[getFeatureLength()];
        features1[0] = 512;
        for (int i = 0; i < 10; i++) {
            features1[i] = i + 1;
        }
        System.out.println("features1 (length 512): ");
        System.out.println(Arrays.toString(features1));
        System.out.println();

        int[] features2 = new int[getFeatureLength()];
        Arrays.fill(features2, 2);
        System.out.println("features2 (length 512): ");
        System.out.println(Arrays.toString(features2));
        System.out.println();


        //============================= Encrypt & Decrypt Features =============================
        System.out.println("============================================");
        System.out.println("Encryption...");

        long[][] encryptedFeatures1 = Encryption.encrypt(features1, publicKey);
        System.out.println("encrypted features1 (size 2 x 1024): ");
        System.out.println(Arrays.deepToString(encryptedFeatures1));
        System.out.println();

        long[][] encryptedFeatures2 = Encryption.encrypt(features2, publicKey);
        System.out.println("encrypted features2 (size 2 x 1024): ");
        System.out.println(Arrays.deepToString(encryptedFeatures2));
        System.out.println();

        System.out.println("Homomorphic Addition...");
        long[][] encryptedSum = HEOperations.rlweAddCt(encryptedFeatures1, encryptedFeatures2, getPolydegree());

        System.out.println("encrypted sum of [features1 + features2] (size 2 x 1024): ");
        System.out.println(Arrays.deepToString(encryptedSum));
        System.out.println();

        System.out.println("Decryption...");
        long[] decryptedAdditionResult = Decryption.rlwe64Dec(getPolydegree(), getCiphertextModulus(),
                getPlaintextModulus(), secretKey, encryptedSum);
        System.out.println("decrypted addition result of [features1 + features2] (length 512): ");
        System.out.println(Arrays.toString(decryptedAdditionResult));
        System.out.println();

    }
}