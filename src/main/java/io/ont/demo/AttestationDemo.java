package io.ont.demo;

import com.github.ontio.common.Helper;
import com.github.ontio.network.exception.RpcException;
import io.ont.proof.Proof;
import io.ont.sdk.AttestationSdk;

import java.security.MessageDigest;
import java.util.*;

public class AttestationDemo {

    public static void main(String[] args) throws Exception {

        // 1.create sdk instance by wallet file
//        AttestationSdk sdk = new AttestationSdk("C:\\Users\\xxx\\wallet.dat", 0, "123456");

        // 2.create sdk instance by mnemonic codes
//        AttestationSdk sdk = new AttestationSdk("mnemonicCodes");

        // 3.create sdk instance by key store
        AttestationSdk sdk = new AttestationSdk("", "");

        // testNode:http://polaris1.ont.io:20336
        // mainNode:http://dappnode1.ont.io:20336
        sdk.initialize("http://106.75.209.209:2020/addon/attestation",
                "http://polaris2.ont.io:20336",
                "did:ont:AG7o6vm4AZ7YMvfHskui2mk2PP9nEvdy2i",
                "8",
                "0e116f28e32762a12ac999a54e416f1025a2d148");

        // get Contract address (if necessary)
//        sdk.getContractAddress();

        // confirm
//        String confirmHash = sdk.confirm();
//        System.out.println("confirmHash:" + confirmHash);

        // generate test hash with SHA256
        MessageDigest md = MessageDigest.getInstance("SHA256");
        md.update("test1".getBytes());
        String hashHex = Helper.toHexString(md.digest());
        md.update("test2".getBytes());
        String hashHex2 = Helper.toHexString(md.digest());
        md.update("test3".getBytes());
        String hashHex3 = Helper.toHexString(md.digest());

        // add attestation request
        try {
            sdk.batchAdd("1", new String[]{hashHex, hashHex2, hashHex3});
        } catch (RpcException e) {
            System.err.println(e.getMessage());
            // parse for duplicate error if necessary
            String[] dupHashes = sdk.parseDuplicateError(e);
            System.out.println(String.format("duplicated hashes: %s", Arrays.toString(dupHashes)));
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }

        Thread.sleep(30000);
        // get proof of the attestation. it may wait for 30 second
        try {
            Proof proof = sdk.getProof("1", hashHex);
            System.out.println(proof);
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }

        // trust server and verify it
        try {
            boolean result = sdk.verify("1", hashHex, true);
            System.out.println(result);
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }

//         get hashes by txHash
//        List<String> hashes = sdk.getHashesByTxHash("txHash");
//        for (String hash : hashes) {
//            System.err.println(hash);
//        }
    }
}