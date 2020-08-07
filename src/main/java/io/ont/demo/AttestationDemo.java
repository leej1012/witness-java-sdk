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
//        AttestationSdk sdk = new AttestationSdk("brother cube work silk eagle arrange minute eyebrow episode defense agree title");
        AttestationSdk sdk = new AttestationSdk("mnemonicCodes");

        // 3.create sdk instance by key store
//        AttestationSdk sdk = new AttestationSdk("{\"scrypt\":{\"dkLen\":64,\"n\":16384,\"p\":8,\"r\":8},\"address\":\"AXVvpDHbVhFBLMos2H5ZcA3yEYYx5Q8kSW\",\"key\":\"ea5vQNxYqRx0yya8y6qkdmX/W38I98qXOAJHV0E/84kUqD1pJsPprz1AFSlmuWEf\",\"label\":\"leeMain\",\"type\":\"I\",\"algorithm\":\"ECDSA\",\"salt\":\"qvBeCxzfL3/mPPT9WTOQ9A==\",\"parameters\":{\"curve\":\"P-256\"}}", "123456");

        // testNode:http://polaris1.ont.io:20336
        // mainNode:http://dappnode1.ont.io:20336
        sdk.initialize("http://172.168.3.46:2020/addon/attestation",
                "http://polaris2.ont.io:20336",
                "did:ont:AYKUPMjmfZhqGFb4nNjTFd4oqbtHe2dmyY",
                "15",
                "f0d888088b4d968f250737f6ea656abc38c77ce4");

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
        List<String> hashes = sdk.getHashesByTxHash("txHash");
        for (String hash : hashes) {
            System.err.println(hash);
        }
    }
}