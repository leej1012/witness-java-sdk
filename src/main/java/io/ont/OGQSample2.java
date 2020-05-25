package io.ont;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.github.ontio.OntSdk;
import com.github.ontio.account.Account;
import com.github.ontio.common.ErrorCode;
import com.github.ontio.common.Helper;
import com.github.ontio.common.UInt256;
import com.github.ontio.core.payload.InvokeWasmCode;
import com.github.ontio.core.scripts.WasmScriptBuilder;
import com.github.ontio.core.transaction.Attribute;
import com.github.ontio.io.BinaryReader;
import com.github.ontio.merkle.MerkleVerifier;
import com.github.ontio.network.exception.RpcException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.MessageDigest;
import java.util.*;

public class OGQSample2 {

    public enum Error {
        SUCCESS(0),
        INVALID_PARAM(41001),
        ADDHASH_FAILED(41002),
        VERIFY_FAILED(41003),
        NODE_OUTSERVICE(41004),
        NO_AUTH(41005);

        private int code;

        Error(int code) {
            this.code = code;
        }

        public int getCode() {
            return code;
        }
    }

    class addonRpc {
        private final URL url;
        private String addonId, tenantId;
        public String JSON_RPC_VERSION = "2.0";

        public addonRpc(String url, String addonId, String tenantId) throws MalformedURLException {
            this.url = new URL(url);
            this.addonId = addonId;
            this.tenantId = tenantId;
        }

        public String getHost() {
            return url.getHost() + " " + url.getPort();
        }

        public Object call(String id, String method, Object params) throws RpcException, IOException {
            Map request = new HashMap();
            request.put("jsonrpc", JSON_RPC_VERSION);
            request.put("method", method);
            request.put("params", params);
            request.put("id", id);
//            System.out.println(String.format("POST url=%s, body=%s", this.url, JSON.toJSONString(request)));

            Map response = (Map) send(request);
            if (response == null) {
                throw new RpcException(0, ErrorCode.ConnectUrlErr(url + " response is null. maybe is connect error"));
            } else if ((int) response.get("error") == 0) {
                return response.get("result");
            } else {
                throw new RpcException(0, JSON.toJSONString(response));
            }
        }

        public Object send(Object request) throws IOException {
            try {
                HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                connection.setRequestMethod("POST");
                connection.setRequestProperty("addonID", addonId);
                connection.setRequestProperty("tenantID", tenantId);
                connection.setDoOutput(true);
                try (OutputStreamWriter w = new OutputStreamWriter(connection.getOutputStream())) {
                    w.write(JSON.toJSONString(request));
                }
                try (InputStreamReader r = new InputStreamReader(connection.getInputStream())) {
                    StringBuffer temp = new StringBuffer();
                    int c = 0;
                    while ((c = r.read()) != -1) {
                        temp.append((char) c);
                    }
//                    System.out.println("result: " + temp.toString());
                    return JSON.parseObject(temp.toString(), Map.class);
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
            return null;
        }
    }

    class Proof {
        private UInt256 root;
        private int size, blockheight, index;
        private UInt256[] proof;

        public Proof(UInt256 root, int size, int blockheight, int index, UInt256[] proof) {
            this.root = root;
            this.size = size;
            this.blockheight = blockheight;
            this.index = index;
            this.proof = proof;
        }

        public UInt256 getRoot() {
            return root;
        }

        public int getSize() {
            return size;
        }

        public int getBlockHeight() {
            return blockheight;
        }

        public int getIndex() {
            return index;
        }

        public UInt256[] getProof() {
            return proof;
        }

        @Override
        public String toString() {
            return String.format("block height: %d, size: %d, index: %d, root: %s, proof: %s", blockheight, size, index, root, Arrays.toString(proof));
        }
    }

    public static String ATTESTATION_ADDON_ID = "19";

    private OntSdk ontSdk;
    private Account account;
    private addonRpc rpc;

    public OGQSample2(String filePath, String address, String password) throws Exception {
        ontSdk = OntSdk.getInstance();
        ontSdk.openWalletFile(filePath);
        account = ontSdk.getWalletMgr().getAccount(address, password);
    }

    public OGQSample2(String filePath, int index, String password) throws Exception {
        ontSdk = OntSdk.getInstance();
        ontSdk.openWalletFile(filePath);
        String address = ontSdk.getWalletMgr().getWallet().getAccounts().get(index).address;
        account = ontSdk.getWalletMgr().getAccount(address, password);
    }

    public void initialize(String rpcUrl, String chainNodeUrl, String tenantId) throws Exception {
        rpc = new addonRpc(rpcUrl, ATTESTATION_ADDON_ID, tenantId);
        ontSdk.setRpc(chainNodeUrl);
        ontSdk.setDefaultConnect(ontSdk.getRpc());
    }

    protected Object call(String id, String method, String[] hashes) throws Exception {
        return call(id, method, hashes, false);
    }

    protected Object call(String id, String method, String[] hashes, boolean sign) throws Exception {
        if (null == rpc) throw new NullPointerException("rpc has not been initialized, please check");

        Map params = new HashMap();
        params.put("pubKey", Helper.toHexString(account.serializePublicKey()));
        params.put("hashes", hashes);
        if (sign) {
            StringBuilder stringBuilder = new StringBuilder();
            for (String s : hashes) {
                stringBuilder.append(s);
            }
            params.put("signature", Helper.toHexString(account.generateSignature(Helper.hexToBytes(stringBuilder.toString()), account.getSignatureScheme(), null)));
        }
        return rpc.call(id, method, params);
    }

    public String batchAdd(String id, String[] hashes) throws Exception {
        Object result = call(id, "batchAdd", hashes, true);
        System.out.println(result);
        try {
            return (String) result;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    protected Proof getProof(String id, String hash) throws Exception {
        JSONObject result = (JSONObject) call(id, "verify", new String[]{hash});
        try {
            List<UInt256> proofs = new ArrayList<>();
            for (Object s : (JSONArray) result.get("proof")) {
                proofs.add(new UInt256(Helper.hexToBytes((String) s)));
            }
            UInt256[] ps = new UInt256[proofs.size()];
            proofs.toArray(ps);
            Proof proof = this.new Proof(new UInt256(Helper.hexToBytes((String) result.get("root"))),
                    (int) result.get("size"), (int) result.get("blockheight"), (int) result.get("index"), ps
            );
            return proof;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public boolean verify(String id, String hash, boolean verifyBlock) throws Exception {
        Proof proof = getProof(id, hash);
        return verify(proof, hash, verifyBlock);
    }

    private boolean verifyBlock(Proof proof) throws Exception {
        for (Object o : (JSONArray) ontSdk.getConnect().getSmartCodeEvent(proof.blockheight)) {
            try {
                for (Object nObj : (JSONArray) ((Map) o).get("Notify")) {
                    Map m = (Map) nObj;
                    if (!CONTRACT_ADDRESS.equals(m.get("ContractAddress"))) continue;
                    JSONArray state = (JSONArray) m.get("States");
                    if (proof.root.toHexString().equals(state.getString(0)) && Integer.toString(proof.size).equals(state.getString(1))) {
                        return true;
                    }
                }
            } catch (Exception e) {
            }
        }
        return false;
    }

    public boolean verify(Proof proof, String hash, boolean verifyBlock) throws Exception {
        MerkleVerifier verifier = new MerkleVerifier();
        boolean result = verifier.VerifyLeafHashInclusion(new UInt256(Helper.hexToBytes(hash)), proof.index, proof.proof, proof.root, proof.size);
        return verifyBlock ? (result && verifyBlock(proof)) : result;
    }

    public String[] parseDuplicateError(RpcException e) {
        Map err = (Map) JSON.parseObject(e.getMessage(), Map.class);
        if (Error.ADDHASH_FAILED.getCode() != (int) err.get("error")) return null;
        if (!"ADDHASH_FAILED: duplicate hash leafs. please check.".equals(err.get("desc"))) return null;

        List<String> duplicatedHashes = new ArrayList<>();
        for (Object hash : (JSONArray) err.get("result")) {
            duplicatedHashes.add((String) hash);
        }
        String[] hashes = new String[duplicatedHashes.size()];
        duplicatedHashes.toArray(hashes);
        return hashes;
    }

    // the contract will be updated accordingly
    public static String CONTRACT_ADDRESS = "a1586ac9d2d3d66cb93a4bb6a7c29291b8fbc1d9";

    public static void main(String[] args) throws Exception {

//        OGQSample2 sample = new OGQSample2("ogq.dat", 0, "123456");
        OGQSample2 sample = new OGQSample2("wallet.dat",
                0, "abc123");
//        sample.initialize("https://attestation.ont.io", "http://polaris1.ont.io:20336");
        sample.initialize("http://107.150.112.175:2020/addon/attestation", "http://polaris1.ont.io:20336", "did:ont:Ad2enBhzZpvpxsqjKjP3qT9NhxhY4XneRd");

        // confirm
        String confirmHash = sample.confirm();
        System.out.println("confirmHash:" + confirmHash);

        // generate test hash with SHA256
        MessageDigest md = MessageDigest.getInstance("SHA256");
        md.update("test".getBytes());
        String hashHex = Helper.toHexString(md.digest());
        md.update("test2".getBytes());
        String hashHex2 = Helper.toHexString(md.digest());
        md.update("test3".getBytes());
        String hashHex3 = Helper.toHexString(md.digest());

        System.out.println("hashHex:" + hashHex);
        // add attestation request
        try {
        sample.batchAdd("1", new String[]{hashHex, hashHex2, hashHex3});
        } catch (RpcException e) {
            System.err.println(e.getMessage());

            // parse for duplicate error if necessary
            String[] dupHashes = sample.parseDuplicateError(e);
            System.out.println(String.format("duplicated hashes: %s", Arrays.toString(dupHashes)));
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }

        // get proof of the attestation
        try {
            Proof proof = sample.getProof("1", hashHex);
            System.out.println(proof);
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }

        // trust server and verify it
        try {
            boolean result = sample.verify("1", hashHex, true);
            System.out.println(result);
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }

//         get hashes by txHash
        List<String> hashes = sample.getHashes("9ab547042e3dcba2dbe206374ca87925a5a4dc806eb8725110b76e767c2f6d9e");
    }

    public List<String> getHashes(String hash) throws Exception {
        InvokeWasmCode transaction = (InvokeWasmCode) ontSdk.getConnect().getTransaction(hash);

        BinaryReader reader = new BinaryReader(new ByteArrayInputStream(transaction.invokeCode));
        byte[] contractBytes = reader.readBytes(20);
        String contractStr = Helper.toHexString(contractBytes);
        System.out.println("contract address:" + contractStr);
        byte[] paramBytes = reader.readVarBytes();
        BinaryReader paramReader = new BinaryReader(new ByteArrayInputStream(paramBytes));
        byte[] method = paramReader.readVarBytes();
        String methodStr = new String(method);
        System.out.println("method:" + methodStr);
        long l = paramReader.readVarInt();
        System.out.println("hash size:" + l);
        List<String> hashList = new ArrayList<>();
        for (int i = 0; i < l; i++) {
            byte[] bytes = paramReader.readBytes(32);
            String s = Helper.toHexString(bytes);
            System.out.println("hash:" + s);
            hashList.add(s);
        }
        return hashList;
    }

    // Confirmation of rights
    private String confirm() throws Exception {
        // get contract address
        CONTRACT_ADDRESS = (String) rpc.call("1", "GetContractAddress", null);
        // construct transaction
        List<Object> params = new ArrayList<>();
        byte[] invokeCode = WasmScriptBuilder.createWasmInvokeCode(CONTRACT_ADDRESS, "verifySignature", params);
        InvokeWasmCode tx = new InvokeWasmCode(invokeCode);
        tx.payer = account.getAddressU160();
        tx.gasLimit = 20000L;
        tx.gasPrice = 500;
        tx.attributes = new Attribute[0];
        tx.nonce = (new Random()).nextInt();
        ontSdk.addSign(tx, account);
        ontSdk.getConnect().sendRawTransaction(tx);
        return tx.hash().toString();
    }

    // get root
    private Map<String, Object> getRoot() throws Exception {
        HashMap<String, Object> getRoot = (HashMap<String, Object>) rpc.call("1", "getRoot", null);
        return getRoot;
    }

}