package io.ont.sdk;

import com.alibaba.fastjson.util.Base64;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.github.ontio.OntSdk;
import com.github.ontio.account.Account;
import com.github.ontio.common.Helper;
import com.github.ontio.common.UInt256;
import com.github.ontio.core.payload.InvokeWasmCode;
import com.github.ontio.core.scripts.WasmScriptBuilder;
import com.github.ontio.core.transaction.Attribute;
import com.github.ontio.crypto.MnemonicCode;
import com.github.ontio.crypto.SignatureScheme;
import com.github.ontio.io.BinaryReader;
import com.github.ontio.merkle.MerkleVerifier;
import com.github.ontio.network.exception.RpcException;
import io.ont.error.AttestationError;
import io.ont.rpc.AddonRpc;
import io.ont.proof.Proof;

import java.io.ByteArrayInputStream;
import java.util.*;

public class AttestationSdk {

    private OntSdk ontSdk;
    private Account account;
    private AddonRpc rpc;
    public String contractAddress;

    public AttestationSdk(String filePath, String address, String password) throws Exception {
        ontSdk = OntSdk.getInstance();
        ontSdk.openWalletFile(filePath);
        account = ontSdk.getWalletMgr().getAccount(address, password);
    }

    public AttestationSdk(String mnemonicCodes) throws Exception {
        ontSdk = OntSdk.getInstance();
        byte[] privateKeyFromMnemonicCodes = getPrivateKeyFromMnemonicCodes(mnemonicCodes);
        account = new Account(privateKeyFromMnemonicCodes, SignatureScheme.SHA256WITHECDSA);
    }

    public AttestationSdk(String keyStore, String password) throws Exception {
        ontSdk = OntSdk.getInstance();
        String keystore = keyStore.replace("\\", "");
        JSONObject jsonObject = JSON.parseObject(keystore);
        String key = jsonObject.getString("key");
        String address = jsonObject.getString("address");
        String saltStr = jsonObject.getString("salt");

        int scrypt = jsonObject.getJSONObject("scrypt").getIntValue("n");
        String privateKey = Account.getGcmDecodedPrivateKey(key, password, address, Base64.decodeFast(saltStr), scrypt, SignatureScheme.SHA256WITHECDSA);
        account = new Account(Helper.hexToBytes(privateKey), SignatureScheme.SHA256WITHECDSA);
    }

    public AttestationSdk(String filePath, int index, String password) throws Exception {
        ontSdk = OntSdk.getInstance();
        ontSdk.openWalletFile(filePath);
        String address = ontSdk.getWalletMgr().getWallet().getAccounts().get(index).address;
        account = ontSdk.getWalletMgr().getAccount(address, password);
    }

    public void initialize(String rpcUrl, String chainNodeUrl, String tenantId, String addonId, String contractAddress) throws Exception {
        rpc = new AddonRpc(rpcUrl, addonId, tenantId);
        ontSdk.setRpc(chainNodeUrl);
        ontSdk.setDefaultConnect(ontSdk.getRpc());
        this.contractAddress = contractAddress;
    }

    public byte[] getPrivateKeyFromMnemonicCodes(String mnemonicCodes) throws Exception {
        return MnemonicCode.getPrikeyFromMnemonicCodesStrBip44(mnemonicCodes);
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

    public String getContractAddress() throws Exception {
        contractAddress = (String) rpc.call("1", "GetContractAddress", null);
        return contractAddress;
    }


    public Proof getProof(String id, String hash) throws Exception {
        JSONObject result = (JSONObject) call(id, "verify", new String[]{hash});
        try {
            List<UInt256> proofs = new ArrayList<>();
            for (Object s : (JSONArray) result.get("proof")) {
                proofs.add(new UInt256(Helper.hexToBytes((String) s)));
            }
            UInt256[] ps = new UInt256[proofs.size()];
            proofs.toArray(ps);
            Proof proof = new Proof(new UInt256(Helper.hexToBytes((String) result.get("root"))),
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
        for (Object o : (JSONArray) ontSdk.getConnect().getSmartCodeEvent(proof.blockHeight)) {
            try {
                for (Object nObj : (JSONArray) ((Map) o).get("Notify")) {
                    Map m = (Map) nObj;
                    if (!contractAddress.equals(m.get("ContractAddress"))) continue;
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
        if (AttestationError.ADDHASH_FAILED.getCode() != (int) err.get("error")) return null;
        if (!"ADDHASH_FAILED: duplicate hash leafs. please check.".equals(err.get("desc"))) return null;

        List<String> duplicatedHashes = new ArrayList<>();
        for (Object hash : (JSONArray) err.get("result")) {
            duplicatedHashes.add((String) hash);
        }
        String[] hashes = new String[duplicatedHashes.size()];
        duplicatedHashes.toArray(hashes);
        return hashes;
    }

    public List<String> getHashesByTxHash(String hash) throws Exception {
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
    public String confirm() throws Exception {
        // get contract address
        contractAddress = (String) rpc.call("1", "GetContractAddress", null);
        // construct transaction
        List<Object> params = new ArrayList<>();
        byte[] invokeCode = WasmScriptBuilder.createWasmInvokeCode(contractAddress, "verifySignature", params);
        InvokeWasmCode tx = new InvokeWasmCode(invokeCode);
        tx.payer = account.getAddressU160();
        tx.gasLimit = 20000;
        tx.gasPrice = 2500;
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