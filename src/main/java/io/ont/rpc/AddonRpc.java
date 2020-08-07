package io.ont.rpc;

import com.alibaba.fastjson.JSON;
import com.github.ontio.common.ErrorCode;
import com.github.ontio.network.exception.RpcException;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

public class AddonRpc {
    private final URL url;
    private String addonId, tenantId;
    public String JSON_RPC_VERSION = "2.0";

    public AddonRpc(String url, String addonId, String tenantId) throws MalformedURLException {
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
