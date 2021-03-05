package com.webank.blockchain.data.export.common.client;

import cn.hutool.core.util.HexUtil;
import com.googlecode.jsonrpc4j.JsonRpcHttpClient;
import com.webank.blockchain.data.export.common.entity.ChainInfo;
import com.webank.blockchain.data.export.common.entity.ExportConstant;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.fisco.bcos.sdk.client.protocol.model.JsonTransactionResponse;
import org.fisco.bcos.sdk.client.protocol.response.BcosBlock;
import org.fisco.bcos.sdk.client.protocol.response.BcosTransaction;
import org.fisco.bcos.sdk.client.protocol.response.BcosTransactionReceipt;
import org.fisco.bcos.sdk.crypto.CryptoSuite;
import org.fisco.bcos.sdk.model.TransactionReceipt;

import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;

/**
 * @author wesleywang
 * @Description:
 * @date 2021/2/25
 */
@Slf4j
@AllArgsConstructor
public class RpcHttpClient implements ChainClient{

    private JsonRpcHttpClient client;

    private int group;

    private CryptoSuite cryptoSuite;

    public RpcHttpClient() throws MalformedURLException {
        ChainInfo chainInfo = ExportConstant.getCurrentContext().getChainInfo();
        try {
            client = new JsonRpcHttpClient(new URL(chainInfo.getRpcUrl()));
        } catch (MalformedURLException e) {
            log.error("rpcHttp client build failed , reason : ", e);
            throw e;
        }
        group = chainInfo.getGroupId();
        cryptoSuite = new CryptoSuite(chainInfo.getCryptoTypeConfig());
    }

    @Override
    public BcosBlock.Block getBlockByNumber(BigInteger blockNumber) {
        try {
            BcosBlock.Block response =
                    client.invoke("getBlockByNumber", new Object[] {group, String.valueOf(blockNumber.intValue()), true}, BcosBlock.Block.class);
            return response;
        } catch (Throwable e) {
           log.error("JsonRpcHttpClient getBlockByNumber failed, reason : ", e);
        }
        return null;
    }

    @Override
    public BigInteger getBlockNumber() {
        try {
            String response =
                    client.invoke("getBlockNumber", new Object[] {group}, String.class);
            return HexUtil.toBigInteger(response.replace("x",""));
        } catch (Throwable e) {
            log.error("JsonRpcHttpClient getBlockNumber failed, reason : ", e);
        }
        return null;
    }

    @Override
    public String getCode(String address) {
        try {
            String response =
                    client.invoke("getCode", new Object[] {group, address}, String.class);
            return response;
        } catch (Throwable e) {
            log.error("JsonRpcHttpClient getCode failed, reason : ", e);
        }
        return null;
    }

    @Override
    public CryptoSuite getCryptoSuite() {
        return cryptoSuite;
    }

    @Override
    public BcosTransaction getTransactionByHash(String transactionHash) {
        try {
            JsonTransactionResponse response =
                    client.invoke("getTransactionByHash", new Object[] {group, transactionHash}, JsonTransactionResponse.class);
            BcosTransaction bcosTransaction = new BcosTransaction();
            bcosTransaction.setResult(response);
            return bcosTransaction;
        } catch (Throwable e) {
            log.error("JsonRpcHttpClient getCode failed, reason : ", e);
        }
        return null;
    }

    @Override
    public BcosTransactionReceipt getTransactionReceipt(String hash) {
        try {
            TransactionReceipt response =
                    client.invoke("getTransactionReceipt", new Object[] {group, hash}, TransactionReceipt.class);
            BcosTransactionReceipt receipt = new BcosTransactionReceipt();
            receipt.setResult(response);
            return receipt;
        } catch (Throwable e) {
            log.error("JsonRpcHttpClient getCode failed, reason : ", e);
        }
        return null;
    }
}
