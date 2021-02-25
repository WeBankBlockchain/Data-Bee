package com.webank.blockchain.data.export.common.entity;

import cn.hutool.core.lang.Chain;
import org.fisco.bcos.sdk.client.Client;
import org.fisco.bcos.sdk.client.protocol.response.BcosBlock;
import org.fisco.bcos.sdk.client.protocol.response.BcosTransaction;
import org.fisco.bcos.sdk.client.protocol.response.BcosTransactionReceipt;
import org.fisco.bcos.sdk.crypto.CryptoSuite;

import java.math.BigInteger;

/**
 * @author wesleywang
 * @Description:
 * @date 2021/2/25
 */

public class ChannelClient implements ChainClient {

    private Client client;

    public ChannelClient(Client client) {
        this.client = client;
    }

    @Override
    public BcosBlock.Block getBlockByNumber(BigInteger blockNumber) {
        return client.getBlockByNumber(blockNumber,true).getBlock();
    }

    @Override
    public BigInteger getBlockNumber() {
        return client.getBlockNumber().getBlockNumber();
    }

    @Override
    public String getCode(String address) {
        return client.getCode(address).getCode();
    }

    @Override
    public CryptoSuite getCryptoSuite() {
        return client.getCryptoSuite();
    }

    @Override
    public BcosTransaction getTransactionByHash(String transactionHash) {
        return client.getTransactionByHash(transactionHash);
    }

    @Override
    public BcosTransactionReceipt getTransactionReceipt(String hash) {
        return client.getTransactionReceipt(hash);
    }
}
