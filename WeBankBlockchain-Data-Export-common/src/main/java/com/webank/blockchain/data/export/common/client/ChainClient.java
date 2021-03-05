package com.webank.blockchain.data.export.common.client;


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
public interface ChainClient {

    BcosBlock.Block getBlockByNumber(BigInteger blockNumber);

    BigInteger getBlockNumber();

    String getCode(String address);

    CryptoSuite getCryptoSuite();

    BcosTransaction getTransactionByHash(String transactionHash);

    BcosTransactionReceipt getTransactionReceipt(String transactionHash);
}
