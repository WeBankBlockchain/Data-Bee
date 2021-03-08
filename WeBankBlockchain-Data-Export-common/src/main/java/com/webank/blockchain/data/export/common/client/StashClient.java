package com.webank.blockchain.data.export.common.client;

import com.webank.blockchain.data.export.common.entity.ExportConstant;
import com.webank.blockchain.data.export.common.stash.DataStashMysqlRepo;
import com.webank.blockchain.data.export.common.stash.StashBlockDataParser;
import lombok.Data;
import org.fisco.bcos.sdk.client.protocol.response.BcosBlock;
import org.fisco.bcos.sdk.client.protocol.response.BcosTransaction;
import org.fisco.bcos.sdk.client.protocol.response.BcosTransactionReceipt;
import org.fisco.bcos.sdk.crypto.CryptoSuite;

import java.math.BigInteger;

/**
 * @author wesleywang
 * @Description:
 * @date 2021/3/3
 */
@Data
public class StashClient implements ChainClient {

    private DataStashMysqlRepo stashMysqlRepo;

    private StashBlockDataParser blockDataParser;

    private CryptoSuite cryptoSuite;

    public StashClient () {
        cryptoSuite = new CryptoSuite(ExportConstant.getCurrentContext().getStashInfo().getCryptoTypeConfig());
        stashMysqlRepo = DataStashMysqlRepo.create();
        blockDataParser = new StashBlockDataParser(stashMysqlRepo, cryptoSuite);
    }

    @Override
    public BcosBlock.Block getBlockByNumber(BigInteger blockNumber) {
        String blockStr = stashMysqlRepo.queryBlock(blockNumber.longValue());
        return blockDataParser.parse(blockStr);
    }

    @Override
    public BigInteger getBlockNumber() {
        long blockNumber = stashMysqlRepo.queryBlockNumber();
        return BigInteger.valueOf(blockNumber);
    }

    @Override
    public String getCode(String address) {
        return stashMysqlRepo.queryCode(address);
    }

    @Override
    public CryptoSuite getCryptoSuite() {
        return cryptoSuite;
    }

    @Override
    public BcosTransaction getTransactionByHash(String transactionHash) {
        return blockDataParser.getTransaction(transactionHash);
    }

    @Override
    public BcosTransactionReceipt getTransactionReceipt(String transactionHash) {
        return blockDataParser.getReceipt(transactionHash);
    }
}
