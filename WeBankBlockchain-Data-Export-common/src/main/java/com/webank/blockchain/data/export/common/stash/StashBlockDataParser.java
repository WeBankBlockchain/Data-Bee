package com.webank.blockchain.data.export.common.stash;

import com.webank.blockchain.data.export.common.entity.ExportConstant;
import com.webank.blockchain.data.export.common.stash.entity.BlockHeader;
import com.webank.blockchain.data.export.common.stash.entity.BlockV2RC2;
import com.webank.blockchain.data.export.common.stash.entity.TransactionDetail;
import com.webank.blockchain.data.export.common.tools.AddressUtils;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.fisco.bcos.sdk.client.protocol.model.JsonTransactionResponse;
import org.fisco.bcos.sdk.client.protocol.response.BcosBlock;
import org.fisco.bcos.sdk.client.protocol.response.BcosBlockHeader;
import org.fisco.bcos.sdk.client.protocol.response.BcosTransaction;
import org.fisco.bcos.sdk.client.protocol.response.BcosTransactionReceipt;
import org.fisco.bcos.sdk.crypto.CryptoSuite;
import org.fisco.bcos.sdk.model.TransactionReceipt;
import org.fisco.bcos.sdk.transaction.codec.encode.TransactionEncoderService;
import org.fisco.bcos.sdk.transaction.model.po.RawTransaction;
import org.fisco.bcos.sdk.utils.Numeric;

import java.math.BigInteger;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.IntStream;

/**
 * @author wesleywang
 * @Description:
 * @date 2021/3/3
 */
@Data
@Slf4j
public class StashBlockDataParser {

    private Map<Long, List<TransactionReceipt>> receiptCache = new ConcurrentHashMap<>();

    private Map<Long, BcosBlock.Block> blockCache = new ConcurrentHashMap<>();

    private DataStashMysqlRepo dataStashMysqlRepo;

    private TransactionEncoderService encoderService;

    private CryptoSuite cryptoSuite;

    public StashBlockDataParser(DataStashMysqlRepo dataStashMysqlRepo, CryptoSuite cryptoSuite) {
        this.dataStashMysqlRepo = dataStashMysqlRepo;
        this.cryptoSuite = cryptoSuite;
        this.encoderService = new TransactionEncoderService(this.cryptoSuite);
    }


    public BcosBlock.Block parse(String blockStr) {
        BlockV2RC2 blockV2RC2 = new BlockV2RC2(blockStr);
        BlockHeader blockHeader = blockV2RC2.getBlockHeader();
        BcosBlock.Block block = new BcosBlock.Block();
        block.setDbHash(blockHeader.getDbHash());
        block.setExtraData(blockHeader.getExtraData());
        block.setGasLimit(Numeric.encodeQuantity(blockHeader.getGasLimit()));
        block.setGasUsed(Numeric.encodeQuantity(blockHeader.getGasUsed()));
        block.setHash(blockV2RC2.getHash());
        block.setLogsBloom(blockHeader.getLogsBloom());
        block.setNumber(Numeric.encodeQuantity(blockHeader.getNumber()));
        block.setSealerList(blockHeader.getSealerList());
        block.setSealer(Numeric.encodeQuantity(blockHeader.getSealer()));
        block.setTransactionsRoot(blockHeader.getTransactionsRoot());
        block.setParentHash(blockHeader.getParentHash());
        block.setReceiptsRoot(blockHeader.getReceiptRoot());
        block.setStateRoot(blockHeader.getStateRoot());
        block.setTimestamp(Numeric.encodeQuantity(blockHeader.getTimestamp()));

        List<BcosBlockHeader.Signature> signatureList = new ArrayList<>();
        IntStream.range(0, blockV2RC2.getSigList().size()).forEach(i -> {
            BcosBlockHeader.Signature signature = new BcosBlockHeader.Signature();
            Map<String, String> stringMap = blockV2RC2.getSigList().get(i);
            String key = getFirstOrNull(stringMap);
            signature.setIndex(key);
            signature.setSignature(stringMap.get(key));
            signatureList.add(signature);
        });
        block.setSignatureList(signatureList);

        List<BcosBlock.TransactionResult> transactions = new ArrayList<>();
        IntStream.range(0, blockV2RC2.getTransactions().size()).forEach(i -> {
            TransactionDetail transactionDetail = blockV2RC2.getTransactions().get(i);
            BcosBlock.TransactionObject result = new BcosBlock.TransactionObject();
            result.setBlockHash(block.getHash());
            result.setBlockLimit(Numeric.encodeQuantity(transactionDetail.getBlockLimit()));
            result.setBlockNumber(Numeric.encodeQuantity(blockHeader.getNumber()));
            result.setChainId(Numeric.encodeQuantity(transactionDetail.getChainId()));
            result.setExtraData(transactionDetail.getExtraData());
            result.setGas(Numeric.encodeQuantity(transactionDetail.getGas()));
            result.setGasPrice(Numeric.encodeQuantity(transactionDetail.getGasPrice()));
            result.setGroupId(Numeric.encodeQuantity(transactionDetail.getGroupId()));
            result.setHash(transactionDetail.getHash());
            result.setTransactionIndex(Numeric.encodeQuantity(BigInteger.valueOf(i)));
            result.setTo(transactionDetail.getReceiveAddress().getValue());
            result.setInput(transactionDetail.getData());
            result.setNonce(Numeric.encodeQuantity(transactionDetail.getNonce()));
            result.setValue(Numeric.encodeQuantity(transactionDetail.getValue()));

            JsonTransactionResponse.SignatureResponse signature = new JsonTransactionResponse.SignatureResponse();
            signature.setR(Numeric.encodeQuantity(transactionDetail.getR()));
            signature.setS(Numeric.encodeQuantity(transactionDetail.getS()));
            signature.setV(transactionDetail.getV());
            signature.setSignature(signature.getR() + signature.getS().replace("0x","")
                    + signature.getV().replace("x",""));
            result.setSignature(signature);
            result.setFrom(getFrom(transactionDetail));
            transactions.add(result);

        });
        block.setTransactions(transactions);

        List<TransactionReceipt> receipts = new ArrayList<>();
        IntStream.range(0, blockV2RC2.getTrList().size()).forEach(i -> {
            com.webank.blockchain.data.export.common.stash.entity.TransactionReceipt transactionReceipt = blockV2RC2.getTrList().get(i);
            TransactionReceipt tr = new TransactionReceipt();
            tr.setBlockHash(block.getHash());
            tr.setBlockNumber(Numeric.encodeQuantity(block.getNumber()));
            tr.setContractAddress(transactionReceipt.getContractAddress());
            tr.setGasUsed(Numeric.encodeQuantity(transactionReceipt.getGasUsed()));
            List<TransactionReceipt.Logs> logs = new ArrayList<>();
            tr.setLogs(logs);
            transactionReceipt.getLogs().forEach(log -> {
                TransactionReceipt.Logs result = new TransactionReceipt.Logs();
                result.setAddress(log.getAddress());
                result.setBlockNumber(Numeric.encodeQuantity(block.getNumber()));
                result.setTopics(log.getTopics());
                result.setData(log.getData());
                logs.add(result);
            });
            tr.setOutput(transactionReceipt.getOutput());
            tr.setStatus(Numeric.encodeQuantity(BigInteger.valueOf(transactionReceipt.getStatus())));
            tr.setTo(transactionReceipt.getContractAddress());
            tr.setRoot(transactionReceipt.getStateRoot());
            BcosBlock.TransactionObject transactionObject = (BcosBlock.TransactionObject) transactions.get(i);
            tr.setInput(transactionObject.getInput());
            tr.setTransactionIndex(Numeric.encodeQuantity(BigInteger.valueOf(i)));
            tr.setTransactionHash(transactionObject.getHash());
            tr.setFrom(transactionObject.getFrom());
            receipts.add(tr);
        });

        receiptCache.put(block.getNumber().longValue(), receipts);
        blockCache.put(block.getNumber().longValue(),block);
        return block;
    }

    
    public BcosTransaction getTransaction(String transactionHash) {
        long blockHeight = dataStashMysqlRepo.queryBlockHeight(transactionHash);
        BcosBlock.Block block = blockCache.get(blockHeight);
        if (block == null) {
            return null;
        }
        BcosBlock.TransactionObject result = null;
        List<BcosBlock.TransactionResult> transactions = block.getTransactions();
        for (BcosBlock.TransactionResult transactionResult : transactions) {
            BcosBlock.TransactionObject transactionObject = (BcosBlock.TransactionObject) transactionResult;
            if (transactionObject.getHash().equals(transactionHash)) {
                result = transactionObject;
                break;
            }
        }
        BcosTransaction transaction = new BcosTransaction();
        transaction.setResult(result.get());
        return transaction;
    }
    

    public BcosTransactionReceipt getReceipt(String transactionHash){
        long blockHeight = dataStashMysqlRepo.queryBlockHeight(transactionHash);
        List<TransactionReceipt> receipts = receiptCache.get(blockHeight);
        TransactionReceipt result = null;
        for (TransactionReceipt transactionReceipt : receipts) {
            if (transactionReceipt.getTransactionHash().equals(transactionHash)) {
                result = transactionReceipt;
                break;
            }
        }
        BcosTransactionReceipt receipt = new BcosTransactionReceipt();
        receipt.setResult(result);
        return receipt;
    }


    private static String getFirstOrNull(Map<String, String> map) {
        String obj = null;
        for (Map.Entry<String, String> entry : map.entrySet()) {
            obj = entry.getKey();
            if (obj != null) {
                break;
            }
        }
        return obj;
    }

    private String getFrom(TransactionDetail transactionDetail){
        String from = null;
        if (ExportConstant.getCurrentContext().getStashInfo().getCryptoTypeConfig() == 0) {
            byte[] encodedTransaction = encoderService.encode(RawTransaction.createTransaction(transactionDetail.getNonce(),
                    transactionDetail.getGasPrice(),
                    transactionDetail.getGas(),
                    transactionDetail.getBlockLimit(), transactionDetail.getReceiveAddress().toString(),
                    transactionDetail.getValue(), transactionDetail.getData(),
                    transactionDetail.getChainId(), transactionDetail.getGroupId(), ""), null);
            try {
                BigInteger key = AddressUtils.recoverFromSignature(Numeric.hexStringToByteArray(transactionDetail.getV())[0],
                        transactionDetail.getR(), transactionDetail.getS(), cryptoSuite.getHashImpl().hash(encodedTransaction));
                if (key == null) {
                    return null;
                }
                from = cryptoSuite.getCryptoKeyPair().getAddress(Numeric.encodeQuantity(key));
            } catch (SignatureException e) {
                log.error("recoverFromSignature failed , transaction hash is " + transactionDetail.getHash(), e);
            }
        }else {
            from =  cryptoSuite.getCryptoKeyPair().getAddress(transactionDetail.getV());
        }
        return from;
    }




    public static void main(String[] args) {
        String s =
                "f906fcf902bfa03aa4a32e802dbbeaa36ae9dc3f67c71886b67016888ecd32377db3d0fdb4c009a02c8fc114ac3d8a190ffac933939f8f09d1ba0950bdae47c89dc27c668ab0a09ea00435071a80ff56f176942f4f807dd91155c548f748b66da09a2fd399ffd56dd8a0ddb6798c02e54a4805fca619e284be3fb866a2a34b2ba01e6b6d97fdcacba1d6a02c8fc114ac3d8a190ffac933939f8f09d1ba0950bdae47c89dc27c668ab0a09eb90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b8080860178108b38eec003f90108b8402a4e03774341144fd851e8952ff8821d59ca006dc4458fecb8a2552f44a57ddd027332a57740c1d6741857be9c4d38dddc878348052813d85489f027ca46f65eb8404c67db9a7b7cdb559cdc10acc0daaf5f93eac1795a562615cf6ffc0c8d2bdb7f177330c33b56c3ed5017ea390186f1257fe9911b33773f17754a27b0ca1c6a9db84062eb4f5002798fcd9ed50272b83a3f49ca4d1ac509178dca19fade926fc05da7dc34e2f836e78ed9c9b5a2a985f8be24df5a748dad96fbb5b4a7f646dd10212ab840c2aa8c801b8cb5b6ece6abf07a6e1e4f7aab2f00475b5989178b4cb86667d22f9a6372f15b0b9cb0ca3ee8b9faef2350cfb7a42e6a9607ec19f87df9f65f56a4b9013f010000000000000033010000f901309f5a78aeee881fcabf10a5ea34c494e1a30f0ef928f0ce1fa3dade7c58076eb485051f4d5c0083419ce08201fe94a0d985295dc0c365c88b38b525992fb48fcecbad80b8643590b49f000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000067177657177650000000000000000000000000000000000000000000000000000010180b840c529124c64c708ab30811045169cad877c9497fd8106f3461a3ff76134228f49e0e05861a8f9f7f3f7c4253414e2a64da1f86deb913bf8beecf85a26e2240d87a092ac7d52cfc1b24a26ebf47eba97ba41c0313a9a51ac40c97635b40f66bb0a57a0f59b4ec56542bc8de3f52923eed5956644c83622f0e9af0e0bc725695b865a1da05eefa2952a320b85b3420bdfccdff6bf22c651d59095529b710f19e914c9017ef9018ff88301b8806466b3a259f20368d3ac311a28aa9b68124b870b53fcb3ac93043c3522896634bd9363dea6db887880f5b875f457dfab8dfc97efa24d5e812af7317a478b4cc14c67db9a7b7cdb559cdc10acc0daaf5f93eac1795a562615cf6ffc0c8d2bdb7f177330c33b56c3ed5017ea390186f1257fe9911b33773f17754a27b0ca1c6a9df88302b8809b42306f2bdbffa2106210269d8bcc4f4924b4ce58fe4f691e9bad20aa789dbbeea3d26ebdda436af69e8533d6f8b93546e130afe66d4a9b3c0e55260f3294f062eb4f5002798fcd9ed50272b83a3f49ca4d1ac509178dca19fade926fc05da7dc34e2f836e78ed9c9b5a2a985f8be24df5a748dad96fbb5b4a7f646dd10212af88303b88020559430173f6408918fe808f119f52340b12d6fa90ec67d4867e047558d6cb3ea6c70b667e00d4b523aa376976c4909217f70d3ca3b7af283550bc3a198e9f0c2aa8c801b8cb5b6ece6abf07a6e1e4f7aab2f00475b5989178b4cb86667d22f9a6372f15b0b9cb0ca3ee8b9faef2350cfb7a42e6a9607ec19f87df9f65f56a4f90142f9013fa02c8fc114ac3d8a190ffac933939f8f09d1ba0950bdae47c89dc27c668ab0a09e82711a940000000000000000000000000000000000000000b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008080c0";
        new StashBlockDataParser(null,new CryptoSuite(1)).parse(s);

    }


}
