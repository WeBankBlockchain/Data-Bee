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
        if (ExportConstant.getCurrentContext().getChainInfo().getCryptoTypeConfig() == 0) {
            byte[] encodedTransaction = encoderService.encode(RawTransaction.createTransaction(transactionDetail.getNonce(),
                    transactionDetail.getGasPrice(), transactionDetail.getGas(),
                    transactionDetail.getBlockLimit(), transactionDetail.getReceiveAddress().toString(),
                    transactionDetail.getValue(), transactionDetail.getData(),
                    transactionDetail.getChainId(), transactionDetail.getGroupId(), transactionDetail.getExtraData()), null);
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
                "f9071af902bfa03b2698b4739d33a73a767244bc94b7d541afdf02f34843378cce267f9977ee1ea008548e1a555095c3076ddf8e1aae222c3a105dbd0219a414994bd7113d6919fda0de67c3a281e02d054009481b25b45e7b6a40c836534b00eeeca5740074c323baa0f37832d72713bc4d713d5f25dfe8639d7be9872413a3d526aaaca98a0c07c57ea008548e1a555095c3076ddf8e1aae222c3a105dbd0219a414994bd7113d6919fdb90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e808086017800373402c001f90108b84014d927214eb23d6257c99ab45c9058b6970380db295e17c230c40eb7205c23553692a3a4cb42c12c888006a667a3815b99e60b141128da69844fad872b7bee9cb8407d9eb55dcced0a8d95b08244e751b90d42fa7520f743e81e6ef656c0dbc61a2562246720621613a1ea0cd0c8dbc6519ad2dfe11ab2a9fedff2e1fc3785bfa0acb840c553593b77e6a3209bc5df69922fb717701a97720db3ee6498800e116e97884d5a58b6f0bd80246ede07d22874fc4bdc71f7237544b6efada542c0881a08e8e4b840dd7acbf7cd200b72fef042fe86f8c36c527e01e7ec5618f9d26fdac969a3ce9a4ecbec5382a697b4cb0f61cd1d7a103c6714b2f11a422aff83f7657fcb8fe222b9011f010000000000000013010000f90110a00302cce90248d8b753b98742c99d499acee934d98d0ada52cdcad9450b5da3f485051f4d5c0083419ce0820201945b1056a3aae11395ae20e520b4507c039afb70c380b884ea87152b00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000064000000000000000000000000000000000000000000000000000000000000000477616e67000000000000000000000000000000000000000000000000000000000101801ca011099a617d1b732dd594e72967903ef650e80a970fe2cbc56e100d265ca2a349a077d29e817af771a544f14c4d954ac490e1525aac209f3ceb0c0eb90d54238a83a0beb7d61d9e92ab14c2e920d7270f75e11a9dc0904ce3652949cae3d7a9326bdaf8d2f84401b841da79788223182e423384d6d79c2098317a1d736b4cae2e9cf030cc57a03a4c521372d19ec025ef6a4a55d9f9d56230b2e7d42cb4fdaf0b170e8fb58a4b3d9c1900f84403b841a3ed69e1add6a9dc68466a0cbc3d5795adb1146b13ce7e9b8827e120ebf56d1527bd79a041e06ac61fafde9670578137e8ea98be5e3dca6b4ebf0da2a34d5e9700f84480b8415d6793ade5830d61739b3bd03ec3ea3b641e967d9371ba39b770522db2dbfdf57611445fa89fbe930c008b27052bd5eada3086b3e4862ddea822f9bd063f425200f9023ef9023ba008548e1a555095c3076ddf8e1aae222c3a105dbd0219a414994bd7113d6919fd82caf6940000000000000000000000000000000000000000b901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080000000000200000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000800000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000080a00000000000000000000000000000000000000000000000000000000000000000f8dbf8d9945b1056a3aae11395ae20e520b4507c039afb70c3e1a091c95f04198617c60eaf2180fbca88fc192db379657df0e412a9f7dd4ebbe95db8a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000064000000000000000000000000000000000000000000000000000000000000000477616e6700000000000000000000000000000000000000000000000000000000";
        new StashBlockDataParser(null,null).parse(s);




    }


}
