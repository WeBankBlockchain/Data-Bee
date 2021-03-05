package com.webank.blockchain.data.export.common.stash;

import com.webank.blockchain.data.export.common.entity.ExportConstant;
import com.webank.blockchain.data.export.common.stash.entity.BlockHeader;
import com.webank.blockchain.data.export.common.stash.entity.BlockV2RC2;
import com.webank.blockchain.data.export.common.stash.entity.TransactionDetail;
import com.webank.blockchain.data.export.common.stash.rlp.ByteUtil;
import com.webank.blockchain.data.export.common.tools.AddressUtils;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.fisco.bcos.sdk.client.protocol.model.JsonTransactionResponse;
import org.fisco.bcos.sdk.client.protocol.response.BcosBlock;
import org.fisco.bcos.sdk.client.protocol.response.BcosBlockHeader;
import org.fisco.bcos.sdk.client.protocol.response.BcosTransaction;
import org.fisco.bcos.sdk.client.protocol.response.BcosTransactionReceipt;
import org.fisco.bcos.sdk.crypto.CryptoSuite;
import org.fisco.bcos.sdk.crypto.signature.ECDSASignatureResult;
import org.fisco.bcos.sdk.crypto.signature.SignatureResult;
import org.fisco.bcos.sdk.model.TransactionReceipt;
import org.fisco.bcos.sdk.transaction.codec.encode.TransactionEncoderService;
import org.fisco.bcos.sdk.transaction.model.gas.DefaultGasProvider;
import org.fisco.bcos.sdk.transaction.model.po.RawTransaction;
import org.fisco.bcos.sdk.utils.Hex;
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
                "f9071af902bfa0b13d0d569edf7edc10288fc6be489be4cd92ba38447cde4de9672efbf1dbe705a031c941da207173f9bfcb942b647dd41eaf0f6f9ae844a868748cf8be3a84eca0a082cb67c449f04f76e27d8de8797eafeb856aa9d324e20e92f2b966912b9f2725a0b923945b24fcf7e4107a2f44278acc4c05ea1f4f52c7faa1d579e5daf9b7be20a031c941da207173f9bfcb942b647dd41eaf0f6f9ae844a868748cf8be3a84eca0b901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000015808086017801ecac50c001f90108b84014d927214eb23d6257c99ab45c9058b6970380db295e17c230c40eb7205c23553692a3a4cb42c12c888006a667a3815b99e60b141128da69844fad872b7bee9cb8407d9eb55dcced0a8d95b08244e751b90d42fa7520f743e81e6ef656c0dbc61a2562246720621613a1ea0cd0c8dbc6519ad2dfe11ab2a9fedff2e1fc3785bfa0acb840c553593b77e6a3209bc5df69922fb717701a97720db3ee6498800e116e97884d5a58b6f0bd80246ede07d22874fc4bdc71f7237544b6efada542c0881a08e8e4b840dd7acbf7cd200b72fef042fe86f8c36c527e01e7ec5618f9d26fdac969a3ce9a4ecbec5382a697b4cb0f61cd1d7a103c6714b2f11a422aff83f7657fcb8fe222b9011f010000000000000013010000f90110a003a1926d78a800d91bf55300f23f00643ea258565d47905bbfdb65ada289f39a85051f4d5c0083419ce082020894ba4ddc05e4e3bb88179f7be3d81e68af80ebc81680b884ea87152b00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000677777777777700000000000000000000000000000000000000000000000000000101801ba0312f5ff3eab21459bda329755f6a86ec7829f076378f5ec88efb3b3d1a1345c5a00959eef50666306e083f350a48f2fe4b9907e73d5bf9c489c072db7ba6abe617a053843523751894e8d0aef39cd5adf8522902920d75ca5110187b4bfe7b58db3df8d2f84402b84157fae74b340f09bc648021b9b1077ed2a2c4920242d0b64baf8035b6956d61ef0841177ca9e76c2cff3922894bca568572d35c4115bc4660926ac88c451d7bf300f84403b841fa27fe1c4caddee780402fbeef3698782ad538d2ba6c192388187d8ac96b563b79caa215a1f7e985f3631a7ae821e7e04298e643b9c43025f3058e7046699cc001f84401b841190237a70f3bfa15b059734ff0981d8417d969c5404c0f5cd03e527177137ffc5e4098f3e982134f55aa8b4dbd91c0bf26699f3a9b199c5ae718291e013552eb01f9023ef9023ba031c941da207173f9bfcb942b647dd41eaf0f6f9ae844a868748cf8be3a84eca082cb76940000000000000000000000000000000000000000b901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000004000000000000800000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000080a00000000000000000000000000000000000000000000000000000000000000000f8dbf8d994ba4ddc05e4e3bb88179f7be3d81e68af80ebc816e1a091c95f04198617c60eaf2180fbca88fc192db379657df0e412a9f7dd4ebbe95db8a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000067777777777770000000000000000000000000000000000000000000000000000";
        new StashBlockDataParser(null,new CryptoSuite(0)).parse(s);

    }


}
