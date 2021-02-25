package com.webank.blockchain.data.export.common.entity;

import lombok.Data;
import org.fisco.bcos.sdk.client.protocol.response.BcosBlockHeader;

import java.util.List;

/**
 * @author wesleywang
 * @Description:
 * @date 2021/2/25
 */
@Data
public class Block {

    private String number;
    private String hash;
    private String parentHash;
    private String logsBloom;
    private String transactionsRoot;
    private String receiptsRoot;
    private String dbHash;
    private String stateRoot;
    private String sealer;
    private List<String> sealerList;
    private List<String> extraData;
    private String gasLimit;
    private String gasUsed;
    private String timestamp;
    private List<BcosBlockHeader.Signature> signatureList;





}
