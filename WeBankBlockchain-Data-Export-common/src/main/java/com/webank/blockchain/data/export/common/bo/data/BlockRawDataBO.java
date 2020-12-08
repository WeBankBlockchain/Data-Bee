package com.webank.blockchain.data.export.common.bo.data;

import lombok.Data;
import lombok.experimental.Accessors;
import org.fisco.bcos.sdk.client.protocol.response.BcosBlockHeader;

import java.util.Date;
import java.util.List;

/**
 * @author wesleywang
 * @Description:
 * @date 2020/10/23
 */
@Data
@Accessors(chain = true)
public class BlockRawDataBO {

    private String blockHash;
    private long blockHeight;
    private String blockObject;
    private Date blockTimeStamp;
    private String parentHash;
    private String logsBloom;
    private String transactionsRoot;
    private String receiptsRoot;
    private String dbHash;
    private String stateRoot;
    private String sealer;
    private String sealerList;
    private String extraData;
    private String gasLimit;
    private String gasUsed;
    private String signatureList;
    private String transactionList;
    protected Date depotUpdatetime;
}
