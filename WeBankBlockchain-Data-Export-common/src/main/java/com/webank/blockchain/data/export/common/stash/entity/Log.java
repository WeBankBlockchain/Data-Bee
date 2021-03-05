package com.webank.blockchain.data.export.common.stash.entity;

import com.webank.blockchain.data.export.common.stash.rlp.ByteUtil;
import com.webank.blockchain.data.export.common.stash.rlp.RLPList;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.Accessors;
import org.fisco.bcos.sdk.abi.datatypes.Address;
import org.fisco.bcos.sdk.utils.Numeric;

import java.util.List;

/**
 * @author wesleywang
 * @Description:
 * @date 2021/3/4
 */
@Data
@Accessors
@EqualsAndHashCode
public class Log {

    private String address;
    private List<String> topics;
    private String data;


    public Log(RLPList rlp) {
        this.address = new Address(ByteUtil.bytesToBigInteger(rlp.get(0).getRLPData())).getValue();
        this.topics = ((RLPList) rlp.get(1)).getList();
        this.data = Numeric.toHexString(rlp.get(2).getRLPData());
    }
}
