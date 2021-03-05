/**
 * Copyright 2020 Webank.
 *
 * <p>Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License at
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0
 *
 * <p>Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.webank.blockchain.data.export.common.stash.entity;

import com.webank.blockchain.data.export.common.stash.rlp.ByteUtil;
import com.webank.blockchain.data.export.common.stash.rlp.DecodeResult;
import com.webank.blockchain.data.export.common.stash.rlp.RLP;
import com.webank.blockchain.data.export.common.stash.rlp.RLPElement;
import com.webank.blockchain.data.export.common.stash.rlp.RLPList;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.Accessors;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.ArrayUtils;
import org.fisco.bcos.sdk.abi.datatypes.Address;
import org.fisco.bcos.sdk.utils.Numeric;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * TransactionRecipt
 *
 * @Description: TransactionReceipt
 * @author maojiayu
 * @data Sep 25, 2019 10:36:21 AM
 *
 */
@Data
@EqualsAndHashCode
@Accessors(chain = true)
public class TransactionReceipt {
    private String stateRoot;
    private BigInteger gasUsed;
    private String contractAddress;
    private String logsBloom;
    private long status;
    private String output;
    private List<Log> logs;

    public TransactionReceipt(RLPList rlpTransactionReceipt) {
        this.stateRoot = Numeric.toHexString(rlpTransactionReceipt.get(0).getRLPData());
        this.gasUsed = ByteUtil.bytesToBigInteger(rlpTransactionReceipt.get(1).getRLPData());
        this.contractAddress = new Address(ByteUtil.bytesToBigInteger(rlpTransactionReceipt.get(2).getRLPData())).getValue();
        this.logsBloom = Numeric.toHexString(rlpTransactionReceipt.get(3).getRLPData());
        this.status = ByteUtil.bytesToBigInteger(rlpTransactionReceipt.get(4).getRLPData()).longValue();
        this.output = Numeric.toHexString(rlpTransactionReceipt.get(5).getRLPData());
        this.logs = parseLogs(rlpTransactionReceipt.get(6).getRLPData());
    }


    public static List<Log> parseLogs(byte[] logs){
        List<Log> list = new ArrayList<>();
        if(Numeric.toHexString(logs).equals("0xc0")) {
            return list;
        }
        RLPList result = (RLPList ) RLP.decode2(logs).get(0);
        for (RLPElement rlpElement :  result) {
            RLPList rlpElements = (RLPList) rlpElement;
            Log log = new Log(rlpElements);
            list.add(log);
        }
        return list;
    }

}
