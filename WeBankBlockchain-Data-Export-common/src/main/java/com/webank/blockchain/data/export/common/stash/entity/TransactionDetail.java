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
import com.webank.blockchain.data.export.common.stash.rlp.RLPList;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.Accessors;
import org.fisco.bcos.sdk.abi.datatypes.Address;
import org.fisco.bcos.sdk.crypto.CryptoSuite;
import org.fisco.bcos.sdk.transaction.codec.encode.TransactionEncoderService;
import org.fisco.bcos.sdk.transaction.model.po.RawTransaction;
import org.fisco.bcos.sdk.utils.Numeric;

import java.math.BigInteger;

/**
 * TransactionDetail
 *
 * @Description: TransactionDetail
 * @author maojiayu
 * @data Sep 10, 2019 8:02:42 PM
 *
 */
@Data
@Accessors
@EqualsAndHashCode
public class TransactionDetail {
    private BigInteger nonce;
    private BigInteger gasPrice;
    private BigInteger gas;
    private BigInteger blockLimit;
    private Address receiveAddress;
    private BigInteger value;
    private String data;
    private BigInteger chainId;
    private BigInteger groupId;
    private String v;
    private BigInteger r;
    private BigInteger s;
    private String extraData;
    private String hash;

    public TransactionDetail(RLPList rlpHeader) {
        this.nonce = ByteUtil.bytesToBigInteger(rlpHeader.get(0).getRLPData());
        this.gasPrice = ByteUtil.bytesToBigInteger(rlpHeader.get(1).getRLPData());
        this.gas = ByteUtil.bytesToBigInteger(rlpHeader.get(2).getRLPData());
        this.blockLimit = ByteUtil.bytesToBigInteger(rlpHeader.get(3).getRLPData());
        this.receiveAddress = new Address(ByteUtil.bytesToBigInteger(rlpHeader.get(4).getRLPData()));
        this.value = ByteUtil.bytesToBigInteger(rlpHeader.get(5).getRLPData());
        this.data = Numeric.toHexString(rlpHeader.get(6).getRLPData());
        this.chainId = ByteUtil.bytesToBigInteger(rlpHeader.get(7).getRLPData());
        this.groupId = ByteUtil.bytesToBigInteger(rlpHeader.get(8).getRLPData());
        this.extraData = Numeric.toHexString(rlpHeader.get(9).getRLPData());
        this.v = Numeric.toHexString(rlpHeader.get(10).getRLPData());
        this.r = ByteUtil.bytesToBigInteger(rlpHeader.get(11).getRLPData());
        this.s = ByteUtil.bytesToBigInteger(rlpHeader.get(12).getRLPData());
    }

}
