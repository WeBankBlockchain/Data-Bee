package com.webank.blockchain.data.export.common.entity;

import lombok.Builder;
import lombok.Data;

/**
 * @author wesleywang
 * @Description:
 * @date 2020/12/16
 */
@Data
@Builder
public class ChainInfo {

    private String nodeStr;
    private int groupId;
    private String certPath;
}
