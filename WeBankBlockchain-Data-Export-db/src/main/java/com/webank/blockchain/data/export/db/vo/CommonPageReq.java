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
package com.webank.blockchain.data.export.db.vo;

import javax.validation.constraints.Pattern;

import org.hibernate.validator.constraints.Range;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort.Direction;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

/**
 * CommonPageReq
 *
 * @author maojiayu
 * @data Dec 19, 2018 11:34:06 PM
 *
 */
@Data
@NoArgsConstructor
@Accessors(chain = true)
public class CommonPageReq {
    /** @Fields pageNo : request page index, start from 1. */
    @Range(min = 0, max = Integer.MAX_VALUE, message="not a valid input")
    private int pageNo = 1;
    /** @Fields pageSize : requst size of one page */
    @Range(min = 0, max = 1000000, message="not a valid input")
    private int pageSize = 20;
    /** @Fields orderBy : order by which field. */
    private String orderBy = "blockTimeStamp";
    @Pattern(regexp = "DESC|ASC")
    private String order = "DESC";

    public CommonPageReq(CommonPageReq p) {
        this.pageNo = p.pageNo;
        this.pageSize = p.pageSize;
        this.orderBy = p.orderBy;
        this.order = p.order;
    }

    public CommonPageReq(int pageNo, int pageSize) {
        this.pageNo = pageNo;
        this.pageSize = pageSize;
    }

    public Pageable convert() {
        // PageRequest中页是从0开始，前端page是从1开始
        PageRequest pageRequest = PageRequest.of(pageNo - 1, pageSize, Direction.valueOf(order), orderBy);
        return pageRequest;
    }

}
