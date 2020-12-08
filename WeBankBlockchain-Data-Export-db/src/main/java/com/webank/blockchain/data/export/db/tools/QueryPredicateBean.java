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
package com.webank.blockchain.data.export.db.tools;

import java.lang.reflect.Field;

import org.apache.commons.lang3.StringUtils;

import lombok.Data;
import lombok.experimental.Accessors;

/**
 * PredicateBean
 *
 * @Description: PredicateBean
 * @author maojiayu
 * @data Jun 28, 2020 3:13:16 PM
 *
 */
@Data
@Accessors(chain = true)
public class QueryPredicateBean {

    private String propName;
    String blurry;
    String attributeName;
    Class<?> fieldType;
    Object value;
    QueryAnnotation queryAnnotation;

    public <Q> QueryPredicateBean fromQuery(Q query, QueryAnnotation qAnnotation, Field field)
            throws IllegalArgumentException, IllegalAccessException {
        this.propName = qAnnotation.propName();
        this.blurry = qAnnotation.blurry();
        this.attributeName = StringUtils.isBlank(propName) ? field.getName() : propName;
        this.fieldType = field.getType();
        this.value = field.get(query);
        this.queryAnnotation = qAnnotation;
        return this;
    }

    public <Q> QueryPredicateBean fromQuery(Q query, Field field)
            throws IllegalArgumentException, IllegalAccessException {
        QueryAnnotation q = field.getAnnotation(QueryAnnotation.class);
        return fromQuery(query, q, field);
    }
}
